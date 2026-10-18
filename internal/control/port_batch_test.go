package control

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestPortBatchFixedWaitAndConfidence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		samples []batchCostSample
		want    int
		reason  string
	}{
		{"cold", nil, 4, "cold"},
		{"one small healthy", []batchCostSample{{1, 28, false}}, 4, "observed"},
		{"three small healthy", []batchCostSample{{1, 28, false}, {1, 28, false}, {1, 28, false}}, 4, "observed"},
		{"four IP historical R4", []batchCostSample{{4, 120, false}, {4, 120, false}, {4, 120, false}}, 4, "observed"},
		{"below confidence", []batchCostSample{{3, 110, false}, {3, 110, false}}, 4, "observed"},
		{"observed soft limit", []batchCostSample{{3, 110, false}, {3, 110, false}, {3, 110, false}}, 3, "observed"},
		{"no sticky floor", []batchCostSample{{3, 110, false}, {3, 110, false}, {3, 110, false}, {4, 60, false}}, 4, "observed"},
		{"quick failure", []batchCostSample{{4, 1, true}}, 2, "degraded"},
		{"timeout", []batchCostSample{{4, 180, true}}, 2, "degraded"},
		{"dangerous small workload", []batchCostSample{{1, 100, false}}, 1, "degraded"},
		{"slow successful", []batchCostSample{{4, 150, false}}, 3, "degraded"},
		{"error window never grows", []batchCostSample{{4, 180, true}, {4, 50, false}, {4, 50, false}, {4, 50, false}}, 2, "degraded"},
		{"invalid durations", []batchCostSample{{1, 0, false}, {1, -1, false}, {1, 15, false}, {1, math.NaN(), false}, {1, math.Inf(1), false}}, 4, "cold"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tunePortBatch(tc.samples, 4)
			if got.Size != tc.want || got.Reason != tc.reason {
				t.Fatalf("got %+v, want size=%d reason=%s", got, tc.want, tc.reason)
			}
			if got.FixedSeconds != 15 || got.TargetSeconds != 135 {
				t.Fatal(got)
			}
		})
	}
	got := tunePortBatch([]batchCostSample{{1, 28, false}}, 4)
	if got.HealthySamples != 1 || got.SecondsPerItem != 28 || got.VariableSecondsPerItem != 13 {
		t.Fatal(got)
	}
	if got = tunePortBatch([]batchCostSample{{4, 1, true}}, 4); got.SecondsPerItem != 0 || got.HealthySamples != 0 {
		t.Fatal("failure invented measured cost", got)
	}
	if got = tunePortBatch(nil, 1); got.Size != 1 {
		t.Fatal(got)
	}
}

func TestPostgresPortBatchFrozenArtifactAndFutureSeeds(t *testing.T) {
	t.Setenv("SCAN_PORT_RATE_PPS", "5000")
	t.Setenv("SCAN_PORT_SHARD_MAX", "4")
	t.Setenv("SCAN_TARGET_DISCOVERY_PPS", "5000")
	s, h := newPolicyTestServer(t, "port_batch_artifact")
	ctx := context.Background()
	profileA := "masscan-sha256:" + strings.Repeat("a", 64)
	profileB := "masscan-sha256:" + strings.Repeat("b", 64)
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true;
 INSERT INTO runs(id,name,targets,modes,status) VALUES('history','history','[]','{}','completed')`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "port-artifact", "hostname": "local", "session_id": "s1", "spec": map[string]any{"port_cost_profile": profileA}}, 200, &worker)
	// Samples carry their own frozen identity. Their old worker session/spec is
	// deliberately absent; worker re-registration must never relabel them.
	for i, profile := range []string{profileA, profileA, profileA, profileB, ""} {
		payload, _ := json.Marshal(map[string]any{"targets": []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, "ports": "1-65535", "rate_pps": 5000, "wait_seconds": 15, "port_cost_profile": profile})
		seconds := 110
		if profile != profileA {
			seconds = 180
		}
		_, err := s.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,state,attempt_no,accepted_attempt_no,coverage,first_started_at,completed_at)
 VALUES($1,'history','port',$2,$1,'completed',1,1,'complete',now()-make_interval(secs=>$3),now())`, fmt.Sprintf("sample-%d", i), payload, seconds)
		if err != nil {
			t.Fatal(err)
		}
	}
	load := func() BatchTuning {
		t.Helper()
		tx, err := s.db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		got, err := loadAdaptiveBatch(ctx, tx, "port", 4, 135)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := load(); got.Samples != 3 || got.Size != 3 || got.CostProfile != profileA || got.Reason != "observed" {
		t.Fatal(got)
	}
	targets := make([]string, 24)
	for i := range targets {
		targets[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	seeds, err := buildTaskSeeds(targets, []string{"port"}, false)
	if err != nil {
		t.Fatal(err)
	}
	optimized, err := s.adaptivePortSeeds(ctx, seeds, 1)
	if err != nil || len(optimized) != 8 {
		t.Fatalf("future three-IP batches=%d err=%v", len(optimized), err)
	}
	// The original scopes remain untouched, including timeout and exact range.
	raw, _ := json.Marshal(seeds[0].payload)
	var original map[string]any
	json.Unmarshal(raw, &original)
	if original["ports"] != "1-65535" {
		t.Fatal(original)
	}
	if _, err = s.db.Exec(ctx, `UPDATE workers SET spec=jsonb_set(spec,'{port_cost_profile}',to_jsonb($1::text)) WHERE id=$2`, profileB, worker.ID); err != nil {
		t.Fatal(err)
	}
	if got := load(); got.Samples != 1 || got.CostProfile != profileB || got.Reason != "degraded" {
		t.Fatal("old tasks relabeled by current worker spec", got)
	}
	if _, err = s.db.Exec(ctx, `UPDATE workers SET spec='{}' WHERE id=$1`, worker.ID); err != nil {
		t.Fatal(err)
	}
	if got := load(); got.Samples != 0 || got.Size != 4 || got.Reason != "cold_profile_missing_or_mixed" {
		t.Fatal(got)
	}
	cold, err := s.adaptivePortSeeds(ctx, seeds, 1)
	if err != nil || len(cold) != 6 {
		t.Fatalf("future cold batches=%d err=%v", len(cold), err)
	}
	if _, err = s.db.Exec(ctx, `UPDATE workers SET spec=jsonb_build_object('port_cost_profile',$1::text) WHERE id=$2`, profileA, worker.ID); err != nil {
		t.Fatal(err)
	}
	var second struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "mixed-artifact", "hostname": "local", "session_id": "s2", "spec": map[string]any{"port_cost_profile": profileB}}, 200, &second)
	if got := load(); got.Size != 4 || got.Samples != 0 {
		t.Fatal("mixed pool used a global cost", got)
	}
	if _, err = s.db.Exec(ctx, `UPDATE workers SET maintenance=true WHERE id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	var run Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "future scope", "targets": []string{"198.51.100.1"}, "modes": []string{"port"}}, 201, &run)
	claim := func(id string) *Task {
		t.Helper()
		var out struct {
			Task *Task `json:"task"`
		}
		callAPI(t, h, "POST", "/api/tasks/claim", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "s1", "request_id": id, "types": []string{"port"}, "supports_confirmed_stop": true}, 200, &out)
		return out.Task
	}
	task := claim("first")
	if task == nil {
		t.Fatal("no port task")
	}
	var leased map[string]any
	json.Unmarshal(task.Payload, &leased)
	if leased["port_cost_profile"] != profileA || leased["ports"] != "1-65535" || leased["timeout_seconds"] != float64(180) {
		t.Fatal(leased)
	}
	if _, err = s.db.Exec(ctx, `UPDATE workers SET spec=jsonb_build_object('port_cost_profile',$1::text) WHERE id=$2`, profileB, worker.ID); err != nil {
		t.Fatal(err)
	}
	callAPI(t, h, "POST", "/api/tasks/"+task.ID+"/release", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "s1", "attempt_no": 1, "retryable": true, "stopped": true, "reason": "fixture recovery"}, 200, nil)
	retry := claim("retry")
	if retry == nil || retry.ID != task.ID || retry.AttemptNo != 2 {
		t.Fatal(retry)
	}
	var retried map[string]any
	json.Unmarshal(retry.Payload, &retried)
	if retried["port_cost_profile"] != profileA || retried["ports"] != "1-65535" {
		t.Fatal("retry changed frozen scope/identity", retried)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = validatePortManifest(ctx, tx, run.ID); err != nil {
		t.Fatal(err)
	}
}
