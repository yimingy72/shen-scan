package control

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"testing"
)

func TestAdaptiveBatchCosts(t *testing.T) {
	if got := tuneBatch(nil, 32, 45); got.Size != 32 || got.Reason != "cold" {
		t.Fatal(got)
	}
	slow := []batchCostSample{{32, 90, false}, {32, 90, true}, {32, 1, false}}
	got := tuneBatch(slow, 32, 45)
	before := tuneBatch(slow[:2], 32, 45)
	if got.Size >= 32 || got.Size > before.Size || got.Reason != "degraded" {
		t.Fatal(got, before)
	}
	for _, seconds := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		if got := tuneBatch([]batchCostSample{{8, seconds, false}}, 32, 45); got.Samples != 0 || got.Size != 32 {
			t.Fatal(got)
		}
	}
	many := make([]batchCostSample, 32)
	for i := range many {
		many[i] = batchCostSample{1, 180, true}
	}
	if got := tuneBatch(many, 32, 45); got.Size != 1 {
		t.Fatal(got)
	}
}

func TestAdaptiveWeightedPortCosts(t *testing.T) {
	samples := []portCostSample{}
	for _, work := range []float64{8192, 16384, 32768, 65535} {
		samples = append(samples, portCostSample{work, 20 + work/1000})
	}
	model, ok := fitPortCost(samples, 5000)
	if !ok || math.Abs(model.Rate-1000) > .01 || math.Abs(model.Overhead-20) > .01 {
		t.Fatal(model, ok)
	}
	if _, ok = fitPortCost([]portCostSample{{65535, 80}, {65535, 81}, {65535, 79}, {65535, 80}}, 5000); ok {
		t.Fatal("identical workloads cannot separate startup and rate")
	}
	fast := portStartCandidate{worker: "fast", model: portCostModel{Rate: 1000, Overhead: 15}}
	slow := portStartCandidate{worker: "slow", model: portCostModel{Rate: 300, Overhead: 15}}
	slices := planPortStart(65535, []portStartCandidate{slow, fast}, 5000, 10000, 1)
	if len(slices) != 2 {
		t.Fatal(slices)
	}
	if slices[0].candidate.worker != "fast" || slices[0].last < 49000 || slices[0].last > 52000 {
		t.Fatal(slices)
	}
	next := 1
	for _, slice := range slices {
		if slice.first != next || slice.last < slice.first {
			t.Fatal(slices)
		}
		next = slice.last + 1
	}
	if next != 65536 {
		t.Fatal("coverage gap")
	}
	if got := planPortStart(65535, []portStartCandidate{fast, slow}, 5000, 5000, 1); len(got) != 1 {
		t.Fatal("invented PPS quota", got)
	}
	slow.model.Overhead = 100
	if got := planPortStart(65535, []portStartCandidate{fast, slow}, 5000, 10000, 1); len(got) != 1 {
		t.Fatal("ignored slow startup/wait", got)
	}
	if got := planPortStart(65535, []portStartCandidate{{model: portCostModel{Rate: math.NaN(), Overhead: 15}}}, 5000, 10000, 1); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestAdaptiveHeterogeneousStartupManifest(t *testing.T) {
	t.Setenv("SCAN_PORT_RATE_PPS", "5000")
	t.Setenv("SCAN_TARGET_DISCOVERY_PPS", "10000")
	t.Setenv("SCAN_CALIBRATED_PORT_PROFILE", "")
	s, h := newPolicyTestServer(t, "adaptive_heterogeneous")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	type worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	workers := make([]worker, 2)
	calibrationRun := newID()
	if _, err := s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status) VALUES($1,'synthetic calibration fixture','[]','{port}','completed')`, calibrationRun); err != nil {
		t.Fatal(err)
	}
	for i := range workers {
		callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": fmt.Sprintf("weighted-fixture-%d", i), "hostname": "fixture", "agent_version": "p1-fixture", "session_id": "session", "spec": map[string]any{"port_profile": fmt.Sprintf("fixture-profile-%d", i)}}, 200, &workers[i])
		rate := 1000.0
		if i == 1 {
			rate = 300
		}
		for n, work := range []int{4096, 8192, 16384, 32768} {
			payload, _ := json.Marshal(map[string]any{"targets": []string{"192.0.2.44"}, "ports": fmt.Sprintf("1-%d", work), "rate_pps": 5000, "wait_seconds": 15})
			id := newID()
			_, err := s.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,state,attempt_no,accepted_attempt_no,worker_id,session_id,derived_key,coverage,first_started_at,completed_at)
    VALUES($1,$2,'port',$3,'completed',1,1,$4,'session',$5,'complete',now()-$6::float8*interval '1 second',now())`, id, calibrationRun, payload, workers[i].ID, fmt.Sprintf("calibration-%d-%d", i, n), 15+float64(work)/rate)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	var run Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "weighted live reservations fixture", "targets": []string{"192.0.2.45"}, "modes": []string{"port"}}, 201, &run)
	var wg sync.WaitGroup
	codes := make([]int, 2)
	bodies := make([]string, 2)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := recordAPI(h, "POST", "/api/tasks/claim", workers[i].Token, map[string]any{"worker_id": workers[i].ID, "session_id": "session", "request_id": "weighted-start", "types": []string{"port"}, "supports_confirmed_stop": true, "supports_port_ranges": true, "port_start_reserved": true})
			codes[i] = rr.Code
			bodies[i] = rr.Body.String()
		}(i)
	}
	wg.Wait()
	for i, code := range codes {
		if code != 200 {
			t.Fatal(code, bodies[i])
		}
	}
	rows, err := s.db.Query(ctx, `SELECT m.port_start,m.port_end,t.worker_id FROM port_range_manifest m JOIN tasks t ON t.id=m.task_id WHERE m.run_id=$1 ORDER BY m.port_start`, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	next, count := 1, 0
	for rows.Next() {
		var first, last int
		var workerID string
		if err = rows.Scan(&first, &last, &workerID); err != nil {
			t.Fatal(err)
		}
		if first != next {
			t.Fatal("gap", first, next)
		}
		if count == 0 && (workerID != workers[0].ID || last < 49000 || last > 52000) {
			t.Fatal("not proportional", workerID, last)
		}
		next = last + 1
		count++
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 || next != 65536 {
		t.Fatal("manifest", count, next, bodies)
	}
	var pps int
	if err = s.db.QueryRow(ctx, `SELECT COALESCE(sum(amount),0) FROM target_quotas WHERE scope='192.0.2.45' AND state<>'released'`).Scan(&pps); err != nil || pps != 10000 {
		t.Fatal("PPS quota", pps, err)
	}
}
