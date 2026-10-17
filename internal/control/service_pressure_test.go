package control

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestServicePressureThresholds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		age       float64
		endpoints int
		previous  bool
		cost      BatchTuning
		want      bool
	}{
		{"cold backlog", 30, 8, false, BatchTuning{}, true},
		{"young backlog", 29, 100, false, BatchTuning{}, false},
		{"small old queue", 600, 3, false, BatchTuning{}, false},
		{"hysteresis", 10, 4, true, BatchTuning{}, true},
		{"age exit", 9, 100, true, BatchTuning{}, false},
		{"work exit", 600, 3, true, BatchTuning{}, false},
		{"observed costly work", 30, 3, false, BatchTuning{Samples: 3, SecondsPerItem: 30}, true},
		{"sparse cost ignored", 30, 3, false, BatchTuning{Samples: 2, SecondsPerItem: 30}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := decideServicePressure(servicePressure{OldestWaitSeconds: tc.age, SampledEndpoints: tc.endpoints}, tc.cost, tc.previous)
			if p.PreferService != tc.want {
				t.Fatalf("pressure=%+v, want prefer=%v", p, tc.want)
			}
			if tc.cost.Samples < 3 && (p.SecondsPerEndpoint != 0 || p.SampledEstimatedWorkSeconds != 0) {
				t.Fatalf("cold/sparse history invented cost: %+v", p)
			}
		})
	}
}

func TestServicePressureCache(t *testing.T) {
	var cache servicePressureCache
	now := time.Now()
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	load := func(ctx context.Context, previous bool) (servicePressure, error) {
		calls.Add(1)
		if _, ok := ctx.Deadline(); !ok || previous {
			t.Error("missing query deadline or unexpected initial preference")
		}
		close(entered)
		<-release
		return servicePressure{Available: true, PreferService: true, ObservedAt: now}, nil
	}
	done := make(chan servicePressure, 1)
	go func() { done <- cache.get(context.Background(), now, load) }()
	<-entered
	if p := cache.get(context.Background(), now, load); p.Available || p.PreferService || p.Reason != "refreshing" {
		t.Fatalf("concurrent refresh should be nonblocking with no hint: %+v", p)
	}
	close(release)
	if p := <-done; !p.PreferService {
		t.Fatal("initial refresh lost preference")
	}
	if p := cache.get(context.Background(), now.Add(time.Second), load); !p.PreferService || calls.Load() != 1 {
		t.Fatalf("cache hit queried again: %+v calls=%d", p, calls.Load())
	}
	refreshEntered, refreshRelease := make(chan struct{}), make(chan struct{})
	fail := func(ctx context.Context, previous bool) (servicePressure, error) {
		calls.Add(1)
		if !previous {
			t.Error("refresh lost hysteresis state")
		}
		close(refreshEntered)
		<-refreshRelease
		return servicePressure{}, errors.New("database unavailable")
	}
	go func() { done <- cache.get(context.Background(), now.Add(10*time.Second), fail) }()
	<-refreshEntered
	for i := 0; i < 10; i++ {
		if p := cache.get(context.Background(), now.Add(10*time.Second), fail); !p.Available || !p.PreferService || !p.ObservedAt.Equal(now) {
			t.Fatalf("refresh discarded recent successful snapshot: %+v", p)
		}
	}
	if p := cache.get(context.Background(), now.Add(servicePreferenceTTL*time.Second), fail); !p.PreferService {
		t.Fatalf("maximum-age snapshot should remain usable: %+v", p)
	}
	if p := cache.get(context.Background(), now.Add(servicePreferenceTTL*time.Second+time.Nanosecond), fail); p.Available || p.PreferService || p.Reason != "refreshing" {
		t.Fatalf("refresh retained an over-age snapshot: %+v", p)
	}
	close(refreshRelease)
	if p := <-done; p.Available || p.PreferService || p.Reason != "unavailable" {
		t.Fatalf("failed refresh retained hint: %+v", p)
	}
	if p := cache.get(context.Background(), now.Add(11*time.Second), fail); p.Available || p.PreferService || p.Reason != "unavailable" {
		t.Fatalf("failed refresh did not replace old success: %+v", p)
	}
	if calls.Load() != 2 {
		t.Fatalf("error refresh storm: calls=%d", calls.Load())
	}
}

func TestPostgresServicePressureWindow(t *testing.T) {
	s, h := newPolicyTestServer(t, "service_pressure")
	ctx := context.Background()
	_, err := s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status) VALUES
 ('pressure-active','active','[]','{}','running'),('pressure-paused','paused','[]','{}','paused');
 INSERT INTO tasks(id,run_id,type,derived_key,payload,created_at)
 SELECT 'paused-'||n,'pressure-paused','service','paused-'||n,'{"endpoints":[{}],"service_profile":"nmap-light-v1"}'::jsonb,now()-interval '1 day'
 FROM generate_series(1,1100) n;
 INSERT INTO tasks(id,run_id,type,derived_key,payload,created_at)
 SELECT 'active-'||n,'pressure-active','service','active-'||n,'{"endpoints":[{},{},{},{},{},{},{},{}],"service_profile":"nmap-light-v1"}'::jsonb,now()-interval '60 seconds'
 FROM generate_series(1,1030) n`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.loadServicePressure(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Available || p.PreferService || p.CandidateTasks != servicePressureSampleLimit || p.SampledTasks != 0 || !p.Truncated || !p.WorkIsLowerBound {
		t.Fatalf("paused candidate window must not trigger or scan newer work: %+v", p)
	}
	if _, err = s.db.Exec(ctx, `UPDATE runs SET status='running' WHERE id='pressure-paused';
 UPDATE tasks SET payload=jsonb_set(payload,'{service_profile}','"incompatible-v2"') WHERE run_id='pressure-paused'`); err != nil {
		t.Fatal(err)
	}
	p, err = s.loadServicePressure(ctx, false)
	if err != nil || p.PreferService || p.SampledTasks != 0 || p.CandidateTasks != servicePressureSampleLimit {
		t.Fatalf("incompatible candidate window pressure=%+v err=%v", p, err)
	}
	if _, err = s.db.Exec(ctx, `DELETE FROM runs WHERE id='pressure-paused'`); err != nil {
		t.Fatal(err)
	}
	p, err = s.loadServicePressure(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Available || !p.PreferService || p.CandidateTasks != servicePressureSampleLimit || p.SampledTasks != servicePressureSampleLimit || p.SampledEndpoints != 8*servicePressureSampleLimit || !p.Truncated || !p.WorkIsLowerBound || p.OldestWaitSeconds > 120 || p.CostSamples != 0 || p.SecondsPerEndpoint != 0 {
		t.Fatalf("bounded active-only cold snapshot: %+v", p)
	}
	call := earlyEvidenceCaller(t, h)
	var status struct {
		Pressure servicePressure `json:"service_pressure"`
	}
	call(http.MethodGet, "/api/scheduler/status", "admin-policy", nil, http.StatusOK, &status)
	if !status.Pressure.PreferService || !status.Pressure.Truncated {
		t.Fatalf("status pressure=%+v", status.Pressure)
	}
	if _, err = s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	callAPI(t, h, http.MethodPost, "/api/workers/register", "join-policy", map[string]any{
		"instance_id": "pressure-local", "hostname": "local", "session_id": "pressure-session",
	}, http.StatusOK, &worker)
	var heartbeat struct {
		Prefer bool `json:"prefer_service"`
		TTL    int  `json:"preference_ttl_seconds"`
	}
	callAPI(t, h, http.MethodPost, "/api/workers/heartbeat", worker.Token, map[string]any{
		"worker_id": worker.ID, "session_id": "pressure-session", "status": "ready",
	}, http.StatusOK, &heartbeat)
	if !heartbeat.Prefer || heartbeat.TTL != servicePreferenceTTL {
		t.Fatalf("heartbeat hint=%+v", heartbeat)
	}
	if _, err = s.db.Exec(ctx, `DELETE FROM tasks WHERE run_id='pressure-active' AND substring(id FROM 8)::int>1024`); err != nil {
		t.Fatal(err)
	}
	p, err = s.loadServicePressure(ctx, false)
	if err != nil || p.Truncated || p.WorkIsLowerBound || p.CandidateTasks != servicePressureSampleLimit || p.SampledTasks != servicePressureSampleLimit {
		t.Fatalf("exact window boundary pressure=%+v err=%v", p, err)
	}
	if _, err = s.db.Exec(ctx, `UPDATE runs SET status='paused' WHERE id='pressure-active'`); err != nil {
		t.Fatal(err)
	}
	p, err = s.loadServicePressure(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.PreferService || p.SampledTasks != 0 || p.SampledEndpoints != 0 || p.Truncated || p.OldestWaitSeconds != 0 {
		t.Fatalf("paused run triggered pressure: %+v", p)
	}
}
