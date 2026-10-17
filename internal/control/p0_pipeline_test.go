package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"scanplatform/internal/webevidence"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestP0PartitionGainAndScope(t *testing.T) {
	if k := choosePortPartitions(65535, 10, 5000, 50000, 15, 0); k != 4 {
		t.Fatalf("expected 4, got %d", k)
	}
	// Previously k=2 violated the final selected candidate's gain threshold.
	if k := choosePortPartitions(65535, 10, 20000, 200000, 15, 0); k == 2 {
		t.Fatal("selected under-threshold split")
	}
	if k := choosePortPartitions(65535, 10, 5000, 5000, 15, 0); k != 1 {
		t.Fatal("splitting invented target capacity")
	}
	if k := choosePortPartitions(65535, 0, 0, 5000, 15, 0); k != 1 {
		t.Fatal("missing baseline must fall back")
	}
	for k := 1; k <= 15; k++ {
		next := 1
		for i := 0; i < k; i++ {
			lo, hi, err := parsePortInterval(fmt.Sprintf("%d-%d", 1+i*65535/k, (i+1)*65535/k))
			if err != nil || lo != next {
				t.Fatal("coverage gap")
			}
			next = hi + 1
		}
		if next != 65536 {
			t.Fatal("coverage tail gap")
		}
	}
	raw := []byte(`{"targets":["192.0.2.1"],"ports":"16384-32767"}`)
	if _, err := observationTarget("port", raw, "192.0.2.1", &Observation{Kind: "port", IP: "192.0.2.1", Port: 80}); err == nil {
		t.Fatal("foreign interval result accepted")
	}
}

func TestP0CorePipelineAndQuotaRecovery(t *testing.T) {
	t.Setenv("SCAN_PORT_RATE_PPS", "5000")
	t.Setenv("SCAN_TARGET_DISCOVERY_PPS", "20000")
	t.Setenv("SCAN_CALIBRATED_PORT_PROFILE", "local-fixture")
	t.Setenv("SCAN_CALIBRATED_SYN_RATE", "5000")
	t.Setenv("SCAN_CALIBRATED_PPS", "5000")
	s, h := newPolicyTestServer(t, "p0_core")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	type worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	workers := make([]worker, 4)
	for i := range workers {
		callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": fmt.Sprintf("fixture-%d", i), "hostname": "local", "agent_version": "p0", "session_id": "s1", "spec": map[string]any{"port_profile": "local-fixture"}}, 200, &workers[i])
	}
	var run Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "P0 closure", "targets": []string{"192.0.2.1"}, "modes": []string{"port", "http"}}, 201, &run)
	claims := make([]*Task, 4)
	errors := make([]string, 4)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := recordAPI(h, "POST", "/api/tasks/claim", workers[i].Token, map[string]any{"worker_id": workers[i].ID, "session_id": "s1", "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": "start", "types": []string{"port"}, "supports_port_ranges": true, "port_start_reserved": true})
			if rr.Code != 200 {
				errors[i] = rr.Body.String()
				return
			}
			var out struct {
				Task *Task `json:"task"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
				errors[i] = err.Error()
				return
			}
			claims[i] = out.Task
		}(i)
	}
	wg.Wait()
	for _, err := range errors {
		if err != "" {
			t.Fatal(err)
		}
	}
	count := 0
	intervals := [][2]int{}
	for _, task := range claims {
		if task != nil {
			count++
			var p struct {
				Ports string `json:"ports"`
			}
			json.Unmarshal(task.Payload, &p)
			lo, hi, err := parsePortInterval(p.Ports)
			if err != nil {
				t.Fatal(err)
			}
			intervals = append(intervals, [2]int{lo, hi})
		}
	}
	if count < 2 {
		var diagnostic []byte
		s.db.QueryRow(ctx, `SELECT jsonb_build_object('tasks',(SELECT jsonb_agg(jsonb_build_object('payload',payload,'worker',worker_id)) FROM tasks),'tickets',(SELECT jsonb_agg(to_jsonb(p)) FROM port_start_tickets p),'quotas',(SELECT jsonb_agg(to_jsonb(q)) FROM target_quotas q))`).Scan(&diagnostic)
		t.Fatalf("real startup reservations did not split: %d %s", count, diagnostic)
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i][0] < intervals[j][0] })
	next := 1
	for _, interval := range intervals {
		if interval[0] != next {
			t.Fatal("manifest gap")
		}
		next = interval[1] + 1
	}
	if next != 65536 {
		t.Fatal("manifest incomplete")
	}
	var portWorker int
	for i, task := range claims {
		if task == nil {
			continue
		}
		var p struct{ Ports string }
		json.Unmarshal(task.Payload, &p)
		lo, _, _ := parsePortInterval(p.Ports)
		identity := map[string]any{"worker_id": workers[i].ID, "session_id": "s1", "attempt_no": task.AttemptNo, "last_batch_seq": -1}
		if lo == 1 {
			portWorker = i
			identity["last_batch_seq"] = 0
			callAPI(t, h, "POST", "/api/tasks/"+task.ID+"/batches", workers[i].Token, map[string]any{"worker_id": workers[i].ID, "session_id": "s1", "attempt_no": task.AttemptNo, "batch_seq": 0, "items": []Observation{{Kind: "port", IP: "192.0.2.1", Target: "192.0.2.1", Port: 80, Protocol: "tcp"}}}, 200, nil)
		}
		callAPI(t, h, "POST", "/api/tasks/"+task.ID+"/complete", workers[i].Token, identity, 200, nil)
	}
	var services, web int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FILTER(WHERE type='service'),count(*) FILTER(WHERE type='http') FROM tasks WHERE run_id=$1`, run.ID).Scan(&services, &web); err != nil {
		t.Fatal(err)
	}
	if services != 1 || web != 0 {
		t.Fatalf("port bypassed service stage: %d/%d", services, web)
	}
	w := workers[portWorker]
	request := 0
	claim := func(types ...string) *Task {
		t.Helper()
		request++
		var out struct {
			Task *Task `json:"task"`
		}
		callAPI(t, h, "POST", "/api/tasks/claim", w.Token, map[string]any{"worker_id": w.ID, "session_id": "s1", "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": fmt.Sprintf("next-%d", request), "types": types, "service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile, "fingerprint_bundle": webevidence.FingerprintBundle}, 200, &out)
		return out.Task
	}
	service := claim("service")
	if service == nil {
		t.Fatal("service not claimable")
	}
	var serviceProfile struct {
		Profile                 string `json:"service_profile"`
		TimeoutSeconds          int    `json:"timeout_seconds"`
		ExecutionTimeoutSeconds int    `json:"execution_timeout_seconds"`
	}
	if err := json.Unmarshal(service.Payload, &serviceProfile); err != nil || serviceProfile.Profile != "nmap-light-v1" || serviceProfile.TimeoutSeconds != 60 || serviceProfile.ExecutionTimeoutSeconds != 90 {
		t.Fatalf("Nmap batch requires a 60-second tool budget within a 90-second task: %s (%v)", service.Payload, err)
	}
	callAPI(t, h, "POST", "/api/tasks/"+service.ID+"/batches", w.Token, map[string]any{"worker_id": w.ID, "session_id": "s1", "attempt_no": service.AttemptNo, "batch_seq": 0, "items": []Observation{{Kind: "service", IP: "192.0.2.1", Target: "192.0.2.1", Port: 80, Service: "http", Outcome: "identified"}}}, 200, nil)
	complete := map[string]any{"worker_id": w.ID, "session_id": "s1", "attempt_no": service.AttemptNo, "last_batch_seq": 0}
	callAPI(t, h, "POST", "/api/tasks/"+service.ID+"/complete", w.Token, complete, 200, nil)
	complete["last_batch_seq"] = -1
	callAPI(t, h, "POST", "/api/tasks/"+service.ID+"/complete", w.Token, complete, http.StatusConflict, nil)
	httpTask := claim("http")
	if httpTask == nil {
		t.Fatal("Web stage not derived")
	}
	var ep struct{ Endpoints []taskEndpoint }
	json.Unmarshal(httpTask.Payload, &ep)
	if len(ep.Endpoints) != 1 {
		t.Fatal("Web unit is not one entry")
	}
	callAPI(t, h, "POST", "/api/tasks/"+httpTask.ID+"/batches", w.Token, map[string]any{"worker_id": w.ID, "session_id": "s1", "attempt_no": httpTask.AttemptNo, "batch_seq": 0, "items": []Observation{{Kind: "http", IP: "192.0.2.1", Target: "192.0.2.1", Port: 80, URL: "http://192.0.2.1:80/", Error: "fixture timeout", Outcome: "incomplete", Coverage: "partial"}}}, 200, nil)
	callAPI(t, h, "POST", "/api/tasks/"+httpTask.ID+"/complete", w.Token, map[string]any{"worker_id": w.ID, "session_id": "s1", "attempt_no": httpTask.AttemptNo, "last_batch_seq": 0}, 200, nil)
	callAPI(t, h, "GET", "/api/runs/"+run.ID, "admin-policy", nil, 200, &run)
	if run.Status != "partial" {
		t.Fatalf("incomplete entry reported %s", run.Status)
	}
	// An expired external process is not made safe by an expired lease or cancel.
	var run2 Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "quota recovery", "targets": []string{"192.0.2.2"}, "modes": []string{"port"}}, 201, &run2)
	old := claim("port")
	if old == nil {
		t.Fatal("port start missing")
	}
	if _, err := s.db.Exec(ctx, `UPDATE tasks SET lease_until=now()-interval '1 minute' WHERE id=$1;`, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `UPDATE target_quotas SET valid_until=now()-interval '1 minute' WHERE task_id=$1 AND state='active'`, old.ID); err != nil {
		t.Fatal(err)
	}
	if retry := claim("port"); retry != nil {
		t.Fatal("lease expiry recycled unknown process quota")
	}
	pending, err := s.PendingStopInstances(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("stop recovery=%v %v", pending, err)
	}
	if err = s.ConfirmWorkerStopped(ctx, pending[0], "different-session", "fixture stopped"); err != nil {
		t.Fatal(err)
	}
	if retry := claim("port"); retry != nil {
		t.Fatal("wrong session released quota")
	}
	if err = s.ConfirmInstanceStopped(ctx, pending[0], "fixture terminal instance evidence"); err != nil {
		t.Fatal(err)
	}
	retry := claim("port")
	if retry == nil || retry.ID != old.ID || retry.AttemptNo != old.AttemptNo+1 {
		t.Fatalf("same range not retried after stop proof: %#v", retry)
	}
	callAPI(t, h, "POST", "/api/tasks/"+old.ID+"/batches", w.Token, map[string]any{"worker_id": w.ID, "session_id": "s1", "attempt_no": old.AttemptNo, "batch_seq": 0, "items": []Observation{{Kind: "port", IP: "192.0.2.2", Port: 443}}}, http.StatusConflict, nil)
}

func TestP0ExpiredStartupReservationDoesNotPoisonNewExecution(t *testing.T) {
	s, h := newPolicyTestServer(t, "p0_takeover")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	type worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	var a, b worker
	for i, w := range []*worker{&a, &b} {
		callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": fmt.Sprintf("takeover-%d", i), "hostname": "local", "session_id": "s1"}, 200, w)
	}
	var run Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "expired startup", "targets": []string{"192.0.2.9"}, "modes": []string{"port"}}, 201, &run)
	var taskID string
	if err := s.db.QueryRow(ctx, `SELECT id FROM tasks WHERE run_id=$1`, run.ID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO target_quotas(epoch,task_id,attempt_no,worker_id,instance_id,session_id,scope,dimension,amount,state,valid_until)
        SELECT 'expired-ticket',$1,1,id,instance_id,'s1','192.0.2.9','discovery_pps',5000,'reserved',now()-interval '1 second' FROM workers WHERE id=$2`, taskID, a.ID); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Task *Task `json:"task"`
	}
	callAPI(t, h, "POST", "/api/tasks/claim", b.Token, map[string]any{"worker_id": b.ID, "session_id": "s1", "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": "takeover", "types": []string{"port"}, "supports_port_ranges": true}, 200, &out)
	if out.Task == nil || out.Task.ID != taskID || out.Task.AttemptNo != 1 {
		t.Fatalf("B did not take over attempt 1: %+v", out.Task)
	}
	var oldUntil time.Time
	var oldState, oldEvidence string
	if err := s.db.QueryRow(ctx, `SELECT valid_until,state,stop_evidence FROM target_quotas WHERE epoch='expired-ticket'`).Scan(&oldUntil, &oldState, &oldEvidence); err != nil || oldState != "released" {
		t.Fatalf("expired reservation not released: %s %v", oldState, err)
	}
	// A previous session of B is also historical, even with the same worker ID.
	if _, err := s.db.Exec(ctx, `INSERT INTO target_quotas(epoch,task_id,attempt_no,worker_id,instance_id,session_id,scope,dimension,amount,state,valid_until,stop_evidence)
        SELECT 'old-session',$1,1,id,instance_id,'s0','192.0.2.9','discovery_pps',5000,'released',$3,'old session stopped' FROM workers WHERE id=$2`, taskID, b.ID, oldUntil); err != nil {
		t.Fatal(err)
	}
	identity := map[string]any{"worker_id": b.ID, "session_id": "s1", "attempt_no": 1}
	var renewed struct {
		Action string `json:"action"`
	}
	callAPI(t, h, "POST", "/api/tasks/"+taskID+"/renew", b.Token, identity, 200, &renewed)
	if renewed.Action != "continue" {
		t.Fatalf("historical reservation stopped B: %s", renewed.Action)
	}
	// Stop evidence for the old session must not release the replacement.
	if err := s.ConfirmWorkerStopped(ctx, "takeover-0", "s1", "old worker stopped"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmWorkerStopped(ctx, "takeover-1", "s0", "old B session stopped"); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM target_quotas WHERE task_id=$1 AND worker_id=$2 AND session_id='s1' AND state='active'`, taskID, b.ID).Scan(&active); err != nil || active != 1 {
		t.Fatalf("old stop confirmation affected B: %d %v", active, err)
	}
	for _, state := range []string{"suspect", "released"} {
		if _, err := s.db.Exec(ctx, `UPDATE target_quotas SET state=$3 WHERE task_id=$1 AND worker_id=$2 AND session_id='s1'`, taskID, b.ID, state); err != nil {
			t.Fatal(err)
		}
		callAPI(t, h, "POST", "/api/tasks/"+taskID+"/renew", b.Token, identity, 200, &renewed)
		if renewed.Action != "stop" {
			t.Fatalf("current %s quota was renewed", state)
		}
	}
	if _, err := s.db.Exec(ctx, `UPDATE target_quotas SET state='active' WHERE task_id=$1 AND worker_id=$2 AND session_id='s1'`, taskID, b.ID); err != nil {
		t.Fatal(err)
	}
	identity["stopped"], identity["reason"] = true, "replacement exited"
	callAPI(t, h, "POST", "/api/tasks/"+taskID+"/release", b.Token, identity, 200, nil)
	var unchanged bool
	if err := s.db.QueryRow(ctx, `SELECT valid_until=$1 AND state=$2 AND stop_evidence=$3 FROM target_quotas WHERE epoch='expired-ticket'`, oldUntil, oldState, oldEvidence).Scan(&unchanged); err != nil || !unchanged {
		t.Fatalf("B renewed or overwrote old reservation evidence: %v %v", unchanged, err)
	}
	if err := s.db.QueryRow(ctx, `SELECT valid_until=$1 AND state='released' AND stop_evidence='old session stopped' FROM target_quotas WHERE epoch='old-session'`, oldUntil).Scan(&unchanged); err != nil || !unchanged {
		t.Fatalf("current session renewed or overwrote old session evidence: %v %v", unchanged, err)
	}
}

func TestP0IndependentWebEntriesShareTwoTargetSlots(t *testing.T) {
	s, h := newPolicyTestServer(t, "p0_web_slots")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var w struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "web-slots", "hostname": "local", "session_id": "s1"}, 200, &w)
	create := func(path string) Run {
		t.Helper()
		var run Run
		callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": path, "targets": []string{"http://example.com/" + path}, "modes": []string{"http"}}, 201, &run)
		return run
	}
	request := 0
	claim := func(stage string) *Task {
		t.Helper()
		request++
		var out struct {
			Task *Task `json:"task"`
		}
		callAPI(t, h, "POST", "/api/tasks/claim", w.Token, map[string]any{"worker_id": w.ID, "session_id": "s1", "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": fmt.Sprintf("web-%d", request), "types": []string{stage}, "service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile, "fingerprint_bundle": webevidence.FingerprintBundle}, 200, &out)
		return out.Task
	}
	slow := create("slow")
	if task := claim("http"); task == nil || task.RunID != slow.ID {
		t.Fatalf("slow entry not claimed: %+v", task)
	}
	create("slow")
	if task := claim("http"); task != nil {
		t.Fatalf("duplicate entry claimed concurrently: %+v", task)
	}
	fast := create("fast")
	if task := claim("http"); task == nil || task.RunID != fast.ID {
		t.Fatalf("slow entry blocked independent fast entry: %+v", task)
	}
	create("third")
	if task := claim("http"); task != nil {
		t.Fatalf("exceeded two global target Web slots: %+v", task)
	}
	for _, stage := range []string{"service", "poc"} {
		payload, _ := json.Marshal(map[string]any{"endpoints": []map[string]any{{"host": "example.com", "port": 80}}})
		if _, err := s.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,target_key,derived_key) VALUES($1,$2,$3,$4,'example.com',$3)`, newID(), slow.ID, stage, payload); err != nil {
			t.Fatal(err)
		}
		if task := claim(stage); task != nil {
			t.Fatalf("Web concurrency bypassed %s target exclusion: %+v", stage, task)
		}
	}
}

func TestP0ServiceWebDispatchPreservesSchemeEvidence(t *testing.T) {
	s, h := newPolicyTestServer(t, "p0_web_scheme")
	ctx := context.Background()
	var run Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "scheme evidence", "targets": []string{"192.0.2.19"}, "modes": []string{"port", "http"}}, 201, &run)
	var parentID string
	if err := s.db.QueryRow(ctx, `SELECT id FROM tasks WHERE run_id=$1`, run.ID).Scan(&parentID); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	cases := []struct {
		service, tunnel string
		port            int
		url             string
	}{
		{"http", "ssl", 18081, "https://192.0.2.19:18081/"},
		{"http", "tls", 18082, "https://192.0.2.19:18082/"},
		{"https", "", 18083, "https://192.0.2.19:18083/"},
		{"ssl/http", "", 18084, "https://192.0.2.19:18084/"},
		{"http", "", 443, "http://192.0.2.19:443/"},
		{"unknown", "", 18085, ""},
	}
	for i, test := range cases {
		o := Observation{Kind: "service", IP: "192.0.2.19", Port: test.port, Service: test.service, ServiceTunnel: test.tunnel, Outcome: "identified"}
		raw, _ := json.Marshal(o)
		if _, err := tx.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,observation) VALUES($1,$2,$3,1,0,$4,$5)`, newID(), run.ID, parentID, i, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := deriveServiceWebTasks(ctx, tx, parentID, run.ID, 1, []byte(`{"http_enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		var payload []byte
		if err := tx.QueryRow(ctx, `SELECT payload FROM tasks WHERE run_id=$1 AND type='http' AND (payload->'endpoints'->0->>'port')::int=$2`, run.ID, test.port).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var p struct{ Endpoints []taskEndpoint }
		if json.Unmarshal(payload, &p) != nil || len(p.Endpoints) != 1 || p.Endpoints[0].URL != test.url || p.Endpoints[0].Port != test.port {
			t.Fatalf("service=%s tunnel=%s: wrong dispatch %s", test.service, test.tunnel, payload)
		}
	}
}
