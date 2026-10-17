package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestWorkerMaintenanceAndConfirmedStopCompatibility(t *testing.T) {
	t.Setenv("SCAN_PORT_RATE_PPS", "5000")
	t.Setenv("SCAN_TARGET_DISCOVERY_PPS", "20000")
	t.Setenv("SCAN_CALIBRATED_PORT_PROFILE", "maintenance-fixture")
	t.Setenv("SCAN_CALIBRATED_SYN_RATE", "5000")
	t.Setenv("SCAN_CALIBRATED_PPS", "5000")
	s, h := newPolicyTestServer(t, "maintenance")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true,desired_workers=1`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	register := func(session string) {
		t.Helper()
		callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "maintenance-fixture", "hostname": "local", "session_id": session, "spec": map[string]any{"port_profile": "maintenance-fixture"}}, 200, &worker)
	}
	register("s1")
	var run Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "maintenance", "targets": []string{"192.0.2.80"}, "modes": []string{"port"}}, 201, &run)
	claim := func(request string, capable bool) *Task {
		t.Helper()
		body := map[string]any{"worker_id": worker.ID, "session_id": "s1", "request_id": request, "types": []string{"port"}, "supports_port_ranges": true, "port_start_reserved": true}
		if capable {
			body["supports_confirmed_stop"] = true
		}
		var out struct{ Task *Task }
		callAPI(t, h, "POST", "/api/tasks/claim", worker.Token, body, 200, &out)
		return out.Task
	}
	if task := claim("old", false); task != nil {
		t.Fatal("old Agent acquired new work")
	}
	var oldResponse struct{ Task *Task }
	callAPI(t, h, "POST", "/api/tasks/claim", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "s1", "request_id": "explicit-false", "types": []string{"port"}, "supports_confirmed_stop": false}, 200, &oldResponse)
	if oldResponse.Task != nil {
		t.Fatal("Agent explicitly lacking stop confirmation acquired work")
	}
	assertNoStartup := func() {
		t.Helper()
		var occupied int
		if err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM target_quotas)+(SELECT count(*) FROM port_start_tickets)+(SELECT count(*) FROM tasks WHERE attempt_no>0)`).Scan(&occupied); err != nil || occupied != 0 {
			t.Fatalf("blocked claim created execution/reservation: %d, %v", occupied, err)
		}
	}
	assertNoStartup()
	path := "/api/workers/" + worker.ID + "/maintenance"
	var response struct {
		Maintenance bool   `json:"maintenance"`
		SessionID   string `json:"session_id"`
		Active      int    `json:"active_tasks"`
	}
	callAPI(t, h, "POST", path, "admin-policy", map[string]any{"enabled": true}, 200, &response)
	if !response.Maintenance || response.SessionID != "s1" || response.Active != 0 {
		t.Fatalf("unexpected maintenance response: %+v", response)
	}
	if task := claim("maintenance", true); task != nil {
		t.Fatal("maintenance permitted new execution")
	}
	assertNoStartup()
	callAPI(t, h, "POST", "/api/workers/heartbeat", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "s1", "status": "ready"}, 200, nil)
	workers, err := s.WorkerInstances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w := workers["maintenance-fixture"]
	if !w.Maintenance || w.Status != "ready" || w.SessionID != "s1" {
		t.Fatalf("maintenance changed cloud health or heartbeat cleared it: %+v", w)
	}
	var listed struct{ Items []Worker }
	callAPI(t, h, "GET", "/api/workers", "admin-policy", nil, 200, &listed)
	if len(listed.Items) != 1 || !listed.Items[0].Maintenance {
		t.Fatal("worker list omitted maintenance")
	}
	var desired int
	var enabled bool
	var drainReason string
	if err := s.db.QueryRow(ctx, `SELECT p.enabled,p.desired_workers,COALESCE(w.spec->>'drain_reason','') FROM worker_pool p CROSS JOIN workers w`).Scan(&enabled, &desired, &drainReason); err != nil || !enabled || desired != 1 || drainReason != "" {
		t.Fatalf("maintenance changed pool/drain state: %v %d %q %v", enabled, desired, drainReason, err)
	}
	callAPI(t, h, "POST", path, "admin-policy", map[string]any{"enabled": false}, 400, nil)
	callAPI(t, h, "POST", path, "admin-policy", map[string]any{"enabled": false, "expected_session_id": "stale"}, 409, nil)
	callAPI(t, h, "POST", path, "admin-policy", map[string]any{"enabled": false, "expected_session_id": "s1"}, 200, nil)
	// No calibration is needed to test the normal complete-range execution.
	t.Setenv("SCAN_CALIBRATED_PORT_PROFILE", "")
	task := claim("capable", true)
	if task == nil {
		t.Fatal("capable Agent could not claim after maintenance")
	}
	callAPI(t, h, "POST", path, "admin-policy", map[string]any{"enabled": true, "expected_session_id": "s1"}, 200, &response)
	if response.Active != 1 {
		t.Fatalf("maintenance lost in-flight execution: %+v", response)
	}
	if replay := claim("capable", false); replay == nil || replay.ID != task.ID || replay.AttemptNo != task.AttemptNo {
		t.Fatal("legacy request replay lost its existing execution")
	}
	var renewed struct{ Action string }
	callAPI(t, h, "POST", "/api/tasks/"+task.ID+"/renew", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "s1", "attempt_no": task.AttemptNo}, 200, &renewed)
	if renewed.Action != "continue" {
		t.Fatalf("maintenance stopped an active task: %s", renewed.Action)
	}
	callAPI(t, h, "POST", "/api/tasks/"+task.ID+"/complete", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "s1", "attempt_no": task.AttemptNo, "last_batch_seq": -1}, 200, nil)
	register("s2")
	callAPI(t, h, "POST", path, "admin-policy", map[string]any{"enabled": false, "expected_session_id": "s1"}, 409, nil)
	workers, err = s.WorkerInstances(ctx)
	if err != nil || !workers["maintenance-fixture"].Maintenance {
		t.Fatal("registration cleared maintenance")
	}
	callAPI(t, h, "POST", path, "admin-policy", map[string]any{"enabled": false, "expected_session_id": "s2"}, 200, &response)
	if response.Active != 0 || response.Maintenance {
		t.Fatalf("completed execution still active: %+v", response)
	}
}

func TestUnknownQuotaSurvivesRunDeletion(t *testing.T) {
	s, h := newPolicyTestServer(t, "quota_retention")
	ctx := context.Background()
	// Exercise upgrading a database with the original cascading constraint.
	if _, err := s.db.Exec(ctx, `ALTER TABLE target_quotas ADD CONSTRAINT target_quotas_task_id_fkey FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, schema); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		ID string `json:"worker_id"`
	}
	callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "retained-instance", "hostname": "local", "session_id": "retained-session"}, 200, &worker)
	var run Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "retention", "targets": []string{"192.0.2.90"}, "modes": []string{"port"}}, 201, &run)
	if _, err := s.db.Exec(ctx, `INSERT INTO target_quotas(epoch,task_id,attempt_no,worker_id,instance_id,session_id,scope,dimension,amount,state,valid_until,suspect_since,revoke_deadline)
	 SELECT 'retained-quota',id,1,$2,'retained-instance','retained-session','192.0.2.90','discovery_pps',5000,'suspect',now()-interval '1 second',now(),now()+interval '90 seconds' FROM tasks WHERE run_id=$1`, run.ID, worker.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM runs WHERE id=$1`, run.ID); err != nil {
		t.Fatal(err)
	}
	unknown, err := s.UnknownWorkerQuotas(ctx)
	if err != nil || len(unknown) != 1 || unknown[0].Epoch != "retained-quota" {
		t.Fatalf("run deletion lost unknown allocation: %+v %v", unknown, err)
	}
	var response struct {
		Active int `json:"active_tasks"`
	}
	callAPI(t, h, "POST", "/api/workers/"+worker.ID+"/maintenance", "admin-policy", map[string]any{"enabled": true}, 200, &response)
	if response.Active != 1 {
		t.Fatal("deleted task's unknown executor was reported idle")
	}
	if err := s.ConfirmWorkerStopped(ctx, "retained-instance", "retained-session", "fixture instance stop confirmed"); err != nil {
		t.Fatal(err)
	}
	var state, evidence string
	if err := s.db.QueryRow(ctx, `SELECT state,stop_evidence FROM target_quotas WHERE epoch='retained-quota'`).Scan(&state, &evidence); err != nil || state != "released" || evidence != "fixture instance stop confirmed" {
		t.Fatalf("orphan quota could not be released: %s %q %v", state, evidence, err)
	}
}

func TestWorkerMaintenanceSerializesWithConcurrentClaim(t *testing.T) {
	t.Setenv("SCAN_CALIBRATED_PORT_PROFILE", "")
	s, h := newPolicyTestServer(t, "maintenance_race")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "race-worker", "hostname": "local", "session_id": "s1"}, 200, &worker)
	var run Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "race", "targets": []string{"192.0.2.81"}, "modes": []string{"port"}}, 201, &run)
	guard, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Rollback(ctx)
	if _, err = guard.Exec(ctx, `SELECT pg_advisory_xact_lock($1,hashtext($2))`, workerClaimLockNamespace, worker.ID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		status int
		body   []byte
	}
	claimDone, maintenanceDone := make(chan result, 1), make(chan result, 1)
	go func() {
		rr := recordAPI(h, "POST", "/api/tasks/claim", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "s1", "request_id": "race", "types": []string{"port"}, "supports_confirmed_stop": true})
		claimDone <- result{rr.Code, rr.Body.Bytes()}
	}()
	go func() {
		rr := recordAPI(h, "POST", "/api/workers/"+worker.ID+"/maintenance", "admin-policy", map[string]any{"enabled": true})
		maintenanceDone <- result{rr.Code, rr.Body.Bytes()}
	}()
	// Verify both actual handlers reached the shared lock before releasing it.
	for {
		var waiting int
		if err = s.db.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid=$1::oid AND objid=hashtext($2)::bigint & 4294967295`, workerClaimLockNamespace, worker.ID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 2 {
			break
		}
		select {
		case got := <-claimDone:
			t.Fatalf("claim bypassed worker lock: %+v", got)
		case got := <-maintenanceDone:
			t.Fatalf("maintenance bypassed worker lock: %+v", got)
		case <-ctx.Done():
			t.Fatal("handlers did not wait on the shared worker lock")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = guard.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	claim, maintenance := <-claimDone, <-maintenanceDone
	if claim.status != http.StatusOK || maintenance.status != http.StatusOK {
		t.Fatalf("claim %d %s; maintenance %d %s", claim.status, claim.body, maintenance.status, maintenance.body)
	}
	var claimed struct{ Task *Task }
	var maintained struct {
		Active int `json:"active_tasks"`
	}
	if err = json.Unmarshal(claim.body, &claimed); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(maintenance.body, &maintained); err != nil {
		t.Fatal(err)
	}
	expected := 0
	if claimed.Task != nil {
		expected = 1
	}
	if maintained.Active != expected {
		t.Fatalf("maintenance reported %d active tasks while concurrent claim returned %v", maintained.Active, claimed.Task)
	}
}
