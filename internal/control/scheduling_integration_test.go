package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"scanplatform/internal/webevidence"
)

func TestPostgresSchedulingInvariants(t *testing.T) {
	databaseURL := os.Getenv("CONTROL_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTROL_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	adminDB, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := "control_test_" + strings.ReplaceAll(newID(), "-", "")
	if _, err := adminDB.Exec(ctx, `CREATE SCHEMA `+schemaName); err != nil {
		adminDB.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schemaName)
	u.RawQuery = query.Encode()
	server, err := New(ctx, u.String(), "admin-test", "join-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		_, _ = adminDB.Exec(context.Background(), `DROP SCHEMA `+schemaName+` CASCADE`)
		adminDB.Close()
	})
	if _, err := server.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	var portRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-test", map[string]any{
		"name": "port slot", "targets": []string{"192.0.2.11", "192.0.2.12"}, "modes": []string{"port", "http"},
	}, http.StatusCreated, &portRun)
	var registered struct {
		WorkerID    string `json:"worker_id"`
		WorkerToken string `json:"worker_token"`
	}
	callAPI(t, handler, http.MethodPost, "/api/workers/register", "join-test", map[string]any{
		"instance_id": "integration-worker", "hostname": "local", "agent_version": "test", "session_id": "session-1", "spec": map[string]any{},
	}, http.StatusOK, &registered)
	claimBody := func(requestID string, types []string) map[string]any {
		return map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": requestID, "types": types,
			"service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile, "fingerprint_bundle": webevidence.FingerprintBundle}
	}
	// Logical cancellation does not prove a fixture executor has stopped. Model
	// that acknowledgement before reusing this worker for the next scenario.
	confirmCancelledStopped := func(runID string) {
		t.Helper()
		rows, err := server.db.Query(ctx, `SELECT id,attempt_no FROM tasks WHERE run_id=$1 AND state='cancelled' AND worker_id=$2 AND session_id='session-1'`, runID, registered.WorkerID)
		if err != nil {
			t.Fatal(err)
		}
		type execution struct {
			id      string
			attempt int
		}
		var executions []execution
		for rows.Next() {
			var v execution
			if err := rows.Scan(&v.id, &v.attempt); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			executions = append(executions, v)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		for _, v := range executions {
			callAPI(t, handler, http.MethodPost, "/api/tasks/"+v.id+"/release", registered.WorkerToken,
				map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": v.attempt, "stopped": true, "reason": "fixture executor exited"}, http.StatusOK, nil)
		}
	}
	var firstClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken, claimBody("port-1", []string{"port"}), http.StatusOK, &firstClaim)
	if firstClaim.Task == nil || firstClaim.Task.Type != "port" {
		t.Fatalf("first port claim = %#v", firstClaim.Task)
	}
	var secondClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken, claimBody("port-2", []string{"port"}), http.StatusOK, &secondClaim)
	if secondClaim.Task != nil {
		t.Fatalf("second concurrent port claim must be empty: %#v", secondClaim.Task)
	}
	var replay struct {
		Task    *Task `json:"task"`
		Expired bool  `json:"expired"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken, claimBody("port-1", []string{"port"}), http.StatusOK, &replay)
	if replay.Task == nil || replay.Task.ID != firstClaim.Task.ID || !replay.Task.ServerTime.After(firstClaim.Task.ServerTime) {
		t.Fatalf("valid replay must keep identity and refresh server_time: %#v", replay)
	}
	portTargets := taskTargetKeys(firstClaim.Task.Payload)
	if len(portTargets) == 0 {
		t.Fatal("port task has no target keys")
	}
	items := make([]Observation, 0, 1025+len(portTargets)-1)
	for port := 1; port <= 1025; port++ {
		items = append(items, Observation{Kind: "port", Target: portTargets[0], IP: portTargets[0], Port: port, Protocol: "tcp"})
	}
	for _, target := range portTargets[1:] {
		items = append(items, Observation{Kind: "port", Target: target, IP: target, Port: 443, Protocol: "tcp"})
	}
	batch := map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": firstClaim.Task.AttemptNo, "batch_seq": 0, "items": items}
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+firstClaim.Task.ID+"/batches", registered.WorkerToken, batch, http.StatusOK, nil)
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+firstClaim.Task.ID+"/batches", registered.WorkerToken, batch, http.StatusOK, nil)
	conflict := map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": firstClaim.Task.AttemptNo, "batch_seq": 0,
		"items": []Observation{{Kind: "port", Target: portTargets[0], IP: portTargets[0], Port: 8080, Protocol: "tcp"}}}
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+firstClaim.Task.ID+"/batches", registered.WorkerToken, conflict, http.StatusConflict, nil)
	foreign := map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": firstClaim.Task.AttemptNo, "batch_seq": 1,
		"items": []Observation{{Kind: "port", Target: "192.0.2.99", IP: "192.0.2.99", Port: 80, Protocol: "tcp"}}}
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+firstClaim.Task.ID+"/batches", registered.WorkerToken, foreign, http.StatusUnprocessableEntity, nil)
	var assetCount, targetCount int
	if err := server.db.QueryRow(ctx, `SELECT count(*),count(DISTINCT target_key) FROM assets WHERE task_id=$1`, firstClaim.Task.ID).Scan(&assetCount, &targetCount); err != nil {
		t.Fatal(err)
	}
	if assetCount != len(items) || targetCount != len(portTargets) {
		t.Fatalf("copied assets=%d targets=%d, want %d/%d", assetCount, targetCount, len(items), len(portTargets))
	}
	identity := map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": firstClaim.Task.AttemptNo, "last_batch_seq": 0}
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+firstClaim.Task.ID+"/complete", registered.WorkerToken, identity, http.StatusOK, nil)
	for index, target := range portTargets {
		wantService, wantHTTP, wantPorts := 1, 0, 1
		if index == 0 {
			wantService, wantHTTP, wantPorts = 32, 0, 1025
		}
		var serviceTasks, httpTasks int
		if err := server.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE type='service'),count(*) FILTER (WHERE type='http')
			FROM tasks WHERE run_id=$1 AND target_key=$2 AND id<>$3`, portRun.ID, target, firstClaim.Task.ID).Scan(&serviceTasks, &httpTasks); err != nil {
			t.Fatal(err)
		}
		if serviceTasks != wantService || httpTasks != wantHTTP {
			t.Fatalf("derived %s service/http=%d/%d, want %d/%d", target, serviceTasks, httpTasks, wantService, wantHTTP)
		}
		var invalidPayloads int
		if err := server.db.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE run_id=$1 AND target_key=$2 AND id<>$3 AND
			((type='service' AND (jsonb_array_length(payload->'endpoints')>32 OR (payload->>'timeout_seconds')::int<>60 OR payload->>'service_profile'<>'nmap-light-v1')) OR
		 (type='http' AND (jsonb_array_length(payload->'endpoints')<>1 OR (payload->>'timeout_seconds')::int<>8)) OR
			 (payload->>'execution_timeout_seconds')::int<>90 OR payload->'endpoints'->0->>'ip'<>target_key)`,
			portRun.ID, target, firstClaim.Task.ID).Scan(&invalidPayloads); err != nil {
			t.Fatal(err)
		}
		if invalidPayloads != 0 {
			t.Fatalf("derived payload invariant failures for %s: %d", target, invalidPayloads)
		}
		var selectedEndpoints, distinctEndpoints int
		var allSameIP bool
		if err := server.db.QueryRow(ctx, `SELECT count(*),count(DISTINCT (e->>'ip',e->>'port')),bool_and(e->>'ip'=$2)
            FROM tasks t CROSS JOIN LATERAL jsonb_array_elements(t.payload->'endpoints') e
            WHERE t.run_id=$1 AND t.target_key=$2 AND t.type='service'`, portRun.ID, target).Scan(&selectedEndpoints, &distinctEndpoints, &allSameIP); err != nil {
			t.Fatal(err)
		}
		if selectedEndpoints != min(wantPorts, 1024) || distinctEndpoints != selectedEndpoints || !allSameIP {
			t.Fatalf("service batches lost, duplicated or mixed endpoints for %s: %d/%d same_ip=%v", target, selectedEndpoints, distinctEndpoints, allSameIP)
		}
		var openFlood bool
		var openPortCount, fingerprintCount int
		if err := server.db.QueryRow(ctx, `SELECT open_flood,open_port_count,fingerprint_count FROM run_target_policies WHERE run_id=$1 AND target_key=$2`,
			portRun.ID, target).Scan(&openFlood, &openPortCount, &fingerprintCount); err != nil {
			t.Fatal(err)
		}
		if openPortCount != wantPorts || fingerprintCount != min(wantPorts, 1024) || openFlood != (index == 0) {
			t.Fatalf("open flood policy for %s = %t/%d/%d", target, openFlood, openPortCount, fingerprintCount)
		}
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken, claimBody("port-1", []string{"port"}), http.StatusOK, &replay)
	if replay.Task != nil || !replay.Expired {
		t.Fatalf("completed claim replay must expire: %#v", replay)
	}
	callAPI(t, handler, http.MethodPost, "/api/runs/"+portRun.ID+"/cancel", "admin-test", nil, http.StatusOK, nil)
	confirmCancelledStopped(portRun.ID)

	bigRunID, smallRunID := newID(), newID()
	if _, err := server.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,created_at) VALUES
		($1,'large backlog','["198.51.100.1","198.51.100.2"]','{port}','pending','2020-01-01'),
		($2,'small run','["198.51.100.10"]','{port}','pending','2021-01-01')`, bigRunID, smallRunID); err != nil {
		t.Fatal(err)
	}
	for index, seed := range []struct{ runID, target string }{
		{bigRunID, "198.51.100.1"}, {bigRunID, "198.51.100.1"}, {bigRunID, "198.51.100.2"}, {smallRunID, "198.51.100.10"},
	} {
		payload, _ := json.Marshal(map[string]any{"endpoints": []map[string]any{{"ip": seed.target, "port": 80}}, "timeout_seconds": 60, "execution_timeout_seconds": 90, "service_profile": "nmap-light-v1"})
		if _, err := server.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES($1,$2,'service',$3,$4,$5)`,
			newID(), seed.runID, payload, "fair:"+string(rune('a'+index)), seed.target); err != nil {
			t.Fatal(err)
		}
	}
	var fairClaims [2]struct {
		Task *Task `json:"task"`
	}
	for index := range fairClaims {
		callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
			claimBody("fair-"+string(rune('1'+index)), []string{"service"}), http.StatusOK, &fairClaims[index])
	}
	if fairClaims[0].Task == nil || fairClaims[0].Task.RunID != bigRunID || fairClaims[1].Task == nil || fairClaims[1].Task.RunID != smallRunID {
		t.Fatalf("run fairness did not rotate to small run: %#v", fairClaims)
	}
	callAPI(t, handler, http.MethodPost, "/api/runs/"+bigRunID+"/cancel", "admin-test", nil, http.StatusOK, nil)
	confirmCancelledStopped(bigRunID)
	callAPI(t, handler, http.MethodPost, "/api/runs/"+smallRunID+"/cancel", "admin-test", nil, http.StatusOK, nil)
	confirmCancelledStopped(smallRunID)
	expiredRunID, expiredTaskID, queuedTaskID := newID(), newID(), newID()
	if _, err := server.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,last_claim_target_key)
		VALUES($1,'retry priority','["198.51.100.10","198.51.100.20","198.51.100.30"]','{port}','running','198.51.100.25')`, expiredRunID); err != nil {
		t.Fatal(err)
	}
	expiredPayload, _ := json.Marshal(map[string]any{"endpoints": []map[string]any{{"ip": "198.51.100.20", "port": 80}}, "timeout_seconds": 60, "execution_timeout_seconds": 90, "service_profile": "nmap-light-v1"})
	queuedPayload, _ := json.Marshal(map[string]any{"endpoints": []map[string]any{{"ip": "198.51.100.30", "port": 80}}, "timeout_seconds": 60, "execution_timeout_seconds": 90, "service_profile": "nmap-light-v1"})
	if _, err := server.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,state,attempt_no,worker_id,session_id,lease_until,derived_key,target_key) VALUES
		($1,$2,'service',$3,'leased',1,$4,'session-1',now()-interval '1 minute','expired','198.51.100.20'),
		($5,$2,'service',$6,'queued',0,NULL,NULL,NULL,'queued','198.51.100.30')`, expiredTaskID, expiredRunID, expiredPayload,
		registered.WorkerID, queuedTaskID, queuedPayload); err != nil {
		t.Fatal(err)
	}
	// Lease expiry fences results but does not prove the old network process
	// stopped. Keep its quota frozen until this fixture supplies stop evidence.
	if _, err := server.db.Exec(ctx, `INSERT INTO target_quotas(epoch,task_id,attempt_no,worker_id,instance_id,session_id,scope,dimension,amount,state,valid_until)
        SELECT $1,$2,1,id,instance_id,'session-1','198.51.100.20','service_jobs',1,'active',now()-interval '1 minute' FROM workers WHERE id=$3`, newID(), expiredTaskID, registered.WorkerID); err != nil {
		t.Fatal(err)
	}
	var frozenClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
		claimBody("expired-unconfirmed-stop", []string{"service"}), http.StatusOK, &frozenClaim)
	if frozenClaim.Task != nil {
		t.Fatalf("expired quota was recycled without stop evidence: %+v", frozenClaim.Task)
	}
	if err := server.ConfirmWorkerStopped(ctx, "integration-worker", "session-1", "fixture expired executor exit confirmed"); err != nil {
		t.Fatal(err)
	}
	var expiredClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
		claimBody("expired-before-cursor", []string{"service"}), http.StatusOK, &expiredClaim)
	if expiredClaim.Task == nil || expiredClaim.Task.ID != expiredTaskID || expiredClaim.Task.AttemptNo != 2 {
		t.Fatalf("expired lease was not reclaimed before queued task %s: %#v", queuedTaskID, expiredClaim.Task)
	}
	retryTaskID := newID()
	retryPayload, _ := json.Marshal(map[string]any{"endpoints": []map[string]any{{"ip": "198.51.100.10", "port": 80}}, "timeout_seconds": 60, "execution_timeout_seconds": 90, "service_profile": "nmap-light-v1"})
	if _, err := server.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,state,attempt_no,derived_key,target_key)
		VALUES($1,$2,'service',$3,'queued',1,'released-retry','198.51.100.10')`, retryTaskID, expiredRunID, retryPayload); err != nil {
		t.Fatal(err)
	}
	var retryClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
		claimBody("released-retry-before-cursor", []string{"service"}), http.StatusOK, &retryClaim)
	if retryClaim.Task == nil || retryClaim.Task.ID != retryTaskID || retryClaim.Task.AttemptNo != 2 {
		t.Fatalf("queued retry was not reclaimed before queued task %s: %#v", queuedTaskID, retryClaim.Task)
	}
	callAPI(t, handler, http.MethodPost, "/api/runs/"+expiredRunID+"/cancel", "admin-test", nil, http.StatusOK, nil)
	confirmCancelledStopped(expiredRunID)
	var raceRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-test", map[string]any{
		"name": "claim cancel race", "targets": []string{"https://race.example.com/"}, "modes": []string{"http"},
	}, http.StatusCreated, &raceRun)
	type concurrentResult struct {
		operation string
		response  *httptest.ResponseRecorder
	}
	start := make(chan struct{})
	results := make(chan concurrentResult, 2)
	go func() {
		<-start
		results <- concurrentResult{"claim", recordAPI(handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
			claimBody("claim-cancel-race", []string{"http"}))}
	}()
	go func() {
		<-start
		results <- concurrentResult{"cancel", recordAPI(handler, http.MethodPost, "/api/runs/"+raceRun.ID+"/cancel", "admin-test", nil)}
	}()
	close(start)
	for range 2 {
		result := <-results
		if result.response.Code != http.StatusOK {
			t.Fatalf("concurrent %s failed: status=%d body=%s", result.operation, result.response.Code, result.response.Body.String())
		}
	}
	var raceOpen int
	if err := server.db.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE run_id=$1 AND state IN ('queued','leased')`, raceRun.ID).Scan(&raceOpen); err != nil {
		t.Fatal(err)
	}
	if raceOpen != 0 {
		t.Fatalf("cancel left %d claimable tasks", raceOpen)
	}
	confirmCancelledStopped(raceRun.ID)
	var poolRaceRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-test", map[string]any{
		"name": "claim pool stop race", "targets": []string{"https://pool-race.example.com/"}, "modes": []string{"http"},
	}, http.StatusCreated, &poolRaceRun)
	poolResults := make(chan concurrentResult, 2)
	poolStart := make(chan struct{})
	go func() {
		<-poolStart
		poolResults <- concurrentResult{"claim", recordAPI(handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
			claimBody("claim-pool-race", []string{"http"}))}
	}()
	go func() {
		<-poolStart
		poolResults <- concurrentResult{"pool stop", recordAPI(handler, http.MethodPatch, "/api/worker-pool", "admin-test",
			map[string]any{"desired_workers": 0, "enabled": false, "expected_generation": 1})}
	}()
	close(poolStart)
	var racedClaim struct {
		Task *Task `json:"task"`
	}
	for range 2 {
		result := <-poolResults
		if result.response.Code != http.StatusOK {
			t.Fatalf("concurrent %s failed: status=%d body=%s", result.operation, result.response.Code, result.response.Body.String())
		}
		if result.operation == "claim" && json.Unmarshal(result.response.Body.Bytes(), &racedClaim) != nil {
			t.Fatalf("claim returned invalid JSON: %s", result.response.Body.String())
		}
	}
	if racedClaim.Task != nil {
		var renewal struct {
			Action string `json:"action"`
		}
		callAPI(t, handler, http.MethodPost, "/api/tasks/"+racedClaim.Task.ID+"/renew", registered.WorkerToken,
			map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": racedClaim.Task.AttemptNo}, http.StatusOK, &renewal)
		if renewal.Action != "stop" {
			t.Fatalf("pool stop did not revoke raced claim: %#v", renewal)
		}
	}
	var stoppedClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
		claimBody("claim-after-pool-stop", []string{"http"}), http.StatusOK, &stoppedClaim)
	if stoppedClaim.Task != nil {
		t.Fatalf("disabled pool issued task: %#v", stoppedClaim.Task)
	}
	callAPI(t, handler, http.MethodPost, "/api/runs/"+poolRaceRun.ID+"/cancel", "admin-test", nil, http.StatusOK, nil)
	confirmCancelledStopped(poolRaceRun.ID)
	if _, err := server.db.Exec(ctx, `UPDATE worker_pool SET enabled=true,generation=generation+1`); err != nil {
		t.Fatal(err)
	}
	var receiptRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-test", map[string]any{
		"name": "old attempt receipt", "targets": []string{"https://receipt.example.com/"}, "modes": []string{"http"},
	}, http.StatusCreated, &receiptRun)
	var receiptAttempt1 struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
		claimBody("receipt-attempt-1", []string{"http"}), http.StatusOK, &receiptAttempt1)
	if receiptAttempt1.Task == nil {
		t.Fatal("expected receipt test task")
	}
	receiptItems := []Observation{controlHTTPFixture(Observation{Kind: "http", Target: "https://receipt.example.com", URL: "https://receipt.example.com/", StatusCode: 200})}
	receiptBatch := map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": receiptAttempt1.Task.AttemptNo,
		"batch_seq": 0, "items": receiptItems}
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+receiptAttempt1.Task.ID+"/batches", registered.WorkerToken, receiptBatch, http.StatusOK, nil)
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+receiptAttempt1.Task.ID+"/release", registered.WorkerToken,
		map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": receiptAttempt1.Task.AttemptNo,
			"reason": "retry receipt", "retryable": true, "stopped": true}, http.StatusOK, nil)
	var receiptAttempt2 struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
		claimBody("receipt-attempt-2", []string{"http"}), http.StatusOK, &receiptAttempt2)
	if receiptAttempt2.Task == nil || receiptAttempt2.Task.ID != receiptAttempt1.Task.ID || receiptAttempt2.Task.AttemptNo != receiptAttempt1.Task.AttemptNo+1 {
		t.Fatalf("task was not reclaimed with a new attempt: %#v", receiptAttempt2.Task)
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+receiptAttempt1.Task.ID+"/batches", registered.WorkerToken, receiptBatch, http.StatusOK, nil)
	receiptBatch["batch_seq"] = 1
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+receiptAttempt1.Task.ID+"/batches", registered.WorkerToken, receiptBatch, http.StatusConflict, nil)
	var accepted struct {
		Total int     `json:"total"`
		Items []Asset `json:"items"`
	}
	callAPI(t, handler, http.MethodGet, "/api/assets?run_id="+receiptRun.ID, "admin-test", nil, http.StatusOK, &accepted)
	if accepted.Total != 0 {
		t.Fatal("unsealed receipt attempt appeared in accepted result view")
	}
	currentBatch := map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": receiptAttempt2.Task.AttemptNo, "batch_seq": 0,
		"items": []Observation{controlHTTPFixture(Observation{Kind: "http", Target: "https://receipt.example.com/", URL: "https://receipt.example.com/", StatusCode: 201, Coverage: "complete", Outcome: "identified"})}}
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+receiptAttempt2.Task.ID+"/batches", registered.WorkerToken, currentBatch, http.StatusOK, nil)
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+receiptAttempt2.Task.ID+"/complete", registered.WorkerToken,
		map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": receiptAttempt2.Task.AttemptNo, "last_batch_seq": 0}, http.StatusOK, nil)
	callAPI(t, handler, http.MethodGet, "/api/assets?run_id="+receiptRun.ID, "admin-test", nil, http.StatusOK, &accepted)
	if accepted.Total != 1 || len(accepted.Items) != 1 || accepted.Items[0].Observation.StatusCode != 201 {
		t.Fatalf("accepted view mixed old attempt: %+v", accepted)
	}
	callAPI(t, handler, http.MethodPost, "/api/runs/"+receiptRun.ID+"/cancel", "admin-test", nil, http.StatusOK, nil)
	confirmCancelledStopped(receiptRun.ID)
	var timeoutRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-test", map[string]any{
		"name": "execution timeout budget", "targets": []string{"https://timeout.example.com/"}, "modes": []string{"http"},
	}, http.StatusCreated, &timeoutRun)
	timeoutClasses := []string{"execution_timeout", "", "execution_timeout", "execution_timeout"}
	wantFailures := []int{1, 1, 2, 3}
	for index, failureClass := range timeoutClasses {
		var claim struct {
			Task *Task `json:"task"`
		}
		callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
			claimBody("timeout-budget-"+string(rune('1'+index)), []string{"http"}), http.StatusOK, &claim)
		if claim.Task == nil || claim.Task.RunID != timeoutRun.ID {
			t.Fatalf("timeout attempt %d claim=%#v", index+1, claim.Task)
		}
		release := map[string]any{"worker_id": registered.WorkerID, "session_id": "session-1", "attempt_no": claim.Task.AttemptNo,
			"reason": "fixture execution deadline exceeded", "retryable": true, "stopped": true}
		if failureClass != "" {
			release["failure_class"] = failureClass
		}
		callAPI(t, handler, http.MethodPost, "/api/tasks/"+claim.Task.ID+"/release", registered.WorkerToken, release, http.StatusOK, nil)
		var state string
		var failures int
		if err := server.db.QueryRow(ctx, `SELECT state,execution_failures FROM tasks WHERE id=$1`, claim.Task.ID).Scan(&state, &failures); err != nil {
			t.Fatal(err)
		}
		wantState := "queued"
		if index == len(timeoutClasses)-1 {
			wantState = "failed"
		}
		if state != wantState || failures != wantFailures[index] {
			t.Fatalf("timeout release %d state/failures=%s/%d, want %s/%d", index+1, state, failures, wantState, wantFailures[index])
		}
	}
	callAPI(t, handler, http.MethodGet, "/api/runs/"+timeoutRun.ID, "admin-test", nil, http.StatusOK, &timeoutRun)
	if timeoutRun.Status != "failed" || timeoutRun.Error == "" {
		t.Fatalf("timeout budget run status=%s", timeoutRun.Status)
	}

	var httpRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-test", map[string]any{
		"name": "precise stop", "targets": []string{"https://one.example.com/", "https://two.example.com/"}, "modes": []string{"http"},
	}, http.StatusCreated, &httpRun)
	var httpClaims [2]struct {
		Task *Task `json:"task"`
	}
	for index := range httpClaims {
		callAPI(t, handler, http.MethodPost, "/api/tasks/claim", registered.WorkerToken,
			claimBody("http-"+string(rune('1'+index)), []string{"http"}), http.StatusOK, &httpClaims[index])
		if httpClaims[index].Task == nil {
			t.Fatal("expected HTTP task")
		}
	}
	callAPI(t, handler, http.MethodPost, "/api/runs/"+httpRun.ID+"/cancel", "admin-test", nil, http.StatusOK, nil)
	var heartbeat struct {
		Action      string   `json:"action"`
		StopTaskIDs []string `json:"stop_task_ids"`
	}
	callAPI(t, handler, http.MethodPost, "/api/workers/heartbeat", registered.WorkerToken, map[string]any{
		"worker_id": registered.WorkerID, "session_id": "session-1", "current_task_id": httpClaims[0].Task.ID, "status": "running",
		"metrics": map[string]any{"active_tasks": 2, "cpu_percent": 17.5, "mem_total_mib": 2048},
	}, http.StatusOK, &heartbeat)
	if heartbeat.Action != "continue" || !contains(heartbeat.StopTaskIDs, httpClaims[0].Task.ID) || !contains(heartbeat.StopTaskIDs, httpClaims[1].Task.ID) {
		t.Fatalf("heartbeat must stop only cancelled tasks: %#v", heartbeat)
	}
	confirmCancelledStopped(httpRun.ID)
	var workers struct {
		Items []Worker `json:"items"`
	}
	callAPI(t, handler, http.MethodGet, "/api/workers", "admin-test", nil, http.StatusOK, &workers)
	if len(workers.Items) != 1 || workers.Items[0].Metrics["cpu_percent"] != 17.5 {
		t.Fatalf("worker metrics were not persisted: %#v", workers.Items)
	}
	t.Run("large cancel response over closing TLS connection", func(t *testing.T) {
		targets := make([]string, 1000)
		for i := range targets {
			targets[i] = fmt.Sprintf("host%04d.example.test", i)
		}
		var large Run
		callAPI(t, handler, http.MethodPost, "/api/runs", "admin-test", map[string]any{
			"name": "large cancellation", "targets": targets, "modes": []string{"http"},
		}, http.StatusCreated, &large)
		tlsServer := httptest.NewTLSServer(handler)
		defer tlsServer.Close()
		request, _ := http.NewRequest(http.MethodPost, tlsServer.URL+"/api/runs/"+large.ID+"/cancel", strings.NewReader("{}"))
		request.Header.Set("Authorization", "Bearer admin-test")
		request.Close = true
		response, err := tlsServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("truncated cancellation response: %v", err)
		}
		if err := json.Unmarshal(data, &large); err != nil || response.StatusCode != http.StatusOK || large.Status != "cancelled" || len(large.Targets) != 1000 {
			t.Fatalf("incomplete cancellation: status=%d, targets=%d, error=%v", response.StatusCode, len(large.Targets), err)
		}
	})
}

func callAPI(t *testing.T, handler http.Handler, method, path, token string, body any, status int, output any) {
	t.Helper()
	response := recordAPI(handler, method, path, token, body)
	if response.Code != status {
		t.Fatalf("%s %s: got %d body=%s", method, path, response.Code, response.Body.String())
	}
	if output != nil && json.Unmarshal(response.Body.Bytes(), output) != nil {
		t.Fatalf("%s %s returned invalid JSON: %s", method, path, response.Body.String())
	}
}

func recordAPI(handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
