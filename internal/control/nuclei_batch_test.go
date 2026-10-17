package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"testing"

	"scanplatform/internal/rulelib"
)

func controlBatchRule(t *testing.T, id string) rulelib.Rule {
	t.Helper()
	rule, err := rulelib.ParseNucleiOriginal(fmt.Sprintf("id: %s\ninfo:\n  name: %s\n  author: shen\n  severity: info\n  metadata:\n    product: ShenBatchFixture\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/health\"]\n    matchers:\n      - type: status\n        status: [200]\n", id, id))
	if err != nil {
		t.Fatal(err)
	}
	rule.Enabled = true
	return rule
}

func TestPostgresNucleiBatchReceiptsResumeVisibility(t *testing.T) {
	server, baseHandler := newPolicyTestServer(t, "nuclei_batch")
	ctx := context.Background()
	var evidence bytes.Buffer
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, true)
		recorder := httptest.NewRecorder()
		baseHandler.ServeHTTP(recorder, r)
		responseDump, _ := httputil.DumpResponse(recorder.Result(), true)
		fmt.Fprintf(&evidence, "\n```http\n%s\n%s\n```\n", dump, responseDump)
		for k, values := range recorder.Header() {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	})
	if path := os.Getenv("CONTROL_NUCLEI_BATCH_EVIDENCE"); path != "" {
		t.Cleanup(func() {
			if err := os.WriteFile(path, evidence.Bytes(), 0600); err != nil {
				t.Error(err)
			}
		})
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := server.db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE worker_pool SET enabled=true`)
	exec(`INSERT INTO runs(id,name,targets,modes,status,poc_enabled) VALUES('batch-run','batch','["192.0.2.1"]','{http}','pending',true)`)
	rules := []rulelib.Rule{controlBatchRule(t, "receipt-a"), controlBatchRule(t, "receipt-b"), controlBatchRule(t, "receipt-c")}
	payload, _ := json.Marshal(map[string]any{"endpoint": taskEndpoint{IP: "192.0.2.1", URL: "http://192.0.2.1:8080/"}, "rules": rules, "nuclei_batch_profile": rulelib.NucleiSingleResponseBatchProfile})
	exec(`INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES('batch-task','batch-run','poc',$1,'batch-task','192.0.2.1')`, payload)
	exec(`INSERT INTO task_targets(task_id,target_key) VALUES('batch-task','192.0.2.1')`)
	var worker struct {
		WorkerID    string `json:"worker_id"`
		WorkerToken string `json:"worker_token"`
	}
	callAPI(t, handler, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "batch-worker", "hostname": "local", "agent_version": "test", "session_id": "s1", "spec": map[string]any{}}, 200, &worker)
	claim := map[string]any{"worker_id": worker.WorkerID, "session_id": "s1", "request_id": "no-batch", "types": []string{"poc"}, "supports_confirmed_stop": true, "supports_http_request_budget": true, "supports_nuclei_http_original": true}
	var claimed struct {
		Task    *Task `json:"task"`
		Expired bool  `json:"expired"`
	}
	callAPI(t, handler, "POST", "/api/tasks/claim", worker.WorkerToken, claim, 200, &claimed)
	if claimed.Task != nil {
		t.Fatal("old single-template agent claimed a batch")
	}
	claim["supports_nuclei_http_batch"] = true
	claim["request_id"] = "batch-1"
	callAPI(t, handler, "POST", "/api/tasks/claim", worker.WorkerToken, claim, 200, &claimed)
	if claimed.Task == nil {
		t.Fatal("capable agent did not claim batch")
	}
	first := *claimed.Task
	obs := func(index int, status string) Observation {
		r := rules[index]
		return Observation{Kind: "poc", Target: "192.0.2.1", IP: "192.0.2.1", Port: 8080, Protocol: "http", URL: "http://192.0.2.1:8080/health", RuleID: r.ID, RuleName: r.Name, RuleRevision: r.Revision, Engine: r.Engine, Severity: r.Severity, TemplateID: r.Nuclei.TemplateID, ContentSHA256: r.Nuclei.ContentSHA256, ExecutionProfile: r.Nuclei.ExecutionProfile, EngineVersion: "3.11.1", EvidenceProfile: "nuclei-3.11.1-single-http-response-v1", FindingStatus: status, CanProveNoMatch: status == "not_matched", RequestRaw: "GET /health HTTP/1.1\r\nHost: 192.0.2.1:8080\r\n\r\n", ResponseRaw: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Evidence: "local fixture"}
	}
	batch := func(attempt, seq int, items []Observation, want int) {
		callAPI(t, handler, "POST", "/api/tasks/batch-task/batches", worker.WorkerToken, map[string]any{"worker_id": worker.WorkerID, "session_id": "s1", "attempt_no": attempt, "batch_seq": seq, "items": items}, want, nil)
	}
	batch(first.AttemptNo, 0, []Observation{obs(0, "matched")}, 200)
	// Same committed batch is idempotent; changed/new bytes cannot replace receipt.
	batch(first.AttemptNo, 0, []Observation{obs(0, "matched")}, 200)
	batch(first.AttemptNo, 1, []Observation{obs(0, "not_matched")}, 422)
	incomplete := obs(1, "not_matched")
	incomplete.ResponseRaw = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort"
	batch(first.AttemptNo, 1, []Observation{incomplete}, 200)
	var receiptCount int
	if err := server.db.QueryRow(ctx, `SELECT count(*) FROM poc_template_receipts WHERE task_id='batch-task'`).Scan(&receiptCount); err != nil || receiptCount != 1 {
		t.Fatalf("incomplete negative accepted: %d %v", receiptCount, err)
	}
	var findings struct {
		Total int           `json:"total"`
		Items []Observation `json:"items"`
	}
	callAPI(t, handler, "GET", "/api/runs/batch-run/findings", "admin-policy", nil, 200, &findings)
	if findings.Total != 1 || findings.Items[0].RuleID != rules[0].ID {
		t.Fatalf("live receipt invisible: %+v", findings)
	}
	identity := map[string]any{"worker_id": worker.WorkerID, "session_id": "s1", "attempt_no": first.AttemptNo, "last_batch_seq": 1}
	callAPI(t, handler, "POST", "/api/tasks/batch-task/complete", worker.WorkerToken, identity, 422, nil)
	callAPI(t, handler, "POST", "/api/tasks/batch-task/release", worker.WorkerToken, map[string]any{"worker_id": worker.WorkerID, "session_id": "s1", "attempt_no": first.AttemptNo, "retryable": true, "stopped": true, "reason": "local process cancelled after first terminal template"}, 200, nil)
	claim["request_id"] = "batch-2"
	claimed.Task = nil
	callAPI(t, handler, "POST", "/api/tasks/claim", worker.WorkerToken, claim, 200, &claimed)
	if claimed.Task == nil || claimed.Task.AttemptNo != first.AttemptNo+1 {
		t.Fatalf("no retry: %+v", claimed)
	}
	var resumed pocBatchPayload
	if err := json.Unmarshal(claimed.Task.Payload, &resumed); err != nil || len(resumed.Rules) != 2 {
		t.Fatalf("bad resumed manifest: %s %v", claimed.Task.Payload, err)
	}
	for _, r := range resumed.Rules {
		if r.ID == rules[0].ID {
			t.Fatal("accepted template was dispatched again")
		}
	}
	second := *claimed.Task
	// Receipts stay visible despite a new attempt; stale extra data is fenced.
	batch(first.AttemptNo, 2, []Observation{obs(2, "matched")}, 409)
	batch(second.AttemptNo, 0, []Observation{obs(1, "not_matched"), obs(2, "matched")}, 200)
	// A stop after the last receipt but before job completion must return a
	// zero-template manifest and seal without rescanning any accepted template.
	callAPI(t, handler, "POST", "/api/tasks/batch-task/release", worker.WorkerToken, map[string]any{"worker_id": worker.WorkerID, "session_id": "s1", "attempt_no": second.AttemptNo, "retryable": true, "stopped": true, "reason": "stop after all individual receipts"}, 200, nil)
	claim["request_id"] = "batch-3"
	claimed.Task = nil
	callAPI(t, handler, "POST", "/api/tasks/claim", worker.WorkerToken, claim, 200, &claimed)
	if claimed.Task == nil {
		t.Fatal("missing final receipt-only claim")
	}
	resumed = pocBatchPayload{}
	if err := json.Unmarshal(claimed.Task.Payload, &resumed); err != nil || len(resumed.Rules) != 0 {
		t.Fatalf("all accepted templates dispatched again: %s", claimed.Task.Payload)
	}
	identity["attempt_no"] = claimed.Task.AttemptNo
	identity["last_batch_seq"] = -1
	callAPI(t, handler, "POST", "/api/tasks/batch-task/complete", worker.WorkerToken, identity, 200, nil)
	findings.Total = 0
	callAPI(t, handler, "GET", "/api/runs/batch-run/findings", "admin-policy", nil, 200, &findings)
	if findings.Total != 3 {
		t.Fatalf("accepted template attempts lost/duplicated: %+v", findings)
	}
	var firstSource, count int
	if err := server.db.QueryRow(ctx, `SELECT count(*),min(source_attempt_no) FILTER(WHERE rule_id=$1) FROM poc_template_receipts WHERE task_id='batch-task'`, rules[0].ID).Scan(&count, &firstSource); err != nil || count != 3 || firstSource != 1 {
		t.Fatalf("receipt changed: %d %d %v", count, firstSource, err)
	}
	var items, manifest int
	if err := server.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM task_item_completions WHERE task_id='batch-task'),jsonb_array_length(completion_manifest) FROM tasks WHERE id='batch-task'`).Scan(&items, &manifest); err != nil || items != 3 || manifest != 3 {
		t.Fatalf("completion snapshot omitted individual receipts: items=%d manifest=%d err=%v", items, manifest, err)
	}
	t.Log("PASS: capability gate; live immutable receipt; truncated negative not accepted; missing-template completion rejected; cancel/release/reclaim excludes accepted template; final visibility retains three templates across accepted attempts, including zero-template final seal")
}

func TestPostgresNucleiBatchGroupingKeepsEndpointAndDerivedIdentity(t *testing.T) {
	server, _ := newPolicyTestServer(t, "nuclei_group")
	ctx := context.Background()
	if _, err := server.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status) VALUES('group-run','groups','["192.0.2.1"]','{http}','pending')`); err != nil {
		t.Fatal(err)
	}
	tx, err := server.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var rules []rulelib.Rule
	for index := 0; index < 7; index++ {
		rules = append(rules, controlBatchRule(t, fmt.Sprintf("group-%d", index)))
	}
	insert := func() {
		t.Helper()
		for index, rule := range rules {
			port := 8080
			if index >= 5 {
				port = 8443
			}
			ep := taskEndpoint{IP: "192.0.2.1", URL: fmt.Sprintf("http://192.0.2.1:%d/", port)}
			if err := insertPOCTask(ctx, tx, "group-run", "source-task", 1, fmt.Sprintf("http://192.0.2.1:%d", port), "192.0.2.1", ep, rule, []string{fmt.Sprintf("Product-%d", index)}, fmt.Sprintf("reason-%d", index), true); err != nil {
				t.Fatal(err)
			}
		}
	}
	insert()
	if err := groupDerivedPOCBatches(ctx, tx, "group-run"); err != nil {
		t.Fatal(err)
	}
	insert() // Reconciliation reuses original per-rule derived keys, including aliases.
	rows, err := tx.Query(ctx, `SELECT payload FROM tasks WHERE run_id='group-run'`)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	total, taskCount := 0, 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var payload pocBatchPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		taskCount++
		if len(payload.Rules) > 4 {
			t.Fatal("batch larger than four")
		}
		counts[payload.Endpoint.URL] += len(payload.Rules)
		total += len(payload.Rules)
		if len(payload.Rules) > 1 {
			var trace struct {
				Triggers map[string]struct {
					Products []string `json:"matched_products"`
					Reason   string   `json:"trigger_reason"`
				} `json:"rule_triggers"`
			}
			if err := json.Unmarshal(raw, &trace); err != nil || len(trace.Triggers) != len(payload.Rules) {
				t.Fatalf("lost per-rule product provenance: %s", raw)
			}
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if taskCount != 3 || total != 7 || counts["http://192.0.2.1:8080/"] != 5 || counts["http://192.0.2.1:8443/"] != 2 {
		t.Fatalf("grouping crossed scope or duplicated: tasks=%d rules=%d groups=%v", taskCount, total, counts)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNucleiBatchObservationRequiresVerifiedEngine(t *testing.T) {
	rule := controlBatchRule(t, "unverified-engine")
	payload, _ := json.Marshal(pocBatchPayload{Endpoint: taskEndpoint{URL: "http://192.0.2.1:8080/"}, Rules: []rulelib.Rule{rule}, Profile: rulelib.NucleiSingleResponseBatchProfile})
	for _, status := range []string{"matched", "not_matched"} {
		item := Observation{RuleID: rule.ID, RuleRevision: rule.Revision, RuleName: rule.Name, Engine: rule.Engine, Severity: rule.Severity, TemplateID: rule.Nuclei.TemplateID, ContentSHA256: rule.Nuclei.ContentSHA256, ExecutionProfile: rule.Nuclei.ExecutionProfile, EngineVersion: "3.12.0", EvidenceProfile: "nuclei-3.11.1-single-http-response-v1", FindingStatus: status, CanProveNoMatch: true, URL: "http://192.0.2.1:8080/health", RequestRaw: "GET /health HTTP/1.1\r\nHost: 192.0.2.1:8080\r\n\r\n", ResponseRaw: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"}
		if err := validatePOCObservation(payload, &item); err != nil {
			t.Fatal(err)
		}
		if item.FindingStatus != "incomplete" || item.CanProveNoMatch {
			t.Fatalf("unverified engine accepted: %+v", item)
		}
	}
}
