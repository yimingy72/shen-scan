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
	"path/filepath"
	"strings"
	"testing"
)

func earlyEvidenceCaller(t *testing.T, h http.Handler) func(string, string, string, any, int, any) {
	t.Helper()
	var transcript strings.Builder
	t.Cleanup(func() {
		if dir := os.Getenv("SCAN_TEST_EVIDENCE_DIR"); dir != "" {
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(filepath.Join(dir, t.Name()+".http"), []byte(transcript.String()), 0600); err != nil {
				t.Error(err)
			}
		}
	})
	return func(method, path, token string, body any, want int, out any) {
		t.Helper()
		encoded, _ := json.Marshal(body)
		if body == nil {
			encoded = nil
		}
		req := httptest.NewRequest(method, "http://example.com"+path, bytes.NewReader(encoded))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		requestDump, _ := httputil.DumpRequest(req, true)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		responseDump, _ := httputil.DumpResponse(rr.Result(), true)
		fmt.Fprintf(&transcript, "\n### %s %s\n%s\n%s\n", method, path, requestDump, responseDump)
		if rr.Code != want {
			t.Fatalf("%s %s => %d want %d: %s", method, path, rr.Code, want, rr.Body.String())
		}
		if out != nil {
			if err := json.Unmarshal(rr.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestEarlyPortReceiptsAndRetry(t *testing.T) {
	t.Setenv("SCAN_CALIBRATED_PORT_PROFILE", "")
	s, h := newPolicyTestServer(t, "early_receipts")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	call := earlyEvidenceCaller(t, h)
	type worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	workers := make([]worker, 2)
	for i := range workers {
		call("POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": fmt.Sprintf("early-%d", i), "hostname": "fixture", "session_id": "session"}, 200, &workers[i])
	}
	var run Run
	call("POST", "/api/runs", "admin-policy", map[string]any{"name": "early positive evidence fixture", "targets": []string{"192.0.2.61"}, "modes": []string{"port"}}, 201, &run)
	claim := func(i int, stage, request string) *Task {
		var out struct {
			Task *Task `json:"task"`
		}
		call("POST", "/api/tasks/claim", workers[i].Token, map[string]any{"worker_id": workers[i].ID, "session_id": "session", "request_id": request, "types": []string{stage}, "supports_confirmed_stop": true, "supports_port_ranges": true, "service_profile": "nmap-light-v1"}, 200, &out)
		return out.Task
	}
	source := claim(0, "port", "port-one")
	if source == nil {
		t.Fatal("source not claimed")
	}
	batch := func(task *Task, seq int, ports ...int) map[string]any {
		items := []Observation{}
		for _, port := range ports {
			items = append(items, Observation{Kind: "port", IP: "192.0.2.61", Port: port, Protocol: "tcp"})
		}
		return map[string]any{"worker_id": workers[0].ID, "session_id": "session", "attempt_no": task.AttemptNo, "batch_seq": seq, "items": items}
	}
	first := batch(source, 0, 80, 443, 80)
	call("POST", "/api/tasks/"+source.ID+"/batches", workers[0].Token, first, 200, nil)
	var selected, receipts, services int
	if err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM port_service_work WHERE run_id=$1),(SELECT count(*) FROM port_positive_receipts WHERE run_id=$1),(SELECT count(*) FROM tasks WHERE run_id=$1 AND type='service')`, run.ID).Scan(&selected, &receipts, &services); err != nil || selected != 2 || receipts != 2 || services != 1 {
		t.Fatal(selected, receipts, services, err)
	}
	service := claim(1, "service", "early-service")
	if service == nil {
		t.Fatal("downstream unavailable before source completion")
	}
	var p struct {
		Endpoints []taskEndpoint `json:"endpoints"`
	}
	if json.Unmarshal(service.Payload, &p) != nil || len(p.Endpoints) != 2 {
		t.Fatal(string(service.Payload))
	}
	completeService := func(task *Task) {
		var payload struct {
			Endpoints []taskEndpoint `json:"endpoints"`
		}
		if err := json.Unmarshal(task.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		items := []Observation{}
		for _, ep := range payload.Endpoints {
			items = append(items, Observation{Kind: "service", IP: ep.IP, Port: ep.Port, Outcome: "unknown"})
		}
		call("POST", "/api/tasks/"+task.ID+"/batches", workers[1].Token, map[string]any{"worker_id": workers[1].ID, "session_id": "session", "attempt_no": task.AttemptNo, "batch_seq": 0, "items": items}, 200, nil)
		call("POST", "/api/tasks/"+task.ID+"/complete", workers[1].Token, map[string]any{"worker_id": workers[1].ID, "session_id": "session", "attempt_no": task.AttemptNo, "last_batch_seq": 0}, 200, nil)
	}
	completeService(service)
	call("POST", "/api/tasks/"+source.ID+"/release", workers[0].Token, map[string]any{"worker_id": workers[0].ID, "session_id": "session", "attempt_no": source.AttemptNo, "reason": "fixture interrupted after accepted positive batch", "retryable": true, "stopped": true}, 200, nil)
	retry := claim(0, "port", "port-two")
	if retry == nil || retry.ID != source.ID || retry.AttemptNo != 2 {
		t.Fatal(retry)
	}
	call("POST", "/api/tasks/"+source.ID+"/batches", workers[0].Token, first, 200, nil)
	call("POST", "/api/tasks/"+source.ID+"/batches", workers[0].Token, batch(source, 0, 81), 409, nil)
	call("POST", "/api/tasks/"+source.ID+"/batches", workers[0].Token, batch(source, 1, 444), 409, nil)
	second := batch(retry, 0, 80, 8080)
	call("POST", "/api/tasks/"+retry.ID+"/batches", workers[0].Token, second, 200, nil)
	call("POST", "/api/tasks/"+retry.ID+"/batches", workers[0].Token, second, 200, nil)
	if err := s.db.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE source_attempt_no=1) FROM port_positive_receipts WHERE run_id=$1`, run.ID).Scan(&receipts, &selected); err != nil || receipts != 3 || selected != 2 {
		t.Fatal(receipts, selected, err)
	}
	var fingerprintCount, openCount int
	if err := s.db.QueryRow(ctx, `SELECT fingerprint_count,open_port_count FROM run_target_policies WHERE run_id=$1`, run.ID).Scan(&fingerprintCount, &openCount); err != nil || fingerprintCount != 3 || openCount != 3 {
		t.Fatal(fingerprintCount, openCount, err)
	}
	call("POST", "/api/tasks/"+retry.ID+"/release", workers[0].Token, map[string]any{"worker_id": workers[0].ID, "session_id": "session", "attempt_no": retry.AttemptNo, "reason": "fixture terminal partial range", "retryable": false, "stopped": true}, 200, nil)
	next := claim(1, "service", "service-two")
	if next == nil {
		t.Fatal("new port not scheduled")
	}
	completeService(next)
	call("GET", "/api/runs/"+run.ID, "admin-policy", nil, 200, &run)
	if run.Status != "partial" || run.OpenPortCount != 3 {
		t.Fatal(run)
	}
	var targets struct {
		Items []struct {
			OpenPorts int    `json:"open_port_count"`
			PortState string `json:"port_state"`
			Coverage  string `json:"port_coverage"`
		} `json:"items"`
	}
	call("GET", "/api/runs/"+run.ID+"/results", "admin-policy", nil, 200, &targets)
	if len(targets.Items) != 1 || targets.Items[0].OpenPorts != 3 || targets.Items[0].PortState != "failed" || targets.Items[0].Coverage != "partial" {
		t.Fatal(targets)
	}
	var ports struct {
		Total int `json:"total"`
		Items []struct {
			Receipt       string `json:"positive_port_receipt_id"`
			ObservationID string `json:"port_observation_id"`
		} `json:"items"`
	}
	call("GET", "/api/runs/"+run.ID+"/ports?target=192.0.2.61", "admin-policy", nil, 200, &ports)
	if ports.Total != 3 {
		t.Fatal(ports)
	}
	for _, item := range ports.Items {
		if item.Receipt == "" {
			t.Fatal("missing source provenance")
		}
	}
	var detail struct {
		Receipt struct {
			SourceAttempt int    `json:"source_attempt_no"`
			BatchHash     string `json:"batch_sha256"`
			Independent   bool   `json:"coverage_independent"`
		} `json:"positive_port_receipt"`
	}
	call("GET", "/api/observations/"+ports.Items[0].ObservationID, "admin-policy", nil, 200, &detail)
	if detail.Receipt.SourceAttempt != 1 || len(detail.Receipt.BatchHash) != 64 || !detail.Receipt.Independent {
		t.Fatal(detail)
	}
	var covered int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM port_range_manifest m JOIN tasks t ON t.id=m.task_id WHERE m.run_id=$1 AND t.state='completed' AND t.coverage='complete'`, run.ID).Scan(&covered); err != nil || covered != 0 {
		t.Fatal("invented range completion", covered, err)
	}
}

func TestEarlyPortSharedFingerprintBudget(t *testing.T) {
	t.Setenv("SCAN_CALIBRATED_PORT_PROFILE", "")
	s, h := newPolicyTestServer(t, "early_dense")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	call := earlyEvidenceCaller(t, h)
	var worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	call("POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "early-dense", "hostname": "fixture", "session_id": "session"}, 200, &worker)
	var run Run
	call("POST", "/api/runs", "admin-policy", map[string]any{"name": "dense accepted positive fixture", "targets": []string{"192.0.2.62"}, "modes": []string{"port"}}, 201, &run)
	var claim struct {
		Task *Task `json:"task"`
	}
	call("POST", "/api/tasks/claim", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "session", "request_id": "dense", "types": []string{"port"}, "supports_confirmed_stop": true, "supports_port_ranges": true}, 200, &claim)
	if claim.Task == nil {
		t.Fatal("source not leased")
	}
	items := make([]Observation, 1100)
	for i := range items {
		items[i] = Observation{Kind: "port", IP: "192.0.2.62", Port: i + 1, Protocol: "tcp"}
	}
	batch := map[string]any{"worker_id": worker.ID, "session_id": "session", "attempt_no": claim.Task.AttemptNo, "batch_seq": 0, "items": items}
	path := "/api/tasks/" + claim.Task.ID
	call("POST", path+"/batches", worker.Token, batch, 200, nil)
	call("POST", path+"/batches", worker.Token, batch, 200, nil)
	items = append(items, Observation{Kind: "port", IP: "192.0.2.62", Port: 2000, Protocol: "tcp"})
	batch["batch_seq"] = 1
	batch["items"] = items
	call("POST", path+"/batches", worker.Token, batch, 200, nil)
	call("POST", path+"/complete", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "session", "attempt_no": claim.Task.AttemptNo, "last_batch_seq": 1}, 200, nil)
	var evidence, work, selected, open, services int
	if err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM port_positive_receipts WHERE run_id=$1),(SELECT count(*) FROM port_service_work WHERE run_id=$1),fingerprint_count,open_port_count,(SELECT count(*) FROM tasks WHERE run_id=$1 AND type='service') FROM run_target_policies WHERE run_id=$1`, run.ID).Scan(&evidence, &work, &selected, &open, &services); err != nil || evidence != 1101 || open != 1101 || work != 1024 || selected != 1024 || services != 32 {
		t.Fatal(evidence, work, selected, open, services, err)
	}
}
