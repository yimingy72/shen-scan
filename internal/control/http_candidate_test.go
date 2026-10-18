package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"scanplatform/internal/rulelib"
	"strings"
	"testing"
)

// Candidate observations remain stored evidence, but never supply a product
// match to an automatically routed PoC. An independent confirmation may do so.
func TestPostgresHTTPCandidateDoesNotTriggerProductPOC(t *testing.T) {
	s, h := newPolicyTestServer(t, "http_candidate")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var transcript bytes.Buffer
	request := func(label, path, token string, body any) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "http://control.test"+path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		sent, _ := httputil.DumpRequest(r, true)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		received, _ := httputil.DumpResponse(w.Result(), true)
		fmt.Fprintf(&transcript, "\n### %s\n\n```http\n%s\n%s\n```\n", label, sent, received)
		if w.Code != 200 {
			t.Fatalf("%s got %d: %s", label, w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	t.Cleanup(func() {
		if dir := os.Getenv("HTTP_FULL_EVIDENCE_DIR"); dir != "" {
			_ = os.MkdirAll(dir, 0700)
			_ = os.WriteFile(filepath.Join(dir, "candidate-poc-complete-http.md"), transcript.Bytes(), 0600)
		}
	})
	var worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	_ = json.Unmarshal(request("register", "/api/workers/register", "join-policy", map[string]any{"instance_id": "candidate-fixture", "hostname": "local", "session_id": "candidate-session"}), &worker)
	rule := testPOCRule("poc-rdp-confirmation-fixture", []string{"rdp"})
	snapshot, _ := json.Marshal(ruleSnapshot{POCPolicy: "fingerprint", POC: []rulelib.Rule{rule}})
	ep := taskEndpoint{IP: "192.0.2.150", URL: "http://192.0.2.150/", WorkKey: "entry"}
	payload, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{ep}})
	for _, confirmed := range []bool{false, true} {
		label := "candidate-only"
		want := 0
		if confirmed {
			label = "independently-confirmed"
			want = 1
		}
		runID, taskID := newID(), newID()
		if _, err := s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,poc_enabled,rules_snapshot)VALUES($1,$2,'["192.0.2.150"]','{http}','running',true,$3)`, runID, label, snapshot); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key)VALUES($1,$2,'http',$3,'entry','192.0.2.150')`, taskID, runID, payload); err != nil {
			t.Fatal(err)
		}
		var claim struct {
			Task *Task `json:"task"`
		}
		_ = json.Unmarshal(request(label+" claim", "/api/tasks/claim", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "candidate-session", "request_id": label, "types": []string{"http"}, "supports_confirmed_stop": true, "supports_http_request_budget": true}), &claim)
		if claim.Task == nil || claim.Task.ID != taskID {
			t.Fatalf("wrong candidate fixture task: %+v", claim.Task)
		}
		technologies := []Technology{{Name: "rdp", Candidate: true, CandidateReason: "bare Goby feature substring", RuleID: "goby:rdp", Evidence: "original Goby feature rdp matches WordPress substring"}}
		if confirmed {
			technologies = append(technologies, Technology{Name: "rdp", RuleID: "native:rdp-confirmation", Evidence: "independent complete protocol confirmation"})
		}
		obs := Observation{Kind: "http", Target: ep.IP, IP: ep.IP, URL: ep.URL, Port: 80, WorkKey: ep.WorkKey, StatusCode: 200, Coverage: "complete", Outcome: "identified", Technologies: technologies, RequestRaw: "GET / HTTP/1.1\r\nHost: 192.0.2.150\r\n\r\n", ResponseRaw: "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nWordPress"}
		identity := map[string]any{"worker_id": worker.ID, "session_id": "candidate-session", "attempt_no": claim.Task.AttemptNo, "batch_seq": 0, "items": []Observation{obs}}
		request(label+" evidence", "/api/tasks/"+taskID+"/batches", worker.Token, identity)
		request(label+" complete", "/api/tasks/"+taskID+"/complete", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "candidate-session", "attempt_no": claim.Task.AttemptNo, "last_batch_seq": 0})
		var count int
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE run_id=$1 AND type='poc'`, runID).Scan(&count); err != nil || count != want {
			t.Fatalf("%s derived PoCs=%d want=%d: %v", label, count, want, err)
		}
		var stored []byte
		if err := s.db.QueryRow(ctx, `SELECT observation FROM assets WHERE task_id=$1`, taskID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(stored), `"candidate": true`) || !strings.Contains(string(stored), "bare Goby feature substring") {
			t.Fatalf("candidate evidence lost: %s", stored)
		}
		t.Logf("%s: retained candidate evidence, product PoCs=%d", label, count)
	}
}
