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
	"strings"
	"testing"
	"time"

	fb "scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/webevidence"
)

func TestHTTPFullProgressBounds(t *testing.T) {
	reserved := webevidence.EntryProgress{MaxRequests: 2048}
	reserveHTTPFullSegment(&reserved, 1)
	reserveHTTPFullSegment(&reserved, 1)
	reserveHTTPFullSegment(&reserved, 2)
	reserveHTTPFullSegment(&reserved, 3)
	if reserved.ReservedRequests != 2048 || reserved.SegmentRequestLimit != 0 {
		t.Fatal("unknown request budget was refunded or reservation replayed")
	}
	p := webevidence.EntryProgress{Segment: 1, MaxSegments: 32, MaxRequests: 16384, RequestsUsed: 3, Deadline: time.Now().UTC(), CompletedRuleIDs: []string{"one"}, Matches: []webevidence.Match{{Name: "positive", Engine: "fingers"}}}
	n := p
	n.Segment = 2
	n.RequestsUsed = 5
	n.CompletedRuleIDs = []string{"one", "two"}
	n.RemainingRuleIDs = []string{"three"}
	if err := validateHTTPProgress(p, n); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*webevidence.EntryProgress){func(x *webevidence.EntryProgress) { x.Deadline = x.Deadline.Add(time.Second) }, func(x *webevidence.EntryProgress) { x.MaxRequests++ }, func(x *webevidence.EntryProgress) { x.Segment = 33 }, func(x *webevidence.EntryProgress) { x.CompletedRuleIDs = nil }, func(x *webevidence.EntryProgress) { x.RemainingRuleIDs = []string{"one"} }, func(x *webevidence.EntryProgress) { x.Complete = true }, func(x *webevidence.EntryProgress) { x.Matches = nil }} {
		bad := n
		change(&bad)
		if validateHTTPProgress(p, bad) == nil {
			t.Fatal("accepted reset or lost positive")
		}
	}
}

func TestPostgresHTTPFullCheckpointClaimBudgetAndFence(t *testing.T) {
	s, h := newPolicyTestServer(t, "http_full_v2")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var transcript bytes.Buffer
	sequence := 0
	call := func(label, method, path, token string, body any, want int) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "http://control.test"+path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		dump, _ := httputil.DumpRequest(r, true)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		rdump, _ := httputil.DumpResponse(w.Result(), true)
		sequence++
		fmt.Fprintf(&transcript, "\n### %02d %s\n\n```http\n%s\n%s\n```\n", sequence, label, dump, rdump)
		if w.Code != want {
			t.Fatalf("%s got %d want %d: %s", label, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}
	t.Cleanup(func() {
		if dir := os.Getenv("HTTP_FULL_EVIDENCE_DIR"); dir != "" {
			_ = os.MkdirAll(dir, 0700)
			_ = os.WriteFile(filepath.Join(dir, "http-full-checkpoints-complete-http.md"), transcript.Bytes(), 0600)
		}
	})
	var worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	_ = json.Unmarshal(call("register", "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "http-full", "hostname": "local", "session_id": "full-session"}, 200), &worker)
	ep := taskEndpoint{IP: "192.0.2.99", URL: "http://192.0.2.99/start", WorkKey: "stable-entry"}
	payload, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{ep}, "fingerprint_bundle": strings.Repeat("a", 64), "fingerprint_bundle_schema": fb.Schema, "web_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile, "web_execution_profile": webevidence.FullProfile})
	if _, err := s.db.Exec(ctx, `INSERT INTO fingerprint_bundles(digest,source_revision,engine_revision,package,stats,source_notice,manifest_hash)VALUES($1,$2,$3,$4,'{}','local scheduler fixture',$5)`, strings.Repeat("a", 64), strings.Repeat("b", 40), fb.EngineRevision, []byte("{}"), strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := json.Marshal(ruleSnapshot{FingerprintBundle: strings.Repeat("a", 64), FingerprintBundleSchema: fb.Schema, WebExecutionProfile: webevidence.FullProfile, WebProfile: webevidence.Profile, WebEnrichmentProfile: webevidence.EnrichmentProfile})
	_, err := s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,rules_snapshot)VALUES('full-run','full','["192.0.2.99"]','{http}','running',$1);`, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key)VALUES('full-task','full-run','http',$1,'full-entry','192.0.2.99')`, payload)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(id, profile string) *Task {
		var out struct {
			Task *Task `json:"task"`
		}
		_ = json.Unmarshal(call("claim-"+id, "POST", "/api/tasks/claim", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "full-session", "request_id": id, "types": []string{"http"}, "supports_confirmed_stop": true, "supports_http_request_budget": true, "web_evidence_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile, "web_execution_profile": profile, "fingerprint_bundle_schema": fb.Schema, "fingerprint_bundle": webevidence.FingerprintBundle}, 200), &out)
		return out.Task
	}
	if claim("old-profile", "") != nil {
		t.Fatal("legacy capability claimed full work")
	}
	task := claim("full-profile", webevidence.FullProfile)
	if task == nil {
		t.Fatal("full capable worker got no task")
	}
	var config fullHTTPPayload
	if json.Unmarshal(task.Payload, &config) != nil || config.Progress == nil {
		t.Fatal("missing authoritative progress")
	}
	initial := *config.Progress
	initial.MaxRequests = 2048
	bounded, _ := json.Marshal(initial)
	if _, err = s.db.Exec(ctx, `UPDATE tasks SET payload=jsonb_set(payload,'{http_progress}',$1::jsonb) WHERE id='full-task'`, bounded); err != nil {
		t.Fatal(err)
	}
	permit := func(seq, segment int, want int) {
		call("permit", "POST", "/api/tasks/full-task/http-permit", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "full-session", "attempt_no": task.AttemptNo, "request_id": fmt.Sprint(seq), "connect_ip": ep.IP, "host": ep.IP, "port": 80, "segment": segment}, want)
	}
	permit(1, 1, 200)
	// Build a real complete normalized request/response sample; the test exercises
	// acceptance and resume semantics without touching a target outside this fixture.
	response := webevidence.Response{URL: ep.URL, ConnectIP: ep.IP, Host: ep.IP, StatusCode: 200, Completeness: "full", RequestRaw: "GET /start HTTP/1.1\r\nHost: 192.0.2.99\r\n\r\n", HeaderRaw: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", Body: []byte("ok"), DecodedBytes: 2, BodySHA256: webevidence.SHA256([]byte("ok"))}
	checkpoint := func(p webevidence.EntryProgress) Observation {
		identity := webevidence.ExecutionIdentity{EntryURL: p.EntryURL, RulesRef: p.RulesRef, ManifestHash: p.ManifestHash, SelectionProfileHash: p.SelectionProfileHash, TaskID: task.ID, AttemptNo: task.AttemptNo, EntryID: ep.WorkKey, Segment: p.Segment}
		probe := webevidence.ProbeResult{ID: "probe", Protocol: webevidence.Protocol, Profile: webevidence.FullProfile, ExecutionProfile: webevidence.FullProfile, Identity: identity, InputURL: ep.URL, Response: response, Attempts: []webevidence.Response{response}, Requests: 1}
		match := webevidence.MatchResult{ID: "match", Protocol: webevidence.Protocol, ExecutionProfile: webevidence.FullProfile, Identity: identity, Bundle: strings.Repeat("a", 64), Active: &webevidence.ActiveResult{Complete: p.Complete, CompletedRuleIDs: p.CompletedRuleIDs, RemainingRuleIDs: p.RemainingRuleIDs}}
		e, _ := json.Marshal(map[string]any{"probe": probe, "fingerprint": match})
		coverage, outcome := "partial", "incomplete"
		if p.Complete {
			coverage, outcome = "complete", "identified"
		}
		return Observation{Kind: "http", Target: ep.IP, IP: ep.IP, Port: 80, URL: ep.URL, WorkKey: ep.WorkKey, StatusCode: 200, Coverage: coverage, Outcome: outcome, ExecutionProfile: webevidence.FullProfile, Evidence: string(e), HTTPProgress: &p}
	}
	batch := func(seq int, o Observation, want int) {
		call("checkpoint", "POST", "/api/tasks/full-task/batches", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "full-session", "attempt_no": task.AttemptNo, "batch_seq": seq, "items": []Observation{o}}, want)
	}
	p := initial
	p.Segment = 1
	p.RequestsUsed = 1
	p.CompletedRuleIDs = []string{"rule-one"}
	p.RemainingRuleIDs = []string{"rule-two"}
	p.Matches = []webevidence.Match{{Name: "preserved-positive", Engine: "fingers"}}
	batch(0, checkpoint(p), 200)
	batch(0, checkpoint(p), 200)
	var used, count int
	if err = s.db.QueryRow(ctx, `SELECT (payload->'http_progress'->>'requests_used')::int FROM tasks WHERE id='full-task'`).Scan(&used); err != nil || used != 1 {
		t.Fatalf("budget reset: %d %v", used, err)
	}
	oldAttempt := task.AttemptNo
	call("confirmed-stop-for-resume", "POST", "/api/tasks/full-task/release", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "full-session", "attempt_no": oldAttempt, "reason": "fixture restart", "retryable": true, "stopped": true}, 200)
	task = claim("resume", webevidence.FullProfile)
	if task == nil || task.AttemptNo != oldAttempt+1 {
		t.Fatal("resume did not advance execution fence")
	}
	var resumed fullHTTPPayload
	if json.Unmarshal(task.Payload, &resumed) != nil || resumed.Progress == nil || !resumed.Progress.Deadline.Equal(initial.Deadline) || resumed.Progress.RequestsUsed != 1 || resumed.Progress.ReservedRequests != 2048 || resumed.Progress.Segment != 2 || len(resumed.Progress.CompletedRuleIDs) != 1 {
		t.Fatalf("resume reset progress: %+v", resumed.Progress)
	}
	call("stale-old-attempt", "POST", "/api/tasks/full-task/batches", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "full-session", "attempt_no": oldAttempt, "batch_seq": 1, "items": []Observation{checkpoint(p)}}, 409)
	// A newer template segment replaces the current entry asset, preserving prior
	// completed IDs and positive evidence in its accepted checkpoint.
	time.Sleep(110 * time.Millisecond)
	permit(2, 2, 200)
	p.Segment = 2
	p.RequestsUsed = 2
	p.CompletedRuleIDs = []string{"rule-one", "rule-two"}
	p.RemainingRuleIDs = nil
	p.Complete = true
	batch(0, checkpoint(p), 200)
	permit(3, 3, 409)
	if err = s.db.QueryRow(ctx, `SELECT count(*) FROM assets WHERE task_id='full-task'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("segmentation duplicated asset: %d %v", count, err)
	}
	if _, err = s.db.Exec(ctx, `UPDATE runs SET status='paused' WHERE id='full-run'`); err != nil {
		t.Fatal(err)
	}
	call("paused-completion-fenced", "POST", "/api/tasks/full-task/complete", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "full-session", "attempt_no": task.AttemptNo, "last_batch_seq": 0}, 409)
	if _, err = s.db.Exec(ctx, `UPDATE runs SET status='running' WHERE id='full-run'`); err != nil {
		t.Fatal(err)
	}
	call("complete", "POST", "/api/tasks/full-task/complete", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "full-session", "attempt_no": task.AttemptNo, "last_batch_seq": 0}, 200)
	call("stale-attempt-batch", "POST", "/api/tasks/full-task/batches", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "full-session", "attempt_no": task.AttemptNo + 1, "batch_seq": 2, "items": []Observation{checkpoint(p)}}, 409)
	permit(3, 2, 409)
	legacy, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{{IP: "192.0.2.98", URL: "http://192.0.2.98/", WorkKey: "legacy"}}, "fingerprint_bundle": strings.Repeat("b", 64), "fingerprint_bundle_schema": fb.LegacySchema, "web_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile})
	if _, err = s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status)VALUES('legacy-run','legacy','[]','{http}','running');`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key)VALUES('legacy-task','legacy-run','http',$1,'legacy-entry','192.0.2.98')`, legacy); err != nil {
		t.Fatal(err)
	}
	if task = claim("legacy-v1-compatible", webevidence.FullProfile); task == nil || task.ID != "legacy-task" {
		t.Fatal("v2 Agent cannot claim legacy v1 schema")
	}
	t.Logf("PASS full capability claim fence, fixed deadline, cumulative grants=%d, checkpoint replay, one entry asset=%d, paused/stale fences, completion receipt", p.RequestsUsed, count)
}
