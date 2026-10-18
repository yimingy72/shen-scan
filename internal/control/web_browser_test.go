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
	"reflect"
	"testing"
	"time"

	"scanplatform/internal/rulelib"
	"scanplatform/internal/webevidence"
)

func TestPostgresBrowserPhaseMergeBudgetAndFence(t *testing.T) {
	for _, variant := range []struct {
		name                       string
		browserComplete, baseError bool
	}{{"complete", true, false}, {"browser-unavailable", false, false}, {"base-error-preserved", true, true}} {
		t.Run(variant.name, func(t *testing.T) {
			s, h := newPolicyTestServer(t, "browser_phase")
			ctx := context.Background()
			_, _ = s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`)
			var transcript bytes.Buffer
			t.Cleanup(func() {
				if dir := os.Getenv("BROWSER_EVIDENCE_DIR"); dir != "" {
					_ = os.MkdirAll(dir, 0700)
					_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("browser-phase-%s-complete-http.md", variant.name)), transcript.Bytes(), 0600)
				}
			})
			call := func(label, method, path, token string, body any, want int) []byte {
				t.Helper()
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest(method, "http://control.test"+path, bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", "Bearer "+token)
				dump, _ := httputil.DumpRequest(r, true)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				response, _ := httputil.DumpResponse(w.Result(), true)
				fmt.Fprintf(&transcript, "\n### %s\n\n```http\n%s\n%s\n```\n", label, dump, response)
				if w.Code != want {
					t.Fatalf("%s: %d want %d: %s", label, w.Code, want, w.Body.String())
				}
				return w.Body.Bytes()
			}
			var worker struct {
				ID    string `json:"worker_id"`
				Token string `json:"worker_token"`
			}
			_ = json.Unmarshal(call("register", "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "browser-fixture", "hostname": "local", "session_id": "browser-session"}, 200), &worker)
			rule := rulelib.Rule{ID: "browser-source", Kind: "http", Name: "Browser fixture", Severity: "info", Revision: 1, Engine: "httpx-cff", Enabled: true, Definition: rulelib.Definition{Product: "BrowserFixture"}, Fingerprint: json.RawMessage(`{"js":{"fixture.version":"^1\\.0$"}}`)}
			snapshot := ruleSnapshot{HTTP: []rulelib.Rule{rule}, FingerprintBundle: webevidence.FingerprintBundle, WebExecutionProfile: webevidence.FullProfile, WebBrowserProfile: webevidence.BrowserProfile}
			cff, _, _ := browserCFF(snapshot)
			snapshotRaw, _ := json.Marshal(snapshot)
			_, err := s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,rules_snapshot) VALUES('browser-run','browser','["192.0.2.90"]','{http}','running',$1)`, snapshotRaw)
			if err != nil {
				t.Fatal(err)
			}
			ep := taskEndpoint{IP: "192.0.2.90", URL: "http://192.0.2.90/", WorkKey: "browser-entry"}
			payload, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{ep}, "web_execution_profile": webevidence.FullProfile, "web_browser_profile": webevidence.BrowserProfile, "fingerprint_bundle": webevidence.FingerprintBundle})
			_, err = s.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES('browser-parent','browser-run','http',$1,'parent','192.0.2.90');`, payload)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = s.db.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) VALUES('browser-parent','192.0.2.90')`)
			useRulesRef := variant.name == "complete"
			claim := func(id, phase string) *Task {
				var out struct {
					Task *Task `json:"task"`
				}
				_ = json.Unmarshal(call(id, "POST", "/api/tasks/claim", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "browser-session", "request_id": id, "types": []string{"http"}, "supports_confirmed_stop": true, "supports_http_request_budget": true, "web_execution_profile": webevidence.FullProfile, "web_browser_profile": webevidence.BrowserProfile, "fingerprint_bundle": webevidence.FingerprintBundle, "http_phase": phase, "use_rule_sets": phase == "browser" && useRulesRef}, 200), &out)
				return out.Task
			}
			parent := claim("claim-parent", "")
			if parent == nil {
				t.Fatal("no parent")
			}
			var assignment fullHTTPPayload
			_ = json.Unmarshal(parent.Payload, &assignment)
			progress := *assignment.Progress
			progress.Complete = true
			identity := webevidence.ExecutionIdentity{EntryURL: progress.EntryURL, RulesRef: progress.RulesRef, SelectionProfileHash: progress.SelectionProfileHash, ManifestHash: progress.ManifestHash, TaskID: parent.ID, AttemptNo: parent.AttemptNo, EntryID: ep.WorkKey, Segment: progress.Segment}
			body := []byte("<html><title>Parent</title></html>")
			response := webevidence.Response{URL: ep.URL, ConnectIP: ep.IP, Host: ep.IP, StatusCode: 200, Headers: map[string][]string{"Content-Type": {"text/html"}}, Completeness: "full", Body: body, DecodedBytes: len(body), BodySHA256: webevidence.SHA256(body), RequestRaw: "GET / HTTP/1.1\r\nHost: 192.0.2.90\r\n\r\n", HeaderRaw: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"}
			probe := webevidence.ProbeResult{ID: "parent-probe", Protocol: webevidence.Protocol, Profile: webevidence.FullProfile, ExecutionProfile: webevidence.FullProfile, Identity: identity, InputURL: ep.URL, Response: response, Requests: 1, CFFSHA256: webevidence.SHA256(cff), CapabilityGaps: []string{"wappalyzer-browser-js-dom"}}
			match := webevidence.MatchResult{Protocol: webevidence.Protocol, ExecutionProfile: webevidence.FullProfile, Identity: identity, Active: &webevidence.ActiveResult{Complete: true}}
			evidence, _ := json.Marshal(map[string]any{"probe": probe, "fingerprint": match})
			base := Observation{Kind: "http", Target: ep.IP, IP: ep.IP, Port: 80, URL: ep.URL, WorkKey: ep.WorkKey, StatusCode: 200, Title: "Parent", BodyExcerpt: string(body), Technologies: []Technology{{Name: "parent-positive"}}, Coverage: "partial", Outcome: "incomplete", HTTPProgress: &progress, ExecutionProfile: webevidence.FullProfile, Evidence: string(evidence)}
			batch := func(task *Task, obs Observation, want int) {
				call("batch-"+task.ID, "POST", "/api/tasks/"+task.ID+"/batches", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "browser-session", "attempt_no": task.AttemptNo, "batch_seq": 0, "items": []Observation{obs}}, want)
			}
			complete := func(task *Task, want int) {
				call("complete-"+task.ID, "POST", "/api/tasks/"+task.ID+"/complete", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "browser-session", "attempt_no": task.AttemptNo, "last_batch_seq": 0}, want)
			}
			if variant.baseError {
				base.Error = "fingers stage incomplete"
			}
			batch(parent, base, 200)
			complete(parent, 200)
			assertResult := func(wantBrowser bool) {
				t.Helper()
				var out struct {
					Items []struct {
						Title        string                    `json:"title"`
						Technologies []Technology              `json:"technologies"`
						Browser      *webevidence.BrowserStage `json:"browser"`
					} `json:"items"`
					Total int `json:"total"`
				}
				_ = json.Unmarshal(call("visible-http", "GET", "/api/runs/browser-run/http", "admin-policy", nil, 200), &out)
				if out.Total != 1 || out.Items[0].Title != "Parent" {
					t.Fatalf("base result lost or duplicated: %+v", out)
				}
				found := false
				for _, v := range out.Items[0].Technologies {
					if v.Name == "parent-positive" {
						found = true
					}
				}
				if !found {
					t.Fatal("parent positive lost")
				}
				if wantBrowser && (out.Items[0].Browser == nil || out.Items[0].Browser.State != map[bool]string{true: "complete", false: "partial"}[variant.browserComplete]) {
					t.Fatalf("browser stage not complete: %+v", out)
				}
			}
			assertResult(false)
			if claim("ordinary-excludes-browser", "") != nil {
				t.Fatal("ordinary lane took browser")
			}
			child := claim("browser-independent", "browser")
			if child == nil {
				t.Fatal("browser child missing")
			}
			var declaration struct {
				RulesRef string         `json:"rules_ref"`
				Rules    []rulelib.Rule `json:"rules"`
			}
			if err = json.Unmarshal(child.Payload, &declaration); err != nil {
				t.Fatal(err)
			}
			if useRulesRef {
				if declaration.RulesRef != "browser-run:http" || declaration.Rules != nil {
					t.Fatalf("browser deadline erased claim rules reference: %s", child.Payload)
				}
				var frozen struct {
					Ref   string         `json:"ref"`
					Rules []rulelib.Rule `json:"rules"`
				}
				_ = json.Unmarshal(call("browser-reference-download", "GET", "/api/tasks/"+child.ID+"/rules?worker_id="+worker.ID+"&session_id=browser-session&attempt_no="+fmt.Sprint(child.AttemptNo), worker.Token, nil, 200), &frozen)
				referencedCFF, _, e := browserCFF(ruleSnapshot{HTTP: frozen.Rules})
				if e != nil || frozen.Ref != declaration.RulesRef || webevidence.SHA256(referencedCFF) != webevidence.SHA256(cff) {
					t.Fatal("browser reference no longer resolves frozen CFF")
				}
			} else {
				if declaration.RulesRef != "" || len(declaration.Rules) != 1 {
					t.Fatalf("browser deadline erased inline rules: %s", child.Payload)
				}
				inlineCFF, _, e := browserCFF(ruleSnapshot{HTTP: declaration.Rules})
				if e != nil || webevidence.SHA256(inlineCFF) != webevidence.SHA256(cff) {
					t.Fatal("browser inline CFF changed")
				}
			}
			replay := claim("browser-independent", "browser")
			if replay == nil {
				t.Fatal("browser claim replay lost task")
			}
			var firstPayload, replayPayload any
			_ = json.Unmarshal(child.Payload, &firstPayload)
			_ = json.Unmarshal(replay.Payload, &replayPayload)
			if !reflect.DeepEqual(firstPayload, replayPayload) || child.AttemptNo != replay.AttemptNo {
				t.Fatal("browser replay changed deadline/rules/identity")
			}
			var storedRef, storedRules bool
			if err = s.db.QueryRow(ctx, `SELECT payload ? 'rules_ref',payload ? 'rules' FROM tasks WHERE id=$1`, child.ID).Scan(&storedRef, &storedRules); err != nil || storedRef || storedRules {
				t.Fatal("claim-only rules were persisted to task payload")
			}
			if claim("one-browser-per-worker", "browser") != nil {
				t.Fatal("second browser slot claimed")
			}
			var p webevidence.BrowserAssignment
			_ = json.Unmarshal(child.Payload, &p)
			if p.BrowserSeed == nil {
				t.Fatal("complete tiny HTML seed was not retained")
			}
			// A leased browser cannot block a quick ordinary task even at the same target.
			fastRaw, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{{IP: ep.IP, URL: "http://192.0.2.90/fast", WorkKey: "fast"}}})
			_, err = s.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES('fast-http','browser-run','http',$1,'fast','192.0.2.90')`, fastRaw)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = s.db.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) VALUES('fast-http','192.0.2.90')`)
			fast := claim("fast-during-browser", "")
			if fast == nil || fast.ID != "fast-http" {
				t.Fatal("browser blocked ordinary HTTP")
			}
			batch(fast, Observation{Kind: "http", Target: ep.IP, IP: ep.IP, URL: ep.URL, WorkKey: "fast", Coverage: "complete", Outcome: "identified"}, 200)
			complete(fast, 200)
			permit := func(task *Task, seq int, want int) {
				call("browser-permit", "POST", "/api/tasks/"+task.ID+"/http-permit", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "browser-session", "attempt_no": task.AttemptNo, "request_id": fmt.Sprint(seq), "connect_ip": ep.IP, "host": ep.IP, "port": 80}, want)
			}
			permit(child, 1, 200)
			// Releasing an attempt does not refund the grant or reset its deadline.
			call("browser-restart", "POST", "/api/tasks/"+child.ID+"/release", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "browser-session", "attempt_no": child.AttemptNo, "retryable": true, "reason": "local fixture restart", "stopped": true}, 200)
			old := *child
			child = claim("browser-reclaim", "browser")
			var resumed webevidence.BrowserAssignment
			_ = json.Unmarshal(child.Payload, &resumed)
			if child.AttemptNo != old.AttemptNo+1 || resumed.BrowserRequestsUsed != 1 || !resumed.BrowserDeadline.Equal(p.BrowserDeadline) {
				t.Fatal("browser retry reset budget/deadline")
			}
			identity.TaskID, identity.AttemptNo, identity.Segment = child.ID, child.AttemptNo, 0
			result := webevidence.BrowserResult{ID: "browser-result", Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, Identity: identity, Parent: p.BrowserParent, CFFSHA256: p.BrowserCFFSHA256, Engine: "fixture-browser", Complete: variant.browserComplete, PlanSHA256: webevidence.SHA256([]byte("fixture-plan")), TotalRules: 1, EvaluatedRules: 1, StopReason: "sample-window-complete", Matches: []webevidence.Match{{Name: "browser-positive", Engine: "fixture-browser"}}, Rules: []webevidence.RuleExecution{{RuleID: "js-fixture", Status: "matched"}}}
			if !variant.browserComplete {
				result.StopReason = "browser-unavailable"
				result.Error = "local fixture missing Chromium"
			}
			resultRaw, _ := json.Marshal(map[string]any{"browser": result})
			obs := Observation{Kind: "http", Target: ep.IP, IP: ep.IP, URL: ep.URL, Evidence: string(resultRaw)}
			batch(&old, obs, 409)
			_, _ = s.db.Exec(ctx, `UPDATE runs SET status='paused' WHERE id='browser-run'`)
			batch(child, obs, 409)
			_, _ = s.db.Exec(ctx, `UPDATE runs SET status='running' WHERE id='browser-run'`)
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET lease_until=now()-interval '1 second' WHERE id=$1`, child.ID)
			batch(child, obs, 409)
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET lease_until=now()+interval '1 minute' WHERE id=$1`, child.ID)
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET completion_id='changed-parent-execution' WHERE id='browser-parent'`)
			batch(child, obs, 422)
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET completion_id=$1 WHERE id='browser-parent'`, p.BrowserParent.CompletionID)
			// Grant accounting remains capped even across retries (do not issue 32 paced requests).
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET payload=jsonb_set(payload,'{browser_requests_used}','32'::jsonb) WHERE id=$1`, child.ID)
			time.Sleep(110 * time.Millisecond)
			permit(child, 1, 409)
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET payload=jsonb_set(payload,'{browser_requests_used}','1'::jsonb) WHERE id=$1`, child.ID)
			batch(child, obs, 200)
			complete(child, 200)
			assertResult(true)
			var status string
			_ = s.db.QueryRow(ctx, `SELECT status FROM runs WHERE id='browser-run'`).Scan(&status)
			wantStatus := "completed"
			if !variant.browserComplete || variant.baseError {
				wantStatus = "partial"
			}
			if status != wantStatus {
				t.Fatalf("superseded browser-only parent gap locked run %s", status)
			}
			var count int
			_ = s.db.QueryRow(ctx, currentResults+` SELECT count(*) FROM ob WHERE observation->>'status_code'='200'`, "browser-run").Scan(&count)
			if count != 1 {
				t.Fatalf("parent/child endpoint duplicated: %d", count)
			}
			t.Log("PASS browser claim reference/inline and replay retained; no rule persistence; parent visible before browser; independent claim; cumulative budget; stale, paused, expired and changed-parent fences; merged positive preservation; one endpoint; effective final coverage")
		})
	}
}

func TestPostgresBrowserMetadataFrozenForMultipleEntries(t *testing.T) {
	s, h := newPolicyTestServer(t, "browser_metadata")
	var transcript bytes.Buffer
	originalHandler := h
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, _ := httputil.DumpRequest(r, true)
		recorded := httptest.NewRecorder()
		originalHandler.ServeHTTP(recorded, r)
		response, _ := httputil.DumpResponse(recorded.Result(), true)
		fmt.Fprintf(&transcript, "\n### %s %s\n\n```http\n%s\n%s\n```\n", r.Method, r.URL.String(), request, response)
		for key, values := range recorded.Header() {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(recorded.Code)
		_, _ = w.Write(recorded.Body.Bytes())
	})
	t.Cleanup(func() {
		if dir := os.Getenv("BROWSER_EVIDENCE_DIR"); dir != "" {
			_ = os.MkdirAll(dir, 0700)
			_ = os.WriteFile(filepath.Join(dir, "browser-metadata-complete-http.md"), transcript.Bytes(), 0600)
		}
	})
	ctx := context.Background()
	rule := rulelib.Rule{ID: "browser-metadata-source", Kind: "http", Name: "Browser metadata fixture", Engine: "httpx-cff", Severity: "info", Enabled: true, Definition: rulelib.Definition{Service: "http", Product: "BrowserMetadataFixture"}, Fingerprint: json.RawMessage(`{"js":{"fixture.version":"^1$"}}`)}
	callAPI(t, h, "POST", "/api/library", "admin-policy", rule, 201, nil)
	var run Run
	callAPI(t, h, "POST", "/api/runs", "admin-policy", map[string]any{"name": "same frozen selection, two entries", "targets": []string{"http://example.test/first", "http://example.test/second"}, "modes": []string{"http"}, "web_scan_options": webevidence.WebScanOptions{Passive: true, Active: true, JSDOM: true}}, 201, &run)
	var raw []byte
	if err := s.db.QueryRow(ctx, `SELECT rules_snapshot FROM runs WHERE id=$1`, run.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var snapshot ruleSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	cff, needed, err := browserCFF(snapshot)
	if err != nil || !needed || snapshot.BrowserRulesRequired == nil || !*snapshot.BrowserRulesRequired || snapshot.BrowserCFFSHA256 != webevidence.SHA256(cff) {
		t.Fatalf("new run did not freeze exact CFF metadata: needed=%v snapshot=%+v err=%v", needed, snapshot, err)
	}
	rows, err := s.db.Query(ctx, `SELECT id,payload,target_key FROM tasks WHERE run_id=$1 AND type='http' ORDER BY id`, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		id, target string
		payload    []byte
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err = rows.Scan(&e.id, &e.payload, &e.target); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	rows.Close()
	if len(entries) != 2 {
		t.Fatalf("multi-entry fixture has %d tasks", len(entries))
	}
	// A large HTTP rule array is deliberately undecodable after its metadata was
	// frozen. Both parent derivations must still use only the small metadata read.
	if _, err = s.db.Exec(ctx, `UPDATE runs SET rules_snapshot=jsonb_set(rules_snapshot,'{http}','"no full snapshot decode on derive"'::jsonb) WHERE id=$1`, run.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for i, e := range entries {
		var p struct {
			Endpoints []taskEndpoint `json:"endpoints"`
		}
		_ = json.Unmarshal(e.payload, &p)
		response := webevidence.Response{URL: p.Endpoints[0].URL, ConnectIP: "192.0.2.110", Host: "example.test", StatusCode: 200, Completeness: "full", Headers: map[string][]string{"Content-Type": {"text/html"}}}
		probe := webevidence.ProbeResult{Response: response, CFFSHA256: snapshot.BrowserCFFSHA256, Identity: webevidence.ExecutionIdentity{TaskID: e.id, AttemptNo: 1, EntryURL: p.Endpoints[0].URL}}
		evidence, _ := json.Marshal(map[string]any{"probe": probe})
		observation, _ := json.Marshal(Observation{Kind: "http", Target: e.target, IP: response.ConnectIP, URL: response.URL, StatusCode: 200, WorkKey: fmt.Sprintf("entry-%d", i), Evidence: string(evidence)})
		if _, err = tx.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,target_key,observation) VALUES($1,$2,$3,1,0,0,$4,$5)`, newID(), run.ID, e.id, e.target, observation); err != nil {
			t.Fatal(err)
		}
		if err = deriveBrowserTasks(ctx, tx, e.id, run.ID, 1, "frozen-completion", e.payload); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	var consistent bool
	if err = tx.QueryRow(ctx, `SELECT count(*),bool_and(payload->>'browser_cff_sha256'=$2) FROM tasks WHERE run_id=$1 AND payload->>'phase'='browser'`, run.ID, snapshot.BrowserCFFSHA256).Scan(&count, &consistent); err != nil || count != 2 || !consistent {
		t.Fatalf("same-run metadata changed entry scope: count=%d consistent=%v err=%v", count, consistent, err)
	}
	t.Logf("PASS run creation froze CFF sha256=%s; two entry derivations reused metadata without decoding HTTP rules; URL/IP/Host/parent scope unchanged", snapshot.BrowserCFFSHA256)
}
