package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"math/rand"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scanplatform/internal/rulelib"
	"scanplatform/internal/webevidence"
)

func TestPostgresWebScanOptionsDefaultsAndScreenshotIsolation(t *testing.T) {
	for _, mode := range []string{"screenshot-only", "js-partial-image-complete", "js-complete-invalid-image", "js-complete-partial-image"} {
		t.Run(mode, func(t *testing.T) {
			s, h := newPolicyTestServer(t, "web_options")
			ctx := context.Background()
			_, _ = s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`)
			var wire bytes.Buffer
			t.Cleanup(func() {
				if dir := os.Getenv("BROWSER_EVIDENCE_DIR"); dir != "" {
					_ = os.MkdirAll(dir, 0700)
					_ = os.WriteFile(filepath.Join(dir, "options-"+mode+"-full-http.md"), wire.Bytes(), 0600)
				}
			})
			call := func(label, method, path, token string, body any, want int) []byte {
				t.Helper()
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest(method, "http://control.test"+path, bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				if strings.Contains(path, "/screenshot") {
					r.Header.Set("Accept-Encoding", "gzip")
				}
				if token != "" {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				request, _ := httputil.DumpRequest(r, true)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				response, _ := httputil.DumpResponse(w.Result(), !strings.HasPrefix(w.Header().Get("Content-Type"), "image/png"))
				fmt.Fprintf(&wire, "\n### %s\n\n```http\n%s\n%s\n```\n", label, request, response)
				if strings.HasPrefix(w.Header().Get("Content-Type"), "image/png") {
					fmt.Fprintf(&wire, "\nActual PNG response body, complete Base64; decode to reproduce exact bytes (SHA256 %s):\n\n```text\n%s\n```\n", webevidence.SHA256(w.Body.Bytes()), base64.StdEncoding.EncodeToString(w.Body.Bytes()))
					if w.Header().Get("Content-Encoding") != "" {
						t.Fatal("PNG was gzip encoded")
					}
					if w.Header().Get("X-Content-Type-Options") != "nosniff" {
						t.Fatal("PNG endpoint omitted nosniff")
					}
				}
				if w.Code != want {
					t.Fatalf("%s: %d want %d %s", label, w.Code, want, w.Body.String())
				}
				return w.Body.Bytes()
			}
			var worker struct {
				ID    string `json:"worker_id"`
				Token string `json:"worker_token"`
			}
			_ = json.Unmarshal(call("register", "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "options-fixture", "hostname": "local", "session_id": "options"}, 200), &worker)
			call("worker-browser-readiness", "POST", "/api/workers/heartbeat", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "options", "status": "ready", "metrics": map[string]float64{"browser_ready": 0, "browser_processes": 1, "browser_rss_mib": 24.5, "browser_cpu_percent": 12}, "browser_status": webevidence.BrowserCapability{Ready: false, UnavailableReason: "system Chrome missing"}}, 200)
			var reason string
			_ = s.db.QueryRow(ctx, `SELECT spec->>'browser_unavailable_reason' FROM workers WHERE id=$1`, worker.ID).Scan(&reason)
			if reason != "system Chrome missing" {
				t.Fatal("worker browser diagnostics missing from spec")
			}
			// New defaults are explicit, and an all-false request remains all-false.
			var selectionHashes []string
			for _, collectionOnly := range []bool{false, true} {
				var run Run
				body := map[string]any{"name": "defaults", "targets": []string{"http://192.0.2.42/default"}, "modes": []string{"http"}}
				if collectionOnly {
					body["web_scan_options"] = webevidence.WebScanOptions{}
				}
				_ = json.Unmarshal(call("create-default-options", "POST", "/api/runs", "admin-policy", body, 201), &run)
				expected := webevidence.DefaultWebScanOptions()
				if collectionOnly {
					expected = webevidence.WebScanOptions{}
				}
				if run.WebScanOptions == nil || *run.WebScanOptions != expected {
					t.Fatalf("options default/all-false changed: %+v", run.WebScanOptions)
				}
				var raw []byte
				_ = s.db.QueryRow(ctx, `SELECT payload->'web_scan_options' FROM tasks WHERE run_id=$1`, run.ID).Scan(&raw)
				var frozen webevidence.WebScanOptions
				if json.Unmarshal(raw, &frozen) != nil || frozen != expected {
					t.Fatal("options did not freeze into task")
				}
				var taskID string
				var taskPayload []byte
				if err := s.db.QueryRow(ctx, `SELECT id,payload FROM tasks WHERE run_id=$1`, run.ID).Scan(&taskID, &taskPayload); err != nil {
					t.Fatal(err)
				}
				hashTx, err := s.db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = hashTx.Exec(ctx, `UPDATE tasks SET first_started_at=now() WHERE id=$1`, taskID)
				initialized, err := initializeHTTPProgress(ctx, hashTx, taskID, taskPayload)
				if err != nil {
					t.Fatal(err)
				}
				var scope fullHTTPPayload
				_ = json.Unmarshal(initialized, &scope)
				selectionHashes = append(selectionHashes, scope.Progress.SelectionProfileHash)
				_ = hashTx.Rollback(ctx)
				_, _ = s.db.Exec(ctx, `UPDATE runs SET status='paused' WHERE id=$1`, run.ID)
			}
			if len(selectionHashes) != 2 || selectionHashes[0] == selectionHashes[1] {
				t.Fatal("different frozen scan options shared selection scope hash")
			}
			options := &webevidence.WebScanOptions{Screenshot: true, JSDOM: mode != "screenshot-only"}
			snapshot := ruleSnapshot{WebScanOptions: options, WebBrowserProfile: webevidence.BrowserProfile}
			if options.JSDOM {
				snapshot.HTTP = []rulelib.Rule{{ID: "js", Enabled: true, Engine: "httpx-cff", Definition: rulelib.Definition{Product: "JS fixture"}, Fingerprint: json.RawMessage(`{"js":{"fixture":""}}`)}}
			}
			if err := freezeBrowserMetadata(&snapshot); err != nil {
				t.Fatal(err)
			}
			snapshotRaw, _ := json.Marshal(snapshot)
			_, err := s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,rules_snapshot)VALUES('options-run','options','["192.0.2.42"]','{http}','running',$1)`, snapshotRaw)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := taskEndpoint{IP: "192.0.2.42", URL: "http://192.0.2.42/", WorkKey: "fixed-home"}
			parentIdentity := webevidence.ExecutionIdentity{TaskID: "options-parent", AttemptNo: 1, EntryURL: endpoint.URL, EntryID: endpoint.WorkKey}
			probe := webevidence.ProbeResult{Protocol: webevidence.Protocol, Profile: webevidence.FullProfile, Identity: parentIdentity, CFFSHA256: snapshot.BrowserCFFSHA256, Response: webevidence.Response{URL: endpoint.URL, ConnectIP: endpoint.IP, Host: endpoint.IP, StatusCode: 200, Completeness: "full", Headers: map[string][]string{"Content-Type": {"text/html"}}}}
			evidence, _ := json.Marshal(map[string]any{"probe": probe, "fingerprint": webevidence.MatchResult{Active: &webevidence.ActiveResult{Complete: true}}})
			base := Observation{Kind: "http", Target: endpoint.IP, IP: endpoint.IP, Port: 80, URL: endpoint.URL, WorkKey: endpoint.WorkKey, StatusCode: 200, Title: "base remains visible", Coverage: "complete", HTTPProgress: &webevidence.EntryProgress{Complete: true}, WebScanOptions: options, Evidence: string(evidence)}
			raw, _ := json.Marshal(base)
			payload, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{endpoint}, "web_scan_options": options, "web_browser_profile": webevidence.BrowserProfile})
			_, err = s.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key,state,attempt_no,accepted_attempt_no,completion_id,coverage)VALUES('options-parent','options-run','http',$1,'parent','192.0.2.42','completed',1,1,'parent-completion','complete')`, payload)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = s.db.Exec(ctx, `INSERT INTO task_targets(task_id,target_key)VALUES('options-parent','192.0.2.42')`)
			_, err = s.db.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,target_key,observation)VALUES('options-parent-asset','options-run','options-parent',1,0,0,'192.0.2.42',$1)`, raw)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := s.db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = deriveBrowserTasks(ctx, tx, "options-parent", "options-run", 1, "parent-completion", payload); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			claim := func(id string, support bool) *Task {
				var out struct {
					Task *Task `json:"task"`
				}
				_ = json.Unmarshal(call(id, "POST", "/api/tasks/claim", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "options", "request_id": id, "types": []string{"http"}, "http_phase": "browser", "web_browser_profile": webevidence.BrowserProfile, "supports_confirmed_stop": true, "supports_http_request_budget": true, "supports_web_scan_options": support}, 200), &out)
				return out.Task
			}
			if claim("old-agent-must-not-ignore-options", false) != nil {
				t.Fatal("old worker claimed selected options")
			}
			child := claim("new-agent-screenshot-child", true)
			if child == nil {
				t.Fatal("screenshot-only did not derive without CFF/browser rules")
			}
			var assignment webevidence.BrowserAssignment
			_ = json.Unmarshal(child.Payload, &assignment)
			picture := image.NewRGBA(image.Rect(0, 0, 400, 300))
			_, _ = rand.New(rand.NewSource(7)).Read(picture.Pix)
			var pngData bytes.Buffer
			_ = png.Encode(&pngData, picture)
			if pngData.Len() < 64<<10 || pngData.Len() > webevidence.MaxScreenshot {
				t.Fatal("fixture must exercise >64KiB PNG upload under image cap")
			}
			identity := parentIdentity
			identity.TaskID, identity.AttemptNo, identity.Segment = child.ID, child.AttemptNo, 0
			result := webevidence.BrowserResult{ID: "options-result", Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, Identity: identity, Parent: assignment.BrowserParent, CFFSHA256: assignment.BrowserCFFSHA256, Engine: "fixture", PlanSHA256: webevidence.SHA256([]byte("plan")), TotalRules: 1, EvaluatedRules: 1, Complete: true, JSDOM: &webevidence.WebStage{State: "complete"}, Screenshot: &webevidence.BrowserScreenshot{WebStage: webevidence.WebStage{State: "complete"}, PNG: pngData.Bytes()}}
			if options.JSDOM {
				result.Engine = "fixture-js+fixture-screenshot"
				result.Matches = []webevidence.Match{{Name: "JS independent positive", Engine: "fixture-js"}}
			}
			if mode == "js-partial-image-complete" {
				result.JSDOM.State = "partial"
				result.JSDOM.Error = "unsupported JS fixture"
				result.Complete = false
			}
			if mode == "js-complete-invalid-image" {
				result.Screenshot.PNG = []byte("invalid PNG")
				result.Complete = false
			}
			if mode == "js-complete-partial-image" {
				result.Screenshot.State = "partial"
				result.Screenshot.Error = "partial visual resource"
				result.Complete = false
			}
			resultRaw, _ := json.Marshal(map[string]any{"browser": result})
			item := Observation{Kind: "http", Target: endpoint.IP, IP: endpoint.IP, URL: endpoint.URL, Evidence: string(resultRaw)}
			batchBody := map[string]any{"worker_id": worker.ID, "session_id": "options", "attempt_no": child.AttemptNo, "batch_seq": 0, "items": []Observation{item}}
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET lease_until=now()-interval '1 second' WHERE id=$1`, child.ID)
			call("expired-image-result-fenced", "POST", "/api/tasks/"+child.ID+"/batches", worker.Token, batchBody, 409)
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET lease_until=now()+interval '1 minute' WHERE id=$1`, child.ID)
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET completion_id='different-parent' WHERE id='options-parent'`)
			call("different-parent-image-fenced", "POST", "/api/tasks/"+child.ID+"/batches", worker.Token, batchBody, 422)
			_, _ = s.db.Exec(ctx, `UPDATE tasks SET completion_id='parent-completion' WHERE id='options-parent'`)
			call("accept-image-independent-stages", "POST", "/api/tasks/"+child.ID+"/batches", worker.Token, batchBody, 200)
			var assetID string
			_ = s.db.QueryRow(ctx, `SELECT id FROM assets WHERE task_id=$1`, child.ID).Scan(&assetID)
			imagePath := "/api/observations/" + assetID + "/screenshot"
			call("uncompleted-image-not-visible", "GET", imagePath, "admin-policy", nil, 404)
			call("complete-child", "POST", "/api/tasks/"+child.ID+"/complete", worker.Token, map[string]any{"worker_id": worker.ID, "session_id": "options", "attempt_no": child.AttemptNo, "last_batch_seq": 0}, 200)
			call("image-requires-auth", "GET", imagePath, "", nil, 401)
			wantImage := mode != "js-complete-invalid-image"
			if wantImage {
				data := call("full-image", "GET", imagePath, "admin-policy", nil, 200)
				if !bytes.Equal(data, pngData.Bytes()) {
					t.Fatal("stored image bytes changed")
				}
				thumb := call("thumbnail-image", "GET", imagePath+"?thumbnail=true", "admin-policy", nil, 200)
				cfg, e := png.DecodeConfig(bytes.NewReader(thumb))
				if e != nil || cfg.Width != 240 || cfg.Height != 180 {
					t.Fatalf("bad thumbnail: %+v %v", cfg, e)
				}
			} else {
				call("invalid-png-not-served", "GET", imagePath, "admin-policy", nil, 404)
			}
			var detail Asset
			_ = json.Unmarshal(call("detail-no-base64", "GET", "/api/observations/"+assetID, "admin-policy", nil, 200), &detail)
			if detail.Screenshot == nil || detail.StatusCode != 200 || strings.Contains(detail.Evidence, `"png"`) {
				t.Fatal("image missing metadata, base lost, or PNG leaked into indexed evidence")
			}
			if options.JSDOM {
				wantState := "complete"
				if mode == "js-partial-image-complete" {
					wantState = "partial"
				}
				if detail.Browser == nil || detail.Browser.State != wantState {
					t.Fatal("screenshot failure overwrote independent JS state")
				}
			} else if detail.Browser != nil {
				t.Fatal("screenshot-only displayed a JS/DOM stage")
			}
			var batchText string
			_ = s.db.QueryRow(ctx, `SELECT items::text FROM task_batches WHERE task_id=$1`, child.ID).Scan(&batchText)
			if strings.Contains(batchText, `\"png\"`) {
				t.Fatal("PNG duplicated in task JSON")
			}
			var status string
			_ = s.db.QueryRow(ctx, `SELECT status FROM runs WHERE id='options-run'`).Scan(&status)
			wantedStatus := "partial"
			if mode == "screenshot-only" {
				wantedStatus = "completed"
			}
			if status != wantedStatus {
				t.Fatalf("run status %s wanted %s", status, wantedStatus)
			}
			// Existing claim receipts intentionally restrict task deletion; remove only
			// this disposable fixture receipt before checking screenshot cascade.
			_, _ = s.db.Exec(ctx, `DELETE FROM claim_requests WHERE task_id=$1`, child.ID)
			if _, err = s.db.Exec(ctx, `DELETE FROM tasks WHERE id=$1`, child.ID); err != nil {
				t.Fatal(err)
			}
			var screenshots int
			_ = s.db.QueryRow(ctx, `SELECT count(*) FROM http_screenshots WHERE run_id='options-run'`).Scan(&screenshots)
			if screenshots != 0 {
				t.Fatal("deleting task left screenshot bytes")
			}
			call("deleted-image-not-served", "GET", imagePath, "admin-policy", nil, 404)
			t.Logf("PASS %s: independent stages, >64KiB PNG, authenticated original/240px thumbnail, options capability fence, parent/lease fence, no JSON binary, cascade cleanup", mode)
		})
	}
}
