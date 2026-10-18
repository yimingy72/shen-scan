package control

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/webevidence"
)

func TestFingerprintTaskSnapshotAndLeaseDownload(t *testing.T) {
	server, handler := newPolicyTestServer(t, "fingerprint_task_test")
	ctx := context.Background()
	if binary := os.Getenv("TEST_FINGERPRINT_BINARY"); binary != "" {
		t.Setenv("FINGERPRINT_CHECKER_BINARY", binary)
	} else {
		t.Skip("TEST_FINGERPRINT_BINARY is not set")
	}
	outputDir := os.Getenv("FINGERPRINT_TASK_EVIDENCE_DIR")
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	sequence := 0
	request := func(label, method, path, token string, body any, expected int) *httptest.ResponseRecorder {
		t.Helper()
		var encoded []byte
		if body != nil {
			var err error
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(encoded))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		if outputDir != "" {
			requestBytes, err := httputil.DumpRequest(r, true)
			if err != nil {
				t.Fatal(err)
			}
			// The JSON decoder consumed request.Body; reconstruct the exact sent bytes.
			if body != nil {
				r.Body = io.NopCloser(bytes.NewReader(encoded))
				requestBytes, err = httputil.DumpRequest(r, true)
				if err != nil {
					t.Fatal(err)
				}
			}
			responseBytes, err := httputil.DumpResponse(response.Result(), true)
			if err != nil {
				t.Fatal(err)
			}
			sequence++
			if err = os.WriteFile(filepath.Join(outputDir, fmt.Sprintf("%02d-%s.http", sequence, label)), append(append(requestBytes, '\n'), responseBytes...), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if response.Code != expected {
			t.Fatalf("%s: got %d want %d: %s", label, response.Code, expected, response.Body.String())
		}
		return response
	}
	createRun := func(name string) Run {
		t.Helper()
		response := request("create-run-"+name, "POST", "/api/runs", "admin-policy", map[string]any{"name": name, "targets": []string{"https://" + name + ".example.com/"}, "modes": []string{"http"}}, 201)
		var run Run
		if err := json.Unmarshal(response.Body.Bytes(), &run); err != nil {
			t.Fatal(err)
		}
		return run
	}
	publish := func(revision string) []byte {
		t.Helper()
		input, _ := fingerprintStorageFixture(t, revision)
		data, err := prepareFingerprintBundle(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if err = server.applyFingerprintBundle(ctx, input, data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	dataA := publish(strings.Repeat("a", 40))
	runA := createRun("bundle-a")
	dataB := publish(strings.Repeat("b", 40))
	runB := createRun("bundle-b")
	expectedData := map[string][]byte{runA.ID: dataA, runB.ID: dataB}
	for runID, data := range expectedData {
		var snapshotDigest, taskDigest, schema string
		if err := server.db.QueryRow(ctx, `SELECT r.rules_snapshot->>'fingerprint_bundle',t.payload->>'fingerprint_bundle',t.payload->>'fingerprint_bundle_schema' FROM runs r JOIN tasks t ON t.run_id=r.id WHERE r.id=$1`, runID).Scan(&snapshotDigest, &taskDigest, &schema); err != nil {
			t.Fatal(err)
		}
		if snapshotDigest != fingerprintbundle.Digest(data) || snapshotDigest != taskDigest || schema != fingerprintbundle.Schema {
			t.Fatalf("run did not pin package: %s %s %s", snapshotDigest, taskDigest, schema)
		}
	}
	if _, err := server.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	type worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	register := func(name string) worker {
		t.Helper()
		response := request("register-"+name, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": name, "hostname": "local", "agent_version": "test", "session_id": name + "-session", "spec": map[string]any{}}, 200)
		var w worker
		if err := json.Unmarshal(response.Body.Bytes(), &w); err != nil {
			t.Fatal(err)
		}
		return w
	}
	oldWorker, newWorker := register("embedded-only"), register("snapshot-capable")
	claimBody := func(w worker, session, requestID, schema string) map[string]any {
		body := map[string]any{"worker_id": w.ID, "session_id": session, "request_id": requestID, "types": []string{"http"}, "service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile, "fingerprint_bundle": webevidence.FingerprintBundle, "supports_confirmed_stop": true, "supports_http_request_budget": true, "use_rule_sets": true, "supports_httpx_cff": true}
		if schema != "" {
			body["fingerprint_bundle_schema"] = schema
		}
		return body
	}
	var claimed struct {
		Task *Task `json:"task"`
	}
	response := request("embedded-worker-no-task", "POST", "/api/tasks/claim", oldWorker.Token, claimBody(oldWorker, "embedded-only-session", "old-claim", ""), 200)
	if err := json.Unmarshal(response.Body.Bytes(), &claimed); err != nil || claimed.Task != nil {
		t.Fatalf("embedded worker claimed external task: %s", response.Body.String())
	}
	tasks := map[string]Task{}
	for index := 0; index < 2; index++ {
		requestID := fmt.Sprintf("snapshot-claim-%d", index)
		response = request("claim-"+requestID, "POST", "/api/tasks/claim", newWorker.Token, claimBody(newWorker, "snapshot-capable-session", requestID, fingerprintbundle.Schema), 200)
		claimed.Task = nil
		if err := json.Unmarshal(response.Body.Bytes(), &claimed); err != nil || claimed.Task == nil {
			t.Fatalf("capable worker got no task: %s", response.Body.String())
		}
		task := *claimed.Task
		tasks[task.RunID] = task
		expected, ok := expectedData[task.RunID]
		if !ok {
			t.Fatalf("unexpected run %s", task.RunID)
		}
		query := url.Values{"worker_id": []string{newWorker.ID}, "session_id": []string{"snapshot-capable-session"}, "attempt_no": []string{fmt.Sprint(task.AttemptNo)}}
		path := "/api/tasks/" + task.ID + "/fingerprint-bundle?" + query.Encode()
		download := request("download-"+requestID, "GET", path, newWorker.Token, nil, 200)
		if !bytes.Equal(download.Body.Bytes(), expected) || download.Header().Get("X-Content-SHA256") != fingerprintbundle.Digest(expected) {
			t.Fatal("task download changed pinned package bytes")
		}
		// Replaying the same claim with downgraded capability must not return a task.
		response = request("replay-without-schema-"+requestID, "POST", "/api/tasks/claim", newWorker.Token, claimBody(newWorker, "snapshot-capable-session", requestID, ""), 200)
		claimed.Task = nil
		if err := json.Unmarshal(response.Body.Bytes(), &claimed); err != nil || claimed.Task != nil {
			t.Fatalf("idempotent replay bypassed schema compatibility: %s", response.Body.String())
		}
	}
	if len(tasks) != 2 {
		t.Fatal("capable worker did not receive both snapshot runs")
	}
	taskA := tasks[runA.ID]
	identity := url.Values{"worker_id": []string{newWorker.ID}, "session_id": []string{"snapshot-capable-session"}, "attempt_no": []string{fmt.Sprint(taskA.AttemptNo)}}
	downloadPath := func() string { return "/api/tasks/" + taskA.ID + "/fingerprint-bundle?" + identity.Encode() }
	identity.Set("session_id", "another-session")
	request("reject-other-session", "GET", downloadPath(), newWorker.Token, nil, 401)
	identity.Set("session_id", "snapshot-capable-session")
	identity.Set("attempt_no", fmt.Sprint(taskA.AttemptNo+1))
	request("reject-other-attempt", "GET", downloadPath(), newWorker.Token, nil, 409)
	identity.Set("attempt_no", fmt.Sprint(taskA.AttemptNo))
	identity.Set("worker_id", oldWorker.ID)
	identity.Set("session_id", "embedded-only-session")
	request("reject-other-worker", "GET", downloadPath(), oldWorker.Token, nil, 409)
	identity.Set("worker_id", newWorker.ID)
	identity.Set("session_id", "snapshot-capable-session")
	if _, err := server.db.Exec(ctx, `UPDATE tasks SET lease_until=now()-interval '1 second' WHERE id=$1`, taskA.ID); err != nil {
		t.Fatal(err)
	}
	request("reject-expired-lease", "GET", downloadPath(), newWorker.Token, nil, 409)
	// Raw export contains exactly the four committed files plus the generated manifest.
	export := request("raw-source-export", "GET", "/api/library/sources/fingers/export?revision="+strings.Repeat("a", 40), "admin-policy", nil, 200)
	archive, err := zip.NewReader(bytes.NewReader(export.Body.Bytes()), int64(export.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := fingerprintbundle.Decode(dataA)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, file := range archive.File {
		if file.Name == sourceManifestPath {
			continue
		}
		expected, ok := pkg.Files[file.Name]
		if !ok || seen[file.Name] {
			t.Fatalf("unexpected/duplicate exported file %s", file.Name)
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Equal(raw, expected.Raw) {
			t.Fatalf("export changed original %s", file.Name)
		}
		seen[file.Name] = true
	}
	if len(seen) != 4 || len(archive.File) != 5 {
		t.Fatalf("export contained %d data files, %d entries", len(seen), len(archive.File))
	}
	t.Logf("PASS: runA=%s bundleA=%s; runB=%s bundleB=%s; embedded claim blocked; schema claims+downloads exact; downgraded replay/session/attempt/other worker/expired lease rejected; export=4 exact raw resources+manifest", runA.ID, fingerprintbundle.Digest(dataA), runB.ID, fingerprintbundle.Digest(dataB))
}
