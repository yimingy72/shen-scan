package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"scanplatform/internal/rulelib"
)

func TestOriginalNucleiCapabilityClaim(t *testing.T) {
	databaseURL := os.Getenv("CONTROL_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTROL_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	adminDB, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := "original_nuclei_test_" + strings.ReplaceAll(newID(), "-", "")
	if _, err = adminDB.Exec(ctx, `CREATE SCHEMA `+schemaName); err != nil {
		adminDB.Close()
		t.Fatal(err)
	}
	parsed, _ := url.Parse(databaseURL)
	query := parsed.Query()
	query.Set("search_path", schemaName)
	parsed.RawQuery = query.Encode()
	server, err := New(ctx, parsed.String(), "admin-original", "join-original")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		_, _ = adminDB.Exec(context.Background(), `DROP SCHEMA `+schemaName+` CASCADE`)
		adminDB.Close()
	})
	handler := server.Handler()
	var run Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-original", map[string]any{
		"name": "original capability", "targets": []string{"192.0.2.21"}, "modes": []string{"http"}, "poc_enabled": true,
	}, http.StatusCreated, &run)

	template := "id: fixture-original\ninfo:\n  name: Fixture original\n  author: shen\n  severity: info\n  metadata:\n    product: FixtureApp\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/health\"]\n    matchers:\n      - type: status\n        status: [200]\n"
	var imported struct {
		Count int `json:"count"`
	}
	callAPI(t, handler, http.MethodPost, "/api/library/import", "admin-original", map[string]any{
		"format": "nuclei", "content": template, "execution_profile": rulelib.NucleiExecutionProfileHTTPBasic,
	}, http.StatusCreated, &imported)
	if imported.Count != 1 {
		t.Fatalf("unexpected import count: %#v", imported)
	}
	var library struct {
		Items []ruleSummary `json:"items"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library?kind=poc&q=fixture-original", "admin-original", nil, http.StatusOK, &library)
	if len(library.Items) != 1 || library.Items[0].ExecutionProfile != rulelib.NucleiExecutionProfileHTTPBasic ||
		library.Items[0].TemplateID != "fixture-original" || library.Items[0].ContentSHA256 == "" || !library.Items[0].ExecutionAvailable {
		t.Fatalf("unexpected imported original rule: %#v", library)
	}
	callAPI(t, handler, http.MethodPatch, "/api/library/"+url.PathEscape(library.Items[0].ID), "admin-original", map[string]any{
		"enabled": true, "expected_revision": 1,
	}, http.StatusOK, nil)
	var snapshotRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-original", map[string]any{
		"name": "original snapshot", "targets": []string{"192.0.2.21"}, "modes": []string{"http"}, "poc_enabled": true,
	}, http.StatusCreated, &snapshotRun)
	var snapshotRaw []byte
	if err = server.db.QueryRow(ctx, `SELECT rules_snapshot FROM runs WHERE id=$1`, snapshotRun.ID).Scan(&snapshotRaw); err != nil {
		t.Fatal(err)
	}
	var snapshot ruleSnapshot
	foundOriginal := false
	if json.Unmarshal(snapshotRaw, &snapshot) == nil {
		for _, rule := range snapshot.POC {
			if rule.ID == library.Items[0].ID && rule.Nuclei != nil && rule.Nuclei.ExecutionProfile == rulelib.NucleiExecutionProfileHTTPBasic {
				foundOriginal = true
			}
		}
	}
	if !foundOriginal {
		t.Fatalf("original rule was not frozen into the run snapshot: %s", snapshotRaw)
	}
	rule, err := rulelib.ParseNucleiOriginal(template)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"endpoint": map[string]any{"ip": "192.0.2.21", "port": 8080, "url": "http://192.0.2.21:8080/app"},
		"rules":    []rulelib.Rule{rule}, "execution_timeout_seconds": 90,
	})
	var targetKey string
	if err = server.db.QueryRow(ctx, `SELECT target_key FROM tasks WHERE run_id=$1 LIMIT 1`, run.ID).Scan(&targetKey); err != nil {
		t.Fatal(err)
	}
	if _, err = server.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES($1,$2,'poc',$3,$4,$5)`,
		newID(), run.ID, payload, "poc-original-capability", targetKey); err != nil {
		t.Fatal(err)
	}
	if _, err = server.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		WorkerID    string `json:"worker_id"`
		WorkerToken string `json:"worker_token"`
	}
	callAPI(t, handler, http.MethodPost, "/api/workers/register", "join-original", map[string]any{
		"instance_id": "original-worker", "hostname": "local", "agent_version": "test", "session_id": "original-session", "spec": map[string]any{},
	}, http.StatusOK, &worker)
	var oldClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "original-session", "supports_confirmed_stop": true, "request_id": "old-agent", "types": []string{"poc"},
	}, http.StatusOK, &oldClaim)
	if oldClaim.Task != nil {
		t.Fatal("agent without original YAML capability claimed the new-format task")
	}
	var newClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "original-session", "supports_confirmed_stop": true, "request_id": "new-agent", "types": []string{"poc"},
		"supports_nuclei_http_original": true,
	}, http.StatusOK, &newClaim)
	if newClaim.Task == nil {
		t.Fatal("capable agent did not claim the original YAML task")
	}
	var claimed struct {
		Rules []rulelib.Rule `json:"rules"`
	}
	if err = json.Unmarshal(newClaim.Task.Payload, &claimed); err != nil || len(claimed.Rules) != 1 ||
		claimed.Rules[0].Nuclei == nil || claimed.Rules[0].Nuclei.ExecutionProfile != rulelib.NucleiExecutionProfileHTTPBasic ||
		claimed.Rules[0].Template != template {
		t.Fatalf("claim did not preserve original YAML: %s err=%v", newClaim.Task.Payload, err)
	}
}
