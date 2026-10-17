package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"scanplatform/internal/rulelib"
)

func newPolicyTestServer(t *testing.T, prefix string) (*Server, http.Handler) {
	t.Helper()
	databaseURL := os.Getenv("CONTROL_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTROL_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	adminDB, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := prefix + "_" + strings.ReplaceAll(newID(), "-", "")
	if _, err = adminDB.Exec(ctx, `CREATE SCHEMA `+schemaName); err != nil {
		adminDB.Close()
		t.Fatal(err)
	}
	u, _ := url.Parse(databaseURL)
	query := u.Query()
	query.Set("search_path", schemaName)
	u.RawQuery = query.Encode()
	server, err := New(ctx, u.String(), "admin-policy", "join-policy")
	if err != nil {
		adminDB.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		_, _ = adminDB.Exec(context.Background(), `DROP SCHEMA `+schemaName+` CASCADE`)
		adminDB.Close()
	})
	return server, server.Handler()
}

func testPOCRule(id string, appliesTo []string) rulelib.Rule {
	return rulelib.Rule{ID: id, Kind: "poc", Name: id, Engine: "native", Severity: "info", Enabled: true,
		AppliesTo: appliesTo, Definition: rulelib.Definition{Condition: "and", Requests: []rulelib.Request{{
			Method: "GET", Path: "/health", Condition: "and", Matchers: []rulelib.Matcher{{Part: "status", Type: "status", Status: []int{200}}},
		}}}}
}

func TestPOCFingerprintPolicyAndLateServiceReconciliation(t *testing.T) {
	server, handler := newPolicyTestServer(t, "poc_policy_test")
	ctx := context.Background()
	bound, manual := testPOCRule("poc-test-grafana", []string{"Grafana"}), testPOCRule("poc-test-manual", nil)
	callAPI(t, handler, http.MethodPost, "/api/library", "admin-policy", bound, http.StatusCreated, &bound)
	callAPI(t, handler, http.MethodPost, "/api/library", "admin-policy", manual, http.StatusCreated, &manual)

	var defaultRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-policy", map[string]any{
		"name": "default fingerprint policy", "targets": []string{"policy.example.com"}, "modes": []string{"http"}, "poc_enabled": true,
	}, http.StatusCreated, &defaultRun)
	var snapshotRaw []byte
	if err := server.db.QueryRow(ctx, `SELECT rules_snapshot FROM runs WHERE id=$1`, defaultRun.ID).Scan(&snapshotRaw); err != nil {
		t.Fatal(err)
	}
	var snapshot ruleSnapshot
	if json.Unmarshal(snapshotRaw, &snapshot) != nil || snapshot.POCPolicy != "fingerprint" || len(snapshot.ExplicitPOCRuleIDs) != 0 {
		t.Fatalf("default snapshot policy=%+v", snapshot)
	}
	boundFound, manualFound := false, false
	for _, rule := range snapshot.POC {
		if len(rule.AppliesTo) == 0 {
			t.Fatalf("default snapshot included unbound rule %s", rule.ID)
		}
		boundFound = boundFound || rule.ID == bound.ID
		manualFound = manualFound || rule.ID == manual.ID
	}
	if !boundFound || manualFound {
		t.Fatalf("default snapshot bound/manual=%t/%t", boundFound, manualFound)
	}
	var explicitRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-policy", map[string]any{
		"name": "explicit rules", "targets": []string{"explicit.example.com"}, "modes": []string{"http"}, "poc_enabled": true,
		"poc_rule_ids": []string{bound.ID, manual.ID},
	}, http.StatusCreated, &explicitRun)
	if err := server.db.QueryRow(ctx, `SELECT rules_snapshot FROM runs WHERE id=$1`, explicitRun.ID).Scan(&snapshotRaw); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(snapshotRaw, &snapshot) != nil || len(snapshot.POC) != 2 || len(snapshot.ExplicitPOCRuleIDs) != 2 {
		t.Fatalf("explicit snapshot=%+v", snapshot)
	}

	policySnapshot := ruleSnapshot{POC: []rulelib.Rule{bound}, POCPolicy: "fingerprint", ExplicitPOCRuleIDs: []string{bound.ID}}
	insertRun := func(name string, endpoints []taskEndpoint, observations []Observation, completed bool) (string, string, []byte) {
		t.Helper()
		runID, taskID := newID(), newID()
		rulesJSON, _ := json.Marshal(policySnapshot)
		payload, _ := json.Marshal(map[string]any{"endpoints": endpoints, "timeout_seconds": 12, "execution_timeout_seconds": 180})
		state := "leased"
		if completed {
			state = "completed"
		}
		if _, err := server.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,poc_enabled,rules_snapshot)
			VALUES($1,$2,'["198.51.100.40"]','{http}','running',true,$3)`, runID, name, rulesJSON); err != nil {
			t.Fatal(err)
		}
		if _, err := server.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,state,attempt_no,derived_key,target_key)
			VALUES($1,$2,'http',$3,$4,1,'http-parent','198.51.100.40')`, taskID, runID, payload, state); err != nil {
			t.Fatal(err)
		}
		if _, err := server.db.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) VALUES($1,'198.51.100.40')`, taskID); err != nil {
			t.Fatal(err)
		}
		for index, observation := range observations {
			raw, _ := json.Marshal(observation)
			if _, err := server.db.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,target_key,observation)
				VALUES($1,$2,$3,1,0,$4,'198.51.100.40',$5)`, newID(), runID, taskID, index, raw); err != nil {
				t.Fatal(err)
			}
		}
		return runID, taskID, payload
	}
	derive := func(runID, taskID, taskType string, attempt int, payload []byte) {
		t.Helper()
		tx, err := server.db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err = derivePOCTasks(ctx, tx, taskID, runID, attempt, taskType, "198.51.100.40", payload); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	endpoints := []taskEndpoint{{IP: "198.51.100.40", Port: 8080}, {IP: "198.51.100.40", Port: 8081}}
	runID, httpTaskID, httpPayload := insertRun("HTTP product routing", endpoints, []Observation{
		{Kind: "http", Target: "198.51.100.40", IP: "198.51.100.40", Port: 8080, URL: "http://198.51.100.40:8080/", StatusCode: 200,
			Technologies: []Technology{{Name: "Grafana"}}},
		{Kind: "http", Target: "198.51.100.40", IP: "198.51.100.40", Port: 8081, URL: "http://198.51.100.40:8081/", StatusCode: 200,
			Technologies: []Technology{{Name: "Unrecognized Product"}}},
	}, false)
	derive(runID, httpTaskID, "http", 1, httpPayload)
	var count int
	var derivedPayload []byte
	if err := server.db.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE run_id=$1 AND type='poc'`, runID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("HTTP fingerprint derived=%d err=%v", count, err)
	}
	if err := server.db.QueryRow(ctx, `SELECT payload FROM tasks WHERE run_id=$1 AND type='poc' LIMIT 1`, runID).Scan(&derivedPayload); err != nil {
		t.Fatal(err)
	}
	secondHTTPTask := newID()
	secondHTTPPayload, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{{IP: "198.51.100.40", Port: 8080, URL: "http://198.51.100.40:8080/admin"}}})
	if _, err := server.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,state,attempt_no,derived_key,target_key)
		VALUES($1,$2,'http',$3,'leased',1,'http-parent-second','198.51.100.40')`, secondHTTPTask, runID, secondHTTPPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := server.db.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) VALUES($1,'198.51.100.40')`, secondHTTPTask); err != nil {
		t.Fatal(err)
	}
	secondObservation, _ := json.Marshal(Observation{Kind: "http", Target: "http://198.51.100.40:8080/admin", IP: "198.51.100.40", Port: 8080,
		URL: "http://198.51.100.40:8080/admin", StatusCode: 200, Technologies: []Technology{{Name: "Grafana"}}})
	if _, err := server.db.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,target_key,observation)
		VALUES($1,$2,$3,1,0,0,'198.51.100.40',$4)`, newID(), runID, secondHTTPTask, secondObservation); err != nil {
		t.Fatal(err)
	}
	derive(runID, secondHTTPTask, "http", 1, secondHTTPPayload)
	if err := server.db.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE run_id=$1 AND type='poc'`, runID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("same-origin second HTTP parent derived=%d err=%v", count, err)
	}
	var trace struct {
		Endpoint        taskEndpoint `json:"endpoint"`
		MatchedProducts []string     `json:"matched_products"`
		TriggerReason   string       `json:"trigger_reason"`
	}
	if json.Unmarshal(derivedPayload, &trace) != nil || trace.Endpoint.Port != 8080 || len(trace.MatchedProducts) != 1 || trace.MatchedProducts[0] != "Grafana" || trace.TriggerReason != "http_technology" {
		t.Fatalf("HTTP trigger trace=%+v", trace)
	}

	lateRunID, lateHTTPTaskID, lateHTTPPayload := insertRun("late service routing", []taskEndpoint{{IP: "198.51.100.40", Port: 8080}}, []Observation{{
		Kind: "http", Target: "198.51.100.40", IP: "198.51.100.40", Port: 8080, URL: "http://198.51.100.40:8080/", StatusCode: 200,
	}}, true)
	derive(lateRunID, lateHTTPTaskID, "http", 1, lateHTTPPayload)
	insertService := func(port int, state string) (string, []byte) {
		t.Helper()
		taskID := newID()
		payload, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{{IP: "198.51.100.40", Port: port}}, "timeout_seconds": 5})
		if _, err := server.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,state,attempt_no,derived_key,target_key)
			VALUES($1,$2,'service',$3,$4,1,$5,'198.51.100.40')`, taskID, lateRunID, payload, state, "service-"+strconv.Itoa(port)); err != nil {
			t.Fatal(err)
		}
		if _, err := server.db.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) VALUES($1,'198.51.100.40')`, taskID); err != nil {
			t.Fatal(err)
		}
		observation, _ := json.Marshal(Observation{Kind: "service", Target: "198.51.100.40", IP: "198.51.100.40", Port: port, Product: "Grafana"})
		if _, err := server.db.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,target_key,observation)
			VALUES($1,$2,$3,1,0,0,'198.51.100.40',$4)`, newID(), lateRunID, taskID, observation); err != nil {
			t.Fatal(err)
		}
		return taskID, payload
	}
	wrongTask, wrongPayload := insertService(9090, "leased")
	derive(lateRunID, wrongTask, "service", 1, wrongPayload)
	if err := server.db.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE run_id=$1 AND type='poc'`, lateRunID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cross-port service derived=%d err=%v", count, err)
	}
	if _, err := server.db.Exec(ctx, `UPDATE tasks SET state='completed' WHERE id=$1`, wrongTask); err != nil {
		t.Fatal(err)
	}
	rightTask, rightPayload := insertService(8080, "leased")
	derive(lateRunID, rightTask, "service", 1, rightPayload)
	if err := server.db.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE run_id=$1 AND type='poc'`, lateRunID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("same-port late service derived=%d err=%v", count, err)
	}
	if err := server.db.QueryRow(ctx, `SELECT payload FROM tasks WHERE run_id=$1 AND type='poc' LIMIT 1`, lateRunID).Scan(&derivedPayload); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(derivedPayload, &trace) != nil || trace.TriggerReason != "service_product" || len(trace.MatchedProducts) != 1 || trace.MatchedProducts[0] != "Grafana" {
		t.Fatalf("service trigger trace=%+v", trace)
	}
}

func TestLibrarySoftDeleteRestoreAndBatchAtomicity(t *testing.T) {
	server, handler := newPolicyTestServer(t, "library_delete_test")
	ctx := context.Background()
	ruleA, ruleB := testPOCRule("poc-delete-a", []string{"Grafana"}), testPOCRule("poc-delete-b", nil)
	callAPI(t, handler, http.MethodPost, "/api/library", "admin-policy", ruleA, http.StatusCreated, &ruleA)
	callAPI(t, handler, http.MethodPost, "/api/library", "admin-policy", ruleB, http.StatusCreated, &ruleB)
	callAPI(t, handler, http.MethodPost, "/api/library/delete", "admin-policy", map[string]any{"items": []map[string]any{
		{"id": ruleA.ID, "expected_revision": ruleA.Revision}, {"id": ruleB.ID, "expected_revision": ruleB.Revision + 1},
	}}, http.StatusConflict, nil)
	callAPI(t, handler, http.MethodGet, "/api/library/"+ruleA.ID, "admin-policy", nil, http.StatusOK, nil)
	callAPI(t, handler, http.MethodGet, "/api/library/"+ruleB.ID, "admin-policy", nil, http.StatusOK, nil)
	var deleted struct {
		DeletedCount int `json:"deleted_count"`
	}
	callAPI(t, handler, http.MethodPost, "/api/library/delete", "admin-policy", map[string]any{"items": []map[string]any{
		{"id": ruleA.ID, "expected_revision": ruleA.Revision}, {"id": ruleB.ID, "expected_revision": ruleB.Revision},
	}}, http.StatusOK, &deleted)
	if deleted.DeletedCount != 2 {
		t.Fatalf("deleted_count=%d", deleted.DeletedCount)
	}
	callAPI(t, handler, http.MethodGet, "/api/library/"+ruleA.ID, "admin-policy", nil, http.StatusNotFound, nil)
	content, _ := json.Marshal(ruleA)
	var restored struct {
		Items []rulelib.Rule `json:"items"`
	}
	callAPI(t, handler, http.MethodPost, "/api/library/import", "admin-policy", map[string]any{"format": "json", "content": string(content)}, http.StatusCreated, &restored)
	if len(restored.Items) != 1 || restored.Items[0].Revision != ruleA.Revision+1 || restored.Items[0].Enabled {
		t.Fatalf("restored rule=%+v", restored.Items)
	}

	var builtin rulelib.Rule
	callAPI(t, handler, http.MethodGet, "/api/library/poc-wordpress-readme", "admin-policy", nil, http.StatusOK, &builtin)
	callAPI(t, handler, http.MethodDelete, "/api/library/"+builtin.ID+"?expected_revision="+strconv.Itoa(builtin.Revision), "admin-policy", nil, http.StatusOK, nil)
	if _, err := server.db.Exec(ctx, `UPDATE rule_library SET seed_version=0 WHERE id=$1`, builtin.ID); err != nil {
		t.Fatal(err)
	}
	if err := seedRuleLibrary(ctx, server.db); err != nil {
		t.Fatal(err)
	}
	callAPI(t, handler, http.MethodGet, "/api/library/"+builtin.ID, "admin-policy", nil, http.StatusNotFound, nil)

	var legacy rulelib.Rule
	callAPI(t, handler, http.MethodGet, "/api/library/poc-grafana-login", "admin-policy", nil, http.StatusOK, &legacy)
	legacy.AppliesTo, legacy.Enabled, legacy.Revision, legacy.Definition.Product = nil, false, 4, "user-edited-grafana"
	legacyRaw, _ := json.Marshal(legacy)
	if _, err := server.db.Exec(ctx, `UPDATE rule_library SET rule=$2,seed_version=0 WHERE id=$1`, legacy.ID, legacyRaw); err != nil {
		t.Fatal(err)
	}
	if err := seedRuleLibrary(ctx, server.db); err != nil {
		t.Fatal(err)
	}
	var upgraded rulelib.Rule
	callAPI(t, handler, http.MethodGet, "/api/library/"+legacy.ID, "admin-policy", nil, http.StatusOK, &upgraded)
	if upgraded.Revision != 5 || upgraded.Enabled || upgraded.Definition.Product != "user-edited-grafana" || len(upgraded.AppliesTo) == 0 {
		t.Fatalf("seed upgrade overwrote user fields or missed binding: %+v", upgraded)
	}

	var products struct {
		Items []string `json:"items"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library/products", "admin-policy", nil, http.StatusOK, &products)
	if len(products.Items) == 0 {
		t.Fatal("library products is empty")
	}
	var selected struct {
		Items []rulelib.Rule `json:"items"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library/export?ids="+ruleA.ID+"&kind=poc&enabled=false", "admin-policy", nil, http.StatusOK, &selected)
	if len(selected.Items) != 1 || selected.Items[0].ID != ruleA.ID {
		t.Fatalf("selected export=%+v", selected.Items)
	}
}
