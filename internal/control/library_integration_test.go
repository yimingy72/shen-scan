package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"scanplatform/internal/webevidence"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"scanplatform/internal/rulelib"
)

func TestRuleLibraryAndPOCClosure(t *testing.T) {
	databaseURL := os.Getenv("CONTROL_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTROL_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	adminDB, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := "library_test_" + strings.ReplaceAll(newID(), "-", "")
	if _, err = adminDB.Exec(ctx, `CREATE SCHEMA `+schemaName); err != nil {
		adminDB.Close()
		t.Fatal(err)
	}
	u, _ := url.Parse(databaseURL)
	query := u.Query()
	query.Set("search_path", schemaName)
	u.RawQuery = query.Encode()
	server, err := New(ctx, u.String(), "admin-library", "join-library")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Close()
		_, _ = adminDB.Exec(context.Background(), `DROP SCHEMA `+schemaName+` CASCADE`)
		adminDB.Close()
	})
	handler := server.Handler()

	var listed struct {
		Items         []ruleSummary    `json:"items"`
		Counts        map[string]int64 `json:"counts"`
		PurposeCounts map[string]int64 `json:"purpose_counts"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library?kind=poc&enabled=true", "admin-library", nil, http.StatusOK, &listed)
	builtinCounts := map[string]int64{}
	purposeCounts := map[string]int64{}
	for _, rule := range rulelib.Builtins() {
		builtinCounts[rule.Kind]++
		if rule.Kind == "poc" {
			purposeCounts[rulelib.VerificationPurpose(rule)]++
		}
	}
	if int64(len(listed.Items)) != builtinCounts["poc"] || listed.Counts["http"] != builtinCounts["http"] ||
		listed.Counts["port"] != builtinCounts["port"] || listed.Counts["poc"] != builtinCounts["poc"] ||
		listed.PurposeCounts["discovery"] != purposeCounts["discovery"] || listed.PurposeCounts["verification"] != purposeCounts["verification"] {
		t.Fatalf("unexpected seeded library counts: %+v items=%d", listed.Counts, len(listed.Items))
	}
	reviewed := rulelib.ReviewedVerifications()[0]
	reviewedRaw, _ := json.Marshal(reviewed)
	if _, err = server.db.Exec(ctx, `UPDATE rule_sources SET status='ready',revision=$2,license='MIT',license_text='MIT License' WHERE id=$1`,
		reviewed.Verification.SourcePin.SourceID, reviewed.Verification.SourcePin.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = server.db.Exec(ctx, `INSERT INTO rule_library(id,rule,seed_version,source_id,upstream_hash)
		VALUES($1,$2,$3,$4,$5)`, reviewed.ID, reviewedRaw, currentRuleSeedVersion,
		reviewed.Verification.SourcePin.SourceID, sourceRuleHash(reviewed)); err != nil {
		t.Fatal(err)
	}
	purposeCounts["verification"] = 1
	var verifications struct {
		Items []ruleSummary `json:"items"`
		Total int64         `json:"total"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library?kind=poc&purpose=verification&limit=500", "admin-library", nil, http.StatusOK, &verifications)
	if verifications.Total != 1 || len(verifications.Items) != 1 {
		t.Fatalf("verification library filter=%+v", verifications)
	}
	if len(verifications.Items) == 0 || verifications.Items[0].Purpose != "verification" || verifications.Items[0].VerificationID == "" ||
		len(verifications.Items[0].CVEs) == 0 || verifications.Items[0].VerificationCategory == "" || verifications.Items[0].EvidenceLevel == "" {
		t.Fatalf("verification summary is incomplete: %+v", verifications.Items)
	}
	var verificationExport ruleExportPackage
	callAPI(t, handler, http.MethodGet, "/api/library/export?kind=poc&purpose=verification", "admin-library", nil, http.StatusOK, &verificationExport)
	if len(verificationExport.Items) != 1 || len(verificationExport.Licenses) != 1 || len(verificationExport.Notices) == 0 {
		t.Fatalf("verification export items/notices=%d/%d", len(verificationExport.Items), len(verificationExport.Notices))
	}
	var nuclei rulelib.Rule
	callAPI(t, handler, http.MethodGet, "/api/library/poc-security-txt", "admin-library", nil, http.StatusOK, &nuclei)
	nuclei.Definition = rulelib.Definition{}
	nuclei.Template = "\n" + nuclei.Template
	var normalizedNuclei rulelib.Rule
	callAPI(t, handler, http.MethodPut, "/api/library/poc-security-txt", "admin-library", struct {
		rulelib.Rule
		ExpectedRevision int `json:"expected_revision"`
	}{Rule: nuclei, ExpectedRevision: 1}, http.StatusOK, &normalizedNuclei)
	if normalizedNuclei.Revision != 2 || !normalizedNuclei.Builtin || len(normalizedNuclei.Definition.Requests) == 0 || strings.HasPrefix(normalizedNuclei.Template, "\n") {
		t.Fatalf("nuclei update was not normalized: %+v", normalizedNuclei)
	}

	custom := rulelib.Rule{ID: "custom-control-http", Kind: "http", Name: "Custom control rule", Engine: "native", Severity: "info", Enabled: true,
		Definition: rulelib.Definition{Matchers: []rulelib.Matcher{{Part: "status", Type: "status", Status: []int{204}}}}}
	var created rulelib.Rule
	callAPI(t, handler, http.MethodPost, "/api/library", "admin-library", custom, http.StatusCreated, &created)
	if created.Revision != 1 || created.Builtin {
		t.Fatalf("created custom rule=%+v", created)
	}
	created.Description = "updated"
	update := struct {
		rulelib.Rule
		ExpectedRevision int `json:"expected_revision"`
	}{Rule: created, ExpectedRevision: 1}
	var updated rulelib.Rule
	callAPI(t, handler, http.MethodPut, "/api/library/"+created.ID, "admin-library", update, http.StatusOK, &updated)
	callAPI(t, handler, http.MethodPut, "/api/library/"+created.ID, "admin-library", update, http.StatusConflict, nil)

	importRule := custom
	importRule.ID, importRule.Name, importRule.Enabled = "imported-control-http", "Imported control rule", true
	content, _ := json.Marshal(importRule)
	var imported struct {
		Items []rulelib.Rule `json:"items"`
		Count int            `json:"count"`
	}
	callAPI(t, handler, http.MethodPost, "/api/library/import", "admin-library", map[string]any{"format": "json", "content": string(content)}, http.StatusCreated, &imported)
	if imported.Count != 1 || imported.Items[0].Enabled {
		t.Fatalf("import must default disabled: %+v", imported)
	}
	callAPI(t, handler, http.MethodDelete, "/api/library/imported-control-http?expected_revision=1", "admin-library", nil, http.StatusOK, nil)
	var exported struct {
		Items []rulelib.Rule `json:"items"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library/export?kind=http", "admin-library", nil, http.StatusOK, &exported)
	if int64(len(exported.Items)) != builtinCounts["http"]+1 {
		t.Fatalf("exported HTTP rules=%d", len(exported.Items))
	}

	var run Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-library", map[string]any{
		"name": "poc closure", "targets": []string{"https://example.com"}, "modes": []string{"http"},
		"poc_enabled": true, "poc_rule_ids": []string{"poc-exposed-git-head"},
	}, http.StatusCreated, &run)
	if !run.POCEnabled {
		t.Fatal("created run did not preserve explicit PoC opt-in")
	}
	callAPI(t, handler, http.MethodDelete, "/api/library/poc-exposed-git-head?expected_revision=1", "admin-library", nil, http.StatusOK, nil)
	if err = seedRuleLibrary(ctx, server.db); err != nil {
		t.Fatal(err)
	}
	callAPI(t, handler, http.MethodGet, "/api/library/poc-exposed-git-head", "admin-library", nil, http.StatusNotFound, nil)

	if _, err = server.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		WorkerID    string `json:"worker_id"`
		WorkerToken string `json:"worker_token"`
	}
	callAPI(t, handler, http.MethodPost, "/api/workers/register", "join-library", map[string]any{
		"instance_id": "library-worker", "hostname": "local", "agent_version": "test", "session_id": "session-library", "spec": map[string]any{},
	}, http.StatusOK, &worker)
	claim := func(requestID string, types []string, output any) {
		callAPI(t, handler, http.MethodPost, "/api/tasks/claim", worker.WorkerToken, map[string]any{
			"worker_id": worker.WorkerID, "session_id": "session-library", "service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile, "fingerprint_bundle": webevidence.FingerprintBundle, "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": requestID, "types": types,
		}, http.StatusOK, output)
	}
	var httpClaim struct {
		Task *Task `json:"task"`
	}
	claim("http", []string{"http"}, &httpClaim)
	if httpClaim.Task == nil {
		t.Fatal("expected HTTP task")
	}
	var httpPayload struct {
		Rules    []rulelib.Rule `json:"rules"`
		POCRules []rulelib.Rule `json:"poc_rules"`
	}
	if json.Unmarshal(httpClaim.Task.Payload, &httpPayload) != nil || int64(len(httpPayload.Rules)) != builtinCounts["http"]+1 || len(httpPayload.POCRules) != 0 {
		t.Fatalf("claim did not use immutable rules snapshot: %+v", httpPayload)
	}
	var refRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-library", map[string]any{
		"name": "rule set ref", "targets": []string{"ref.example.com"}, "modes": []string{"http"},
	}, http.StatusCreated, &refRun)
	var refClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "session-library", "service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile, "fingerprint_bundle": webevidence.FingerprintBundle, "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": "http-ref", "types": []string{"http"}, "use_rule_sets": true,
	}, http.StatusOK, &refClaim)
	var refPayload struct {
		RulesRef string          `json:"rules_ref"`
		Rules    json.RawMessage `json:"rules"`
		POCRules json.RawMessage `json:"poc_rules"`
	}
	if refClaim.Task == nil || json.Unmarshal(refClaim.Task.Payload, &refPayload) != nil || refPayload.RulesRef != refRun.ID+":http" || len(refPayload.Rules) != 0 || len(refPayload.POCRules) != 0 {
		t.Fatalf("reference claim=%+v payload=%s", refClaim.Task, refClaim.Task.Payload)
	}
	var ruleSet struct {
		Ref   string          `json:"ref"`
		Kind  string          `json:"kind"`
		Rules []executionRule `json:"rules"`
	}
	callAPI(t, handler, http.MethodGet, "/api/tasks/"+refClaim.Task.ID+"/rules?worker_id="+worker.WorkerID+
		"&session_id=session-library&attempt_no="+strconv.Itoa(refClaim.Task.AttemptNo), worker.WorkerToken, nil, http.StatusOK, &ruleSet)
	if ruleSet.Ref != refPayload.RulesRef || ruleSet.Kind != "http" || int64(len(ruleSet.Rules)) != builtinCounts["http"]+1 {
		t.Fatalf("downloaded rule set=%+v", ruleSet)
	}
	httpItems := []Observation{
		controlHTTPFixture(Observation{Kind: "http", Target: "https://example.com", URL: "https://example.com/", StatusCode: 200}),
		{Kind: "http", Target: "https://example.com", URL: "https://redirect.example.net/", StatusCode: 200},
	}
	// Cross-origin observations are rejected before storing any batch; only the
	// assigned entry can contribute fingerprints or downstream PoC work.
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+httpClaim.Task.ID+"/batches", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "session-library", "attempt_no": httpClaim.Task.AttemptNo, "batch_seq": 0, "items": httpItems,
	}, http.StatusUnprocessableEntity, nil)
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+httpClaim.Task.ID+"/batches", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "session-library", "attempt_no": httpClaim.Task.AttemptNo, "batch_seq": 0, "items": httpItems[:1],
	}, http.StatusOK, nil)
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+httpClaim.Task.ID+"/complete", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "session-library", "attempt_no": httpClaim.Task.AttemptNo, "last_batch_seq": 0,
	}, http.StatusOK, nil)
	var derivedCount int
	if err = server.db.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE run_id=$1 AND type='poc'`, run.ID).Scan(&derivedCount); err != nil || derivedCount != 1 {
		t.Fatalf("derived PoC tasks=%d err=%v", derivedCount, err)
	}

	var pocClaim struct {
		Task *Task `json:"task"`
	}
	claim("poc", []string{"poc"}, &pocClaim)
	if pocClaim.Task == nil {
		t.Fatal("expected PoC task")
	}
	var pocPayload struct {
		Endpoint taskEndpoint   `json:"endpoint"`
		Rules    []rulelib.Rule `json:"rules"`
	}
	if json.Unmarshal(pocClaim.Task.Payload, &pocPayload) != nil || len(pocPayload.Rules) != 1 || pocPayload.Endpoint.URL != "https://example.com/" {
		t.Fatalf("invalid PoC claim payload: %+v", pocPayload)
	}
	rule := pocPayload.Rules[0]
	finding := Observation{Kind: "poc", Target: "https://example.com/", URL: "https://example.com/.git/HEAD",
		RuleID: rule.ID, RuleName: rule.Name, RuleRevision: rule.Revision, Engine: rule.Engine, Severity: rule.Severity,
		FindingStatus: "matched", Evidence: "ref: refs/heads/main"}
	forged := finding
	forged.RuleRevision++
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+pocClaim.Task.ID+"/batches", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "session-library", "attempt_no": pocClaim.Task.AttemptNo, "batch_seq": 0, "items": []Observation{forged},
	}, http.StatusUnprocessableEntity, nil)
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+pocClaim.Task.ID+"/batches", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "session-library", "attempt_no": pocClaim.Task.AttemptNo, "batch_seq": 0, "items": []Observation{finding},
	}, http.StatusOK, nil)
	callAPI(t, handler, http.MethodPost, "/api/tasks/"+pocClaim.Task.ID+"/complete", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "session-library", "attempt_no": pocClaim.Task.AttemptNo, "last_batch_seq": 0,
	}, http.StatusOK, nil)

	staleRaw, _ := json.Marshal(finding)
	if _, err = server.db.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,target_key,observation)
	 VALUES($1,$2,$3,0,0,0,'example.com',$4)`, newID(), run.ID, pocClaim.Task.ID, staleRaw); err != nil {
		t.Fatal(err)
	}
	var findings struct {
		Items []struct {
			Observation
			ID              string   `json:"id"`
			MatchedProducts []string `json:"matched_products"`
			TriggerReason   string   `json:"trigger_reason"`
		} `json:"items"`
		Total   int64            `json:"total"`
		Summary map[string]int64 `json:"summary"`
	}
	callAPI(t, handler, http.MethodGet, "/api/runs/"+run.ID+"/findings?status=matched", "admin-library", nil, http.StatusOK, &findings)
	if findings.Total != 1 || findings.Summary["matched"] != 1 || findings.Summary["discovery_matched"] != 1 || findings.Summary["verification_matched"] != 0 {
		t.Fatalf("findings included stale attempt: %+v", findings)
	}
	if findings.Items[0].Purpose != "discovery" || findings.Items[0].Verification != nil {
		t.Fatalf("legacy finding was not classified as discovery: %+v", findings.Items[0])
	}
	if len(findings.Items) != 1 || findings.Items[0].TriggerReason != "explicit_unbound_rule" || len(findings.Items[0].MatchedProducts) != 0 {
		t.Fatalf("finding trigger trace=%+v", findings.Items)
	}
	var detail struct {
		MatchedProducts []string `json:"matched_products"`
		TriggerReason   string   `json:"trigger_reason"`
	}
	callAPI(t, handler, http.MethodGet, "/api/observations/"+findings.Items[0].ID, "admin-library", nil, http.StatusOK, &detail)
	if detail.TriggerReason != "explicit_unbound_rule" || len(detail.MatchedProducts) != 0 {
		t.Fatalf("observation trigger trace=%+v", detail)
	}
	callAPI(t, handler, http.MethodGet, "/api/runs/"+run.ID, "admin-library", nil, http.StatusOK, &run)
	if run.FindingCount != 1 || run.DiscoveryMatchCount != 1 || run.VerificationFindingCount != 0 || run.POCCheckedCount != 1 || run.Status != "completed" {
		t.Fatalf("run PoC stats=%+v", run)
	}
}

func TestLegacyTypeCheckMigration(t *testing.T) {
	databaseURL := os.Getenv("CONTROL_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTROL_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	adminDB, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schemaName := "typecheck_test_" + strings.ReplaceAll(newID(), "-", "")
	if _, err = adminDB.Exec(ctx, `CREATE SCHEMA `+schemaName); err != nil {
		adminDB.Close()
		t.Fatal(err)
	}
	u, _ := url.Parse(databaseURL)
	query := u.Query()
	query.Set("search_path", schemaName)
	u.RawQuery = query.Encode()
	first, err := New(ctx, u.String(), "admin-typecheck", "join-typecheck")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = first.db.Exec(ctx, `ALTER TABLE tasks DROP CONSTRAINT tasks_type_check;
		ALTER TABLE tasks ADD CONSTRAINT "typeCheck" CHECK (type IN ('port','service','http'))`); err != nil {
		first.Close()
		t.Fatal(err)
	}
	first.Close()
	second, err := New(ctx, u.String(), "admin-typecheck", "join-typecheck")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		second.Close()
		_, _ = adminDB.Exec(context.Background(), `DROP SCHEMA `+schemaName+` CASCADE`)
		adminDB.Close()
	})
	var definition string
	if err = second.db.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid='tasks'::regclass AND conname='tasks_type_check'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(definition, "poc") {
		t.Fatalf("migrated task type constraint=%s", definition)
	}
	runID := newID()
	if _, err = second.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status) VALUES($1,'migration','["example.com"]','{http}','pending')`, runID); err != nil {
		t.Fatal(err)
	}
	if _, err = second.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key)
		VALUES($1,$2,'poc','{"endpoint":{"url":"https://example.com"}}','migration-poc','example.com')`, newID(), runID); err != nil {
		t.Fatalf("migrated constraint rejected poc task: %v", err)
	}
}

func TestJSONImportOverLegacyLimit(t *testing.T) {
	_, handler := newPolicyTestServer(t, "large_import_test")
	rules := make([]rulelib.Rule, 1001)
	for index := range rules {
		rules[index] = rulelib.Rule{ID: fmt.Sprintf("bulk-http-%04d", index), Kind: "http", Name: fmt.Sprintf("Bulk %d", index),
			Engine: "native", Severity: "info", Revision: 1, Definition: rulelib.Definition{Matchers: []rulelib.Matcher{{
				Part: "status", Type: "status", Status: []int{200},
			}}}}
	}
	content, _ := json.Marshal(rules)
	var imported struct {
		Items []rulelib.Rule `json:"items"`
		Count int            `json:"count"`
	}
	callAPI(t, handler, http.MethodPost, "/api/library/import", "admin-policy", map[string]any{
		"format": "json", "content": string(content),
	}, http.StatusCreated, &imported)
	if imported.Count != len(rules) || len(imported.Items) != len(rules) || imported.Items[1000].Enabled {
		t.Fatalf("large import count/items/enabled=%d/%d/%t", imported.Count, len(imported.Items), imported.Items[1000].Enabled)
	}
}
