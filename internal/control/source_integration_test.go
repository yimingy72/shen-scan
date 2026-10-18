package control

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"scanplatform/internal/webevidence"
	"strings"
	"testing"

	"scanplatform/internal/rulelib"
	"scanplatform/internal/rulesource"
)

func testSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func sourceHTTPRule(id, product, marker string) rulelib.Rule {
	return rulelib.Rule{ID: id, Kind: "http", Name: product, Engine: "native", Severity: "info", Enabled: true, Revision: 1,
		Source: "https://github.com/projectdiscovery/wappalyzergo", Definition: rulelib.Definition{Product: product,
			Matchers: []rulelib.Matcher{{Part: "body", Type: "word", Words: []string{marker}}}}}
}

func sourceCatalog(revision string, rules ...rulelib.Rule) rulesource.Catalog {
	return rulesource.Catalog{Rules: rules, Total: len(rules), Skipped: map[string]int{}, Revision: revision,
		Digest: "sha256:" + revision, Repository: "https://github.com/projectdiscovery/wappalyzergo",
		License: "MIT", LicenseText: "MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy..."}
}

func TestRuleSourceAtomicSyncAndLocalPreservation(t *testing.T) {
	server, handler := newPolicyTestServer(t, "source_sync_test")
	ctx := context.Background()
	a := sourceHTTPRule("wa-a", "A", "a1")
	b := sourceHTTPRule("wa-b", "B", "b1")
	c := sourceHTTPRule("wa-c", "C", "c1")
	c.Enabled = false
	conflict := sourceHTTPRule("wa-conflict", "Local", "local")
	callAPI(t, handler, http.MethodPost, "/api/library", "admin-policy", conflict, http.StatusCreated, &conflict)
	if err := server.applyRuleSourceCatalog(ctx, rulesource.WappalyzerID, sourceCatalog("r1", a, b, c, sourceHTTPRule("wa-conflict", "Upstream", "upstream"))); err != nil {
		t.Fatal(err)
	}
	status, err := server.loadRuleSource(ctx, rulesource.WappalyzerID)
	if err != nil || status.Status != "ready" || status.Stats.Added != 3 || status.Stats.Preserved != 1 {
		t.Fatalf("first sync status=%+v err=%v", status, err)
	}
	var defaultDisabled rulelib.Rule
	callAPI(t, handler, http.MethodGet, "/api/library/wa-c", "admin-policy", nil, http.StatusOK, &defaultDisabled)
	if defaultDisabled.Enabled {
		t.Fatal("source default-disabled rule was enabled during publish")
	}
	empty := sourceCatalog("empty")
	mismatch := sourceCatalog("mismatch", a)
	mismatch.Total = 2
	negative := sourceCatalog("negative", a)
	negative.Total, negative.Skipped = 0, map[string]int{"invalid": -1}
	incomplete := sourceCatalog("incomplete", a)
	incomplete.LicenseText = ""
	badFile := sourceCatalog("bad-file", a)
	badFile.Files = []rulesource.SourceFile{{Path: "fingerprints_data.json", SHA256: strings.Repeat("0", 64), Data: []byte("different")}}
	for name, invalidCatalog := range map[string]rulesource.Catalog{
		"empty": empty, "mismatch": mismatch, "negative": negative, "incomplete": incomplete, "bad-file": badFile,
	} {
		if err = server.applyRuleSourceCatalog(ctx, rulesource.WappalyzerID, invalidCatalog); err == nil {
			t.Fatalf("%s catalog was accepted", name)
		}
	}
	status, _ = server.loadRuleSource(ctx, rulesource.WappalyzerID)
	var sourceCount int
	if err = server.db.QueryRow(ctx, `SELECT count(*) FROM rule_library WHERE source_id=$1`, rulesource.WappalyzerID).Scan(&sourceCount); err != nil || status.Revision != "r1" || sourceCount != 3 {
		t.Fatalf("invalid catalog changed source: revision=%q rows=%d err=%v", status.Revision, sourceCount, err)
	}
	var license struct {
		License     string `json:"license"`
		LicenseText string `json:"license_text"`
		Revision    string `json:"revision"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library/sources/wappalyzer/license", "admin-policy", nil, http.StatusOK, &license)
	if license.License != "MIT" || license.LicenseText == "" || license.Revision != "r1" {
		t.Fatalf("source license=%+v", license)
	}
	var converterVersion string
	if err = server.db.QueryRow(ctx, `SELECT converter_version FROM rule_sources WHERE id=$1`, rulesource.WappalyzerID).Scan(&converterVersion); err != nil || converterVersion != rulesource.ConverterVersion {
		t.Fatalf("converter_version=%q err=%v", converterVersion, err)
	}
	if err = server.markRuleSourceUnchanged(ctx, rulesource.WappalyzerID); err != nil {
		t.Fatal(err)
	}
	status, _ = server.loadRuleSource(ctx, rulesource.WappalyzerID)
	if status.Stats.Added != 0 || status.Stats.Updated != 0 || status.Stats.Unchanged != status.Stats.Accepted {
		t.Fatalf("same revision stats=%+v", status.Stats)
	}
	var sources struct {
		Items []ruleSourceStatus `json:"items"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library/sources", "admin-policy", nil, http.StatusOK, &sources)
	if len(sources.Items) != len(rulesource.Sources()) {
		t.Fatalf("source items=%+v", sources.Items)
	}
	server.sourceMu.Lock()
	server.sourceRunning[rulesource.WappalyzerID] = true
	server.sourceMu.Unlock()
	callAPI(t, handler, http.MethodPost, "/api/library/sources/wappalyzer/update", "admin-policy", nil, http.StatusAccepted, nil)
	server.finishSourceRun(rulesource.WappalyzerID)
	if err = server.applyRuleSourceCatalog(ctx, rulesource.WappalyzerID, sourceCatalog("r2", a, b, c, sourceHTTPRule("wa-conflict", "Upstream", "upstream"))); err != nil {
		t.Fatal(err)
	}
	status, _ = server.loadRuleSource(ctx, rulesource.WappalyzerID)
	if status.Stats.Unchanged != 3 || status.Stats.Preserved != 1 {
		t.Fatalf("idempotent sync status=%+v", status)
	}
	callAPI(t, handler, http.MethodPatch, "/api/library/wa-a", "admin-policy", map[string]any{"enabled": false, "expected_revision": 1}, http.StatusOK, &a)
	var localB rulelib.Rule
	callAPI(t, handler, http.MethodGet, "/api/library/wa-b", "admin-policy", nil, http.StatusOK, &localB)
	localB.Description = "local edit"
	callAPI(t, handler, http.MethodPut, "/api/library/wa-b", "admin-policy", struct {
		rulelib.Rule
		ExpectedRevision int `json:"expected_revision"`
	}{Rule: localB, ExpectedRevision: localB.Revision}, http.StatusOK, &localB)
	callAPI(t, handler, http.MethodDelete, "/api/library/wa-c?expected_revision=1", "admin-policy", nil, http.StatusOK, nil)
	d := sourceHTTPRule("wa-d", "D", "d1")
	invalid := sourceHTTPRule("invalid-id", "Invalid", "invalid")
	if err = server.applyRuleSourceCatalog(ctx, rulesource.WappalyzerID, sourceCatalog("broken", a, b, c, d, invalid)); err == nil {
		t.Fatal("invalid catalog was accepted")
	}
	status, _ = server.loadRuleSource(ctx, rulesource.WappalyzerID)
	if status.Revision != "r2" {
		t.Fatalf("failed sync changed source revision to %q", status.Revision)
	}
	var exists bool
	if err = server.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rule_library WHERE id='wa-d')`).Scan(&exists); err != nil || exists {
		t.Fatalf("failed sync partially inserted wa-d: exists=%t err=%v", exists, err)
	}
	a.Definition.Matchers[0].Words = []string{"a2"}
	b.Definition.Matchers[0].Words = []string{"b2"}
	c.Definition.Matchers[0].Words = []string{"c2"}
	if err = server.applyRuleSourceCatalog(ctx, rulesource.WappalyzerID, sourceCatalog("r3", a, b, c, d, sourceHTTPRule("wa-conflict", "Upstream", "upstream2"))); err != nil {
		t.Fatal(err)
	}
	status, _ = server.loadRuleSource(ctx, rulesource.WappalyzerID)
	if status.Stats.Added != 1 || status.Stats.Updated != 1 || status.Stats.Preserved != 3 {
		t.Fatalf("update sync status=%+v", status)
	}
	var gotA, gotB rulelib.Rule
	callAPI(t, handler, http.MethodGet, "/api/library/wa-a", "admin-policy", nil, http.StatusOK, &gotA)
	callAPI(t, handler, http.MethodGet, "/api/library/wa-b", "admin-policy", nil, http.StatusOK, &gotB)
	callAPI(t, handler, http.MethodGet, "/api/library/wa-c", "admin-policy", nil, http.StatusNotFound, nil)
	if gotA.Enabled || gotA.Definition.Matchers[0].Words[0] != "a2" || gotB.Description != "local edit" {
		t.Fatalf("local choices were not preserved: A=%+v B=%+v", gotA, gotB)
	}
	if err = server.applyRuleSourceCatalog(ctx, rulesource.WappalyzerID, sourceCatalog("r4", d)); err != nil {
		t.Fatal(err)
	}
	status, _ = server.loadRuleSource(ctx, rulesource.WappalyzerID)
	if status.Stats.Retired != 1 || status.Stats.Preserved < 2 {
		t.Fatalf("retirement sync status=%+v", status)
	}
	callAPI(t, handler, http.MethodGet, "/api/library/wa-a", "admin-policy", nil, http.StatusOK, &gotA)
	if gotA.Enabled {
		t.Fatal("removed upstream rule remained enabled")
	}
	var listed struct {
		Items []ruleSummary `json:"items"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library?source_id=wappalyzer&limit=500", "admin-policy", nil, http.StatusOK, &listed)
	for _, item := range listed.Items {
		if item.SourceID != rulesource.WappalyzerID {
			t.Fatalf("source filter leaked item %+v", item)
		}
	}
	var sourceRows int
	if err = server.db.QueryRow(ctx, `SELECT count(*) FROM rule_library WHERE source_id=$1`, rulesource.WappalyzerID).Scan(&sourceRows); err != nil || sourceRows != 4 {
		t.Fatalf("source rows=%d err=%v", sourceRows, err)
	}
	statsRaw, _ := json.Marshal(status.Stats)
	if len(statsRaw) == 0 {
		t.Fatal("source stats did not serialize")
	}
	if _, err = server.db.Exec(ctx, `UPDATE rule_sources SET status='updating' WHERE id=$1`, rulesource.WappalyzerID); err != nil {
		t.Fatal(err)
	}
	if err = initializeRuleSources(ctx, server.db); err != nil {
		t.Fatal(err)
	}
	status, _ = server.loadRuleSource(ctx, rulesource.WappalyzerID)
	if status.Status != "failed" || !strings.Contains(status.Error, "restart") {
		t.Fatalf("stale update status=%+v", status)
	}
}

func TestNucleiCatalogDoesNotReplaceExecutableLibrary(t *testing.T) {
	server, handler := newPolicyTestServer(t, "nuclei_catalog_isolation_test")
	ctx := context.Background()
	var oldRaw []byte
	if err := server.db.QueryRow(ctx, `UPDATE rule_library SET source_id=$1 WHERE id='poc-security-txt' RETURNING rule`,
		rulesource.NucleiID).Scan(&oldRaw); err != nil {
		t.Fatal(err)
	}
	template := `id: nt-catalog-test
info:
  name: Catalog test
  author: test
  severity: info
  description: "metadata before\0metadata after"
http:
  - method: GET
    path:
      - '{{BaseURL}}/catalog-test'
    matchers:
      - type: status
        status: [200]
`
	revision := strings.Repeat("a", 40)
	license := []byte("MIT License\n")
	catalog, err := rulesource.ConvertNuclei(map[string][]byte{"LICENSE.md": license, "http/technologies/catalog-test.yaml": []byte(template)})
	if err != nil || len(catalog.Rules) != 1 {
		t.Fatalf("convert catalog: rules=%d err=%v", len(catalog.Rules), err)
	}
	catalog.Revision = revision
	catalog.Digest = "sha256:catalog-r1"
	catalog.Rules[0].Upstream.Revision = revision
	largeFile := append(bytes.Repeat([]byte("source-data\n"), 12_000), 0, 'x')
	catalog.Files = append(catalog.Files, rulesource.SourceFile{Path: "helpers/large.txt", SHA256: testSHA256(largeFile), Data: largeFile})
	rule := catalog.Rules[0]
	if err = server.applyRuleSourceCatalog(ctx, rulesource.NucleiID, catalog); err != nil {
		t.Fatal(err)
	}
	previousRevision := catalog.Revision
	nextCatalog := catalog
	nextCatalog.Revision = strings.Repeat("c", 40)
	nextCatalog.Rules = append([]rulelib.Rule(nil), catalog.Rules...)
	for index := range nextCatalog.Rules {
		upstream := *nextCatalog.Rules[index].Upstream
		upstream.Revision = nextCatalog.Revision
		nextCatalog.Rules[index].Upstream = &upstream
	}
	if err = server.applyRuleSourceCatalog(ctx, rulesource.NucleiID, nextCatalog); err != nil {
		t.Fatal(err)
	}
	status, err := server.loadRuleSource(ctx, rulesource.NucleiID)
	if err != nil || status.Revision != nextCatalog.Revision || status.Stats.Unchanged != 1 || status.Stats.Updated != 0 {
		t.Fatalf("same-content Nuclei catalog update status=%+v err=%v", status, err)
	}
	var newRaw []byte
	if err = server.db.QueryRow(ctx, `SELECT rule FROM rule_library WHERE id='poc-security-txt'`).Scan(&newRaw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldRaw, newRaw) {
		t.Fatal("Nuclei catalog update changed an existing executable rule")
	}
	var leaked bool
	if err = server.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rule_library WHERE id=$1)`, rule.ID).Scan(&leaked); err != nil || leaked {
		t.Fatalf("catalog-only rule leaked into executable library: leaked=%t err=%v", leaked, err)
	}
	var listed struct {
		Items []ruleSummary `json:"items"`
		Total int64         `json:"total"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library/sources/nuclei-templates/catalog?runtime=catalog_only", "admin-policy", nil, http.StatusOK, &listed)
	if listed.Total != 1 || len(listed.Items) != 1 || listed.Items[0].ID != rule.ID || listed.Items[0].ExecutionAvailable ||
		len(listed.Items[0].CatalogSanitizedFields) == 0 {
		t.Fatalf("catalog list=%+v", listed)
	}
	var detail struct {
		rulelib.Rule
		CatalogSanitizedFields []string `json:"catalog_sanitized_fields"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library/sources/nuclei-templates/catalog/"+rule.ID, "admin-policy", nil, http.StatusOK, &detail)
	if detail.Template != rule.Template || detail.Upstream == nil || detail.Upstream.Path != rule.Upstream.Path {
		t.Fatalf("catalog detail lost raw source: %+v", detail)
	}
	if len(detail.CatalogSanitizedFields) == 0 || detail.Nuclei == nil ||
		strings.ContainsRune(string(detail.Nuclei.Info), 0) || !strings.Contains(string(detail.Nuclei.Info), catalogNULDisplay) {
		t.Fatalf("catalog NUL metadata was not safely indexed: fields=%v info=%s", detail.CatalogSanitizedFields, detail.Nuclei.Info)
	}
	var storedTemplate bool
	if err = server.db.QueryRow(ctx, `SELECT rule ? 'template' FROM rule_source_catalog WHERE source_id=$1 AND revision=$2 AND id=$3`,
		rulesource.NucleiID, nextCatalog.Revision, rule.ID).Scan(&storedTemplate); err != nil || storedTemplate {
		t.Fatalf("catalog JSONB duplicated the template: stored=%t err=%v", storedTemplate, err)
	}
	callAPI(t, handler, http.MethodPost, "/api/library", "admin-policy", detail.Rule, http.StatusBadRequest, nil)
	var historical rulelib.Rule
	callAPI(t, handler, http.MethodGet, "/api/library/sources/nuclei-templates/catalog/"+rule.ID+"?revision="+previousRevision,
		"admin-policy", nil, http.StatusOK, &historical)
	if historical.Upstream == nil || historical.Upstream.Revision != previousRevision {
		t.Fatalf("historical catalog revision was not immutable: %+v", historical.Upstream)
	}
	var files struct {
		Items []sourceFileSummary `json:"items"`
		Total int64               `json:"total"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library/sources/nuclei-templates/files?limit=100", "admin-policy", nil, http.StatusOK, &files)
	if files.Total != 3 || len(files.Items) != 3 {
		t.Fatalf("source files=%+v", files)
	}
	rawRequest := httptest.NewRequest(http.MethodGet, "/api/library/sources/nuclei-templates/files/raw?path=helpers/large.txt", nil)
	rawRequest.Header.Set("Authorization", "Bearer admin-policy")
	rawResponse := httptest.NewRecorder()
	handler.ServeHTTP(rawResponse, rawRequest)
	if rawResponse.Code != http.StatusOK || !bytes.Equal(rawResponse.Body.Bytes(), largeFile) || rawResponse.Header().Get("X-Content-SHA256") != testSHA256(largeFile) {
		t.Fatalf("raw source response status=%d sha=%q bytes=%d", rawResponse.Code,
			rawResponse.Header().Get("X-Content-SHA256"), rawResponse.Body.Len())
	}
	request := httptest.NewRequest(http.MethodGet, "/api/library/sources/nuclei-templates/export", nil)
	request.Header.Set("Authorization", "Bearer admin-policy")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("source export status=%d body=%s", response.Code, response.Body.String())
	}
	archive, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"LICENSE.md": false, "helpers/large.txt": false, rule.Upstream.Path: false, sourceManifestPath: false}
	for _, file := range archive.File {
		if _, ok := wanted[file.Name]; ok {
			wanted[file.Name] = true
		}
		reader, openErr := file.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		data, readErr := io.ReadAll(reader)
		_ = reader.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if file.Name == "helpers/large.txt" && !bytes.Equal(data, largeFile) {
			t.Fatalf("large source file was truncated in zip: got=%d want=%d", len(data), len(largeFile))
		}
	}
	for file, found := range wanted {
		if !found {
			t.Fatalf("source export missing %s", file)
		}
	}
}

func TestWappalyzerFingerprintIsFrozenInHTTPRuleSet(t *testing.T) {
	server, handler := newPolicyTestServer(t, "wappalyzer_snapshot_test")
	data := []byte(`{"apps":{"Header Tech":{"headers":{"server":"^HeaderTech"}}}}`)
	catalog, err := rulesource.ConvertWappalyzer(data)
	if err != nil || len(catalog.Rules) != 1 {
		t.Fatalf("convert Wappalyzer: rules=%d err=%v", len(catalog.Rules), err)
	}
	catalog.Revision = strings.Repeat("b", 40)
	for index := range catalog.Rules {
		catalog.Rules[index].Upstream.Revision = catalog.Revision
	}
	if err = server.applyRuleSourceCatalog(context.Background(), rulesource.WappalyzerID, catalog); err != nil {
		t.Fatal(err)
	}
	var upstream struct {
		Items []ruleSummary `json:"items"`
		Total int64         `json:"total"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library/sources/wappalyzer/catalog", "admin-policy", nil, http.StatusOK, &upstream)
	if upstream.Total != 1 || len(upstream.Items) != 1 || upstream.Items[0].Engine != "httpx-cff" || !upstream.Items[0].ExecutionAvailable {
		t.Fatalf("Wappalyzer upstream catalog=%+v", upstream)
	}
	var run Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-policy", map[string]any{
		"name": "Wappalyzer capability", "targets": []string{"wapp.example"}, "modes": []string{"http"},
	}, http.StatusCreated, &run)
	var requiresHTTPXCFF bool
	if err = server.db.QueryRow(context.Background(), `SELECT requires_httpx_cff FROM runs WHERE id=$1`, run.ID).Scan(&requiresHTTPXCFF); err != nil || !requiresHTTPXCFF {
		t.Fatalf("run did not freeze HTTPx requirement: required=%t err=%v", requiresHTTPXCFF, err)
	}
	if _, err = server.db.Exec(context.Background(), `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		WorkerID    string `json:"worker_id"`
		WorkerToken string `json:"worker_token"`
	}
	callAPI(t, handler, http.MethodPost, "/api/workers/register", "join-policy", map[string]any{
		"instance_id": "wapp-worker", "hostname": "local", "agent_version": "test", "session_id": "wapp-session", "spec": map[string]any{},
	}, http.StatusOK, &worker)
	var oldClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "wapp-session", "service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile, "fingerprint_bundle": webevidence.FingerprintBundle, "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": "old-agent", "types": []string{"http"}, "use_rule_sets": true,
	}, http.StatusOK, &oldClaim)
	if oldClaim.Task != nil {
		t.Fatal("worker without HTTPx capability claimed a mixed HTTP snapshot")
	}
	var newClaim struct {
		Task *Task `json:"task"`
	}
	callAPI(t, handler, http.MethodPost, "/api/tasks/claim", worker.WorkerToken, map[string]any{
		"worker_id": worker.WorkerID, "session_id": "wapp-session", "service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile, "fingerprint_bundle": webevidence.FingerprintBundle, "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": "new-agent", "types": []string{"http"},
		"use_rule_sets": true, "supports_httpx_cff": true,
	}, http.StatusOK, &newClaim)
	if newClaim.Task == nil {
		t.Fatal("HTTPx-capable worker did not claim the mixed HTTP snapshot")
	}
	tx, err := server.db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	snapshot, err := loadRuleSnapshot(context.Background(), tx, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantID := catalog.Rules[0].ID
	for _, rule := range snapshot.HTTP {
		if rule.ID != wantID {
			continue
		}
		if rule.Engine != "httpx-cff" || len(rule.Fingerprint) == 0 {
			t.Fatalf("frozen Wappalyzer rule=%+v", rule)
		}
		execution := executionRules([]rulelib.Rule{rule})
		if len(execution) != 1 || !bytes.Equal(execution[0].Fingerprint, rule.Fingerprint) {
			t.Fatal("rules_ref execution payload lost the raw Wappalyzer app")
		}
		raw, _ := json.Marshal(execution)
		var downloaded []rulelib.Rule
		if json.Unmarshal(raw, &downloaded) != nil || len(downloaded) != 1 || rulelib.Validate(downloaded[0]) != nil {
			t.Fatalf("rules_ref Wappalyzer payload is not Agent-compatible: %s", raw)
		}
		return
	}
	t.Fatalf("Wappalyzer rule %s was not frozen into the HTTP snapshot", wantID)
}
