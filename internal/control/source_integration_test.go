package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"scanplatform/internal/rulelib"
	"scanplatform/internal/rulesource"
)

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
	conflict := sourceHTTPRule("wa-conflict", "Local", "local")
	callAPI(t, handler, http.MethodPost, "/api/library", "admin-policy", conflict, http.StatusCreated, &conflict)
	if err := server.applyRuleSourceCatalog(ctx, rulesource.WappalyzerID, sourceCatalog("r1", a, b, c, sourceHTTPRule("wa-conflict", "Upstream", "upstream"))); err != nil {
		t.Fatal(err)
	}
	status, err := server.loadRuleSource(ctx, rulesource.WappalyzerID)
	if err != nil || status.Status != "ready" || status.Stats.Added != 3 || status.Stats.Preserved != 1 {
		t.Fatalf("first sync status=%+v err=%v", status, err)
	}
	empty := sourceCatalog("empty")
	mismatch := sourceCatalog("mismatch", a)
	mismatch.Total = 2
	negative := sourceCatalog("negative", a)
	negative.Total, negative.Skipped = 0, map[string]int{"invalid": -1}
	incomplete := sourceCatalog("incomplete", a)
	incomplete.LicenseText = ""
	for name, invalidCatalog := range map[string]rulesource.Catalog{
		"empty": empty, "mismatch": mismatch, "negative": negative, "incomplete": incomplete,
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
	if len(sources.Items) != 2 {
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
