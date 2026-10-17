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

func TestDecodeRuleJSONAcceptsLicensedExportPackage(t *testing.T) {
	if notice := rulelib.ThirdPartyNotices(); !strings.Contains(notice, "Copyright (c) 2021 ProjectDiscovery, Inc.") {
		t.Fatal("embedded third-party notice is missing the Wappalyzer copyright")
	}
	rule := rulelib.Rule{
		ID: "license-roundtrip", Kind: "http", Name: "License roundtrip", Engine: "native", Severity: "info", Revision: 1,
		Definition: rulelib.Definition{Service: "http", Product: "Roundtrip", Matchers: []rulelib.Matcher{{Part: "body", Type: "word", Words: []string{"roundtrip"}}}},
	}
	pkg := ruleExportPackage{
		Items: []rulelib.Rule{rule},
		Licenses: []ruleExportLicense{{SourceID: "wappalyzer", Repository: rulesource.WappalyzerRepository,
			Revision: "abc", License: "MIT", LicenseText: "MIT License"}},
		Notices: []ruleExportNotice{{Name: "THIRD_PARTY_NOTICES.md", Text: "notice"}},
	}
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := decodeRuleJSON(string(data))
	if err != nil || len(rules) != 1 || rules[0].ID != rule.ID {
		t.Fatalf("decode licensed export rules=%+v err=%v", rules, err)
	}
	unknown := strings.Replace(string(data), `"name":"License roundtrip"`, `"name":"License roundtrip","unknown":true`, 1)
	if _, err = decodeRuleJSON(unknown); err == nil {
		t.Fatal("licensed export relaxed strict rule decoding")
	}
}

func TestRuleExportIncludesSourceLicensesAndBuiltinNotice(t *testing.T) {
	server, handler := newPolicyTestServer(t, "library_license_export_test")
	rule := sourceHTTPRule("wa-license-export", "Licensed Product", "licensed-marker")
	if err := server.applyRuleSourceCatalog(context.Background(), rulesource.WappalyzerID, sourceCatalog("license-revision", rule)); err != nil {
		t.Fatal(err)
	}

	var automated ruleExportPackage
	callAPI(t, handler, http.MethodGet, "/api/library/export?source_id=wappalyzer", "admin-policy", nil, http.StatusOK, &automated)
	if len(automated.Items) != 1 || len(automated.Licenses) != 1 || len(automated.Notices) != 0 {
		t.Fatalf("automated export metadata=%+v", automated)
	}
	license := automated.Licenses[0]
	if license.SourceID != rulesource.WappalyzerID || license.Repository != rulesource.WappalyzerRepository ||
		license.Revision != "license-revision" || license.License != "MIT" || license.LicenseText == "" {
		t.Fatalf("automated export license=%+v", license)
	}
	var filtered struct {
		Total  int64            `json:"total"`
		Counts map[string]int64 `json:"counts"`
	}
	callAPI(t, handler, http.MethodGet, "/api/library?source_id=wappalyzer", "admin-policy", nil, http.StatusOK, &filtered)
	if filtered.Total != 1 || filtered.Counts["http"] <= filtered.Total || filtered.Counts["port"] == 0 || filtered.Counts["poc"] == 0 {
		t.Fatalf("source filter changed global tab counts: %+v", filtered)
	}
	encoded, _ := json.Marshal(automated)
	if decoded, err := decodeRuleJSON(string(encoded)); err != nil || len(decoded) != 1 || decoded[0].ID != rule.ID {
		t.Fatalf("automated export did not round-trip: rules=%+v err=%v", decoded, err)
	}

	var bootstrap ruleExportPackage
	callAPI(t, handler, http.MethodGet, "/api/library/export?ids=http-adobe-aem", "admin-policy", nil, http.StatusOK, &bootstrap)
	if len(bootstrap.Items) != 1 || len(bootstrap.Licenses) != 0 || len(bootstrap.Notices) != 1 {
		t.Fatalf("bootstrap export metadata=%+v", bootstrap)
	}
	if bootstrap.Notices[0].Name != "internal/rulelib/THIRD_PARTY_NOTICES.md" ||
		!strings.Contains(bootstrap.Notices[0].Text, "Copyright (c) 2021 ProjectDiscovery, Inc.") {
		t.Fatalf("bootstrap notice=%+v", bootstrap.Notices[0])
	}
}
