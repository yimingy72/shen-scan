package rulesource

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"scanplatform/internal/rulelib"
)

const testMITLicense = `MIT License

Copyright (c) ProjectDiscovery

Permission is hereby granted, free of charge, to any person obtaining a copy.
`

func TestConvertNucleiNormalizesDisplayFields(t *testing.T) {
	files := map[string][]byte{
		"LICENSE.md": []byte(testMITLicense),
		"http/exposed-panels/example.yaml": []byte(`# retained upstream attribution
id: example-panel
info:
  name: Example Panel
  author: tester
  severity: info
  description: Detects a product-specific panel.
  impact: Display-only impact text.
  tags: panel,detect
  metadata:
    product: Example Product
http:
  - method: GET
    path:
      - '{{BaseURL}}/example'
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        name: panel-title
        part: body
        words:
          - Example Product Console
# digest: invalid-after-id-rewrite
`),
	}
	catalog, err := ConvertNuclei(files)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total != 1 || len(catalog.Rules) != 1 || catalog.License != "MIT" || catalog.Digest == "" {
		t.Fatalf("unexpected catalog: %#v", catalog)
	}
	rule := catalog.Rules[0]
	if rule.ID != "nt-example-panel" || !rule.Enabled || rule.Builtin || len(rule.AppliesTo) != 1 || rule.AppliesTo[0] != "Example Product" {
		t.Fatalf("unexpected normalized rule: %#v", rule)
	}
	if strings.Contains(rule.Template, "impact:") || strings.Contains(rule.Template, "name: panel-title") || strings.Contains(rule.Template, "digest:") {
		t.Fatalf("display-only fields were retained: %s", rule.Template)
	}
	if !strings.Contains(rule.Template, "retained upstream attribution") || !strings.Contains(rule.Template, "author: tester") {
		t.Fatalf("upstream attribution was removed: %s", rule.Template)
	}
	if !strings.Contains(rule.Source, "/blob/main/http/exposed-panels/example.yaml") || !strings.Contains(rule.Source, "upstream id: example-panel") {
		t.Fatalf("unstable source attribution: %q", rule.Source)
	}
	request := rule.Definition.Requests[0]
	if !rulelib.MatchRequest(request, rulelib.Input{Status: 200, Body: "Example Product Console"}) ||
		rulelib.MatchRequest(request, rulelib.Input{Status: 200, Body: "generic page"}) {
		t.Fatal("normalization changed matcher boolean semantics")
	}
}

func TestConvertNucleiRejectsUnsafeOrUnsupportedTemplates(t *testing.T) {
	safeInfo := `info:
  name: Test
  author: tester
  severity: info
  tags: detect
`
	files := map[string][]byte{
		"LICENSE.md":       []byte(testMITLicense),
		"dns/outside.yaml": []byte("id: outside\n" + safeInfo),
		"http/exposures/configs/env.yaml": []byte(`id: env-config
` + safeInfo + `http:
  - method: GET
    path: ['{{BaseURL}}/.env']
    matchers:
      - type: word
        words: [APP_KEY]
`),
		"http/misconfiguration/raw.yaml": []byte(`id: raw-request
` + safeInfo + `http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words: [test]
`),
		"http/technologies/post.yaml": []byte(`id: post-request
` + safeInfo + `http:
  - method: POST
    path: ['{{BaseURL}}/submit']
    matchers:
      - type: word
        words: [test]
`),
		"http/technologies/extractor.yaml": []byte(`id: extractor-dependent
` + safeInfo + `http:
  - method: GET
    path: ['{{BaseURL}}/']
    extractors:
      - type: regex
        regex: ['token=(.*)']
    matchers:
      - type: word
        words: [test]
`),
		"http/technologies/header-bypass.yaml": []byte(`id: header-bypass
` + safeInfo + `http:
  - method: GET
    path: ['{{BaseURL}}/']
    headers:
      X-Original-URL: /admin
    matchers:
      - type: word
        words: [test]
`),
	}
	catalog, err := ConvertNuclei(files)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total != 6 || len(catalog.Rules) != 0 {
		t.Fatalf("unsafe templates were accepted: %#v", catalog.Rules)
	}
	for _, reason := range []string{"outside_scope", "unsafe_content", "unsupported_http", "unsafe_header", "validation_failed"} {
		if catalog.Skipped[reason] == 0 {
			t.Errorf("missing rejection reason %q: %#v", reason, catalog.Skipped)
		}
	}
}

func TestNormalizedNucleiIDIsStableAndBounded(t *testing.T) {
	original := strings.Repeat("very-long-id-", 20) + "unsafe/value"
	first, second := normalizedNucleiID(original), normalizedNucleiID(original)
	if first != second || len(first) > 128 || !strings.HasPrefix(first, "nt-") || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`).MatchString(first) {
		t.Fatalf("invalid stable id: %q %q", first, second)
	}
}

func TestConvertOfficialNucleiArchive(t *testing.T) {
	root := os.Getenv("TEST_NUCLEI_TEMPLATES_DIR")
	if root == "" {
		t.Skip("set TEST_NUCLEI_TEMPLATES_DIR to an extracted official archive")
	}
	files := make(map[string][]byte)
	err := filepath.WalkDir(root, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ConvertNuclei(files)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total < 4000 || len(catalog.Rules) < 100 || len(catalog.Rules)+sumSkipped(catalog.Skipped) != catalog.Total {
		t.Fatalf("unexpected full-archive accounting: total=%d accepted=%d skipped=%#v", catalog.Total, len(catalog.Rules), catalog.Skipped)
	}
	t.Logf("total=%d accepted=%d skipped=%v digest=%s", catalog.Total, len(catalog.Rules), catalog.Skipped, catalog.Digest)
	acceptedBySource := map[string]int{}
	productBound := 0
	for index, rule := range catalog.Rules {
		if strings.Contains(rule.Template, "# digest:") {
			t.Fatalf("rewritten rule %q retained an invalid upstream digest signature", rule.ID)
		}
		source := strings.TrimPrefix(strings.Split(rule.Source, " (")[0], nucleiRepository+"/blob/main/")
		parts := strings.Split(source, "/")
		category := strings.Join(parts[:min(2, len(parts))], "/")
		acceptedBySource[category]++
		if len(rule.AppliesTo) > 0 {
			productBound++
		}
		if index < 20 || os.Getenv("TEST_NUCLEI_VERBOSE") != "" {
			t.Logf("accepted: %s source=%s applies_to=%v", rule.ID, source, rule.AppliesTo)
		}
	}
	t.Logf("accepted by source=%v product_bound=%d manual_only=%d", acceptedBySource, productBound, len(catalog.Rules)-productBound)
	for index, sample := range catalog.Samples {
		if index == 20 && os.Getenv("TEST_NUCLEI_VERBOSE") == "" {
			break
		}
		t.Logf("rejection: %s: %s", sample.Path, sample.Reason)
	}
}

func TestFetchOfficialNuclei(t *testing.T) {
	if os.Getenv("TEST_RULESOURCE_LIVE") == "" {
		t.Skip("set TEST_RULESOURCE_LIVE=1 to download and convert the official archive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	catalog, err := Fetch(ctx, NucleiID)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Revision) != 40 || !strings.HasPrefix(catalog.Digest, "sha256:") || catalog.Total < 4000 || len(catalog.Rules) < 100 || catalog.LicenseText == "" {
		t.Fatalf("unexpected live catalog: revision=%q digest=%q total=%d rules=%d", catalog.Revision, catalog.Digest, catalog.Total, len(catalog.Rules))
	}
	bound := 0
	for _, rule := range catalog.Rules {
		if len(rule.AppliesTo) > 0 {
			bound++
		}
	}
	t.Logf("revision=%s digest=%s total=%d accepted=%d product_bound=%d skipped=%v", catalog.Revision, catalog.Digest, catalog.Total, len(catalog.Rules), bound, catalog.Skipped)
}

func sumSkipped(skipped map[string]int) int {
	total := 0
	for _, count := range skipped {
		total += count
	}
	return total
}

func TestChangedReviewedTemplateRequiresReview(t *testing.T) {
	approved := rulelib.ReviewedVerifications()[0]
	catalog, err := ConvertNuclei(map[string][]byte{
		"LICENSE.md":                         []byte(rulelib.ThirdPartyNotices()),
		approved.Verification.SourcePin.Path: []byte("changed upstream template"),
	})
	if err != nil || len(catalog.Rules) != 0 || catalog.Skipped["review_required"] != 1 {
		t.Fatalf("changed template was not withheld: catalog=%+v err=%v", catalog, err)
	}
}
