package rulesource

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanplatform/internal/rulelib"
)

const testMITLicense = `MIT License

Copyright (c) ProjectDiscovery

Permission is hereby granted, free of charge, to any person obtaining a copy.
`

func TestConvertNucleiPreservesOriginalTemplateAsCatalogOnly(t *testing.T) {
	template := []byte(`# retained signature and attribution
id: example-panel
info:
  name: Example Panel
  author: tester
  severity: info
  description: Detects a product-specific panel.
  tags: panel,detect
  metadata:
    product: Example Product
http:
  - method: POST
    path: ['{{BaseURL}}/example?fixed=1']
    extractors:
      - type: regex
        regex: ['token=(.*)']
    matchers:
      - type: dsl
        dsl: [status_code == 200]
# digest: original-upstream-signature
`)
	files := map[string][]byte{
		"LICENSE.md":                       []byte(testMITLicense),
		".nuclei-ignore":                   []byte("ignored-template\n"),
		"helpers/payloads/example.txt":     []byte("payload\n"),
		"http/exposed-panels/example.yaml": template,
	}
	catalog, err := ConvertNuclei(files)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total != 1 || len(catalog.Rules) != 1 || len(catalog.Files) != 3 {
		t.Fatalf("unexpected catalog: total=%d rules=%d files=%d skipped=%v", catalog.Total, len(catalog.Rules), len(catalog.Files), catalog.Skipped)
	}
	rule := catalog.Rules[0]
	if rule.Engine != "nuclei" || rule.Kind != "http" || rule.Purpose != "discovery" || rule.Enabled || rule.Nuclei == nil ||
		!rule.Nuclei.CatalogOnly || rule.Nuclei.TemplateID != "example-panel" || rule.Nuclei.RuntimeReason == "" || rule.Upstream == nil {
		t.Fatalf("invalid raw catalog rule: %+v", rule)
	}
	if !bytes.Equal([]byte(rule.Template), template) || !strings.Contains(rule.Template, "digest: original-upstream-signature") {
		t.Fatal("original Nuclei YAML bytes/signature were rewritten")
	}
	if len(rule.Definition.Matchers) != 0 || len(rule.Definition.Requests) != 0 || !hasSourceTag(rule.Nuclei.Capabilities, "dsl") {
		t.Fatalf("raw template was converted into native syntax or lost capabilities: %+v", rule)
	}
	if err := rulelib.Validate(rule); err != nil {
		t.Fatalf("catalog-only rule invalid: %v", err)
	}
	for _, file := range catalog.Files {
		if file.SHA256 == "" || len(file.Data) == 0 {
			t.Fatalf("auxiliary file lost bytes/hash: %+v", file)
		}
	}
}

func TestConvertNucleiIndexesRiskAndUnsupportedRuntime(t *testing.T) {
	files := map[string][]byte{
		"LICENSE.md": []byte(testMITLicense),
		"dns/cves/2025/CVE-2025-9999.yaml": []byte(`id: CVE-2025-9999
info:
  name: DNS CVE
  severity: high
  tags: cve,dos
  classification:
    cve-id: CVE-2025-9999
dns:
  - name: '{{FQDN}}'
    type: A
    matchers:
      - type: word
        words: [test]
`),
		"http/fuzzing/raw.yaml": []byte(`id: raw-fuzz
info:
  name: Raw Fuzz
  severity: medium
  tags: fuzz
http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
    payloads:
      value: [one, two]
    attack: clusterbomb
    matchers:
      - type: dsl
        dsl: [status_code == 200]
`),
		"workflows/example.yaml": []byte(`id: workflow-example
info:
  name: Workflow
  severity: info
workflows:
  - template: http/technologies/example.yaml
`),
		"helpers/config.yaml": []byte("not: a-template\n"),
	}
	catalog, err := ConvertNuclei(files)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total != 4 || len(catalog.Rules) != 3 || catalog.Skipped["not_template"] != 1 {
		t.Fatalf("unexpected full-directory accounting: %+v", catalog)
	}
	byTemplate := map[string]rulelib.Rule{}
	for _, rule := range catalog.Rules {
		byTemplate[rule.Nuclei.TemplateID] = rule
		if rule.Enabled || !rule.Nuclei.CatalogOnly || rule.Nuclei.RuntimeReason == "" {
			t.Fatalf("raw source rule became executable: %+v", rule)
		}
	}
	dns := byTemplate["CVE-2025-9999"]
	if dns.Purpose != "verification" || dns.Kind != "poc" || !strings.Contains(dns.Nuclei.RuntimeReason, "dns") ||
		!strings.Contains(dns.Nuclei.DefaultDisabledReason, "dos") {
		t.Fatalf("DNS risk/runtime index=%+v", dns)
	}
	fuzz := byTemplate["raw-fuzz"]
	if !fuzz.Nuclei.Raw || fuzz.Nuclei.RequestCount != nil || !strings.Contains(fuzz.Nuclei.DefaultDisabledReason, "fuzz") {
		t.Fatalf("raw fuzz index=%+v", fuzz.Nuclei)
	}
	workflow := byTemplate["workflow-example"]
	if !strings.Contains(workflow.Nuclei.RuntimeReason, "workflow") || workflow.Purpose != "check" {
		t.Fatalf("workflow index=%+v", workflow)
	}
}

func TestConvertOfficialNucleiArchive(t *testing.T) {
	root := os.Getenv("TEST_NUCLEI_TEMPLATES_DIR")
	if root == "" {
		t.Skip("set TEST_NUCLEI_TEMPLATES_DIR to an extracted official archive")
	}
	files := make(map[string][]byte)
	err := filepath.WalkDir(root, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		relative, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filePath)
		if err == nil {
			files[filepath.ToSlash(relative)] = data
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ConvertNuclei(files)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total < 4000 || len(catalog.Rules)+sumSkipped(catalog.Skipped) != catalog.Total {
		t.Fatalf("unexpected archive accounting: total=%d rules=%d skipped=%v", catalog.Total, len(catalog.Rules), catalog.Skipped)
	}
	for _, rule := range catalog.Rules {
		if rule.Enabled || rule.Nuclei == nil || !rule.Nuclei.CatalogOnly || rule.Upstream == nil || !bytes.Equal([]byte(rule.Template), files[rule.Upstream.Path]) {
			t.Fatalf("raw template preservation failed for %q", rule.ID)
		}
	}
	t.Logf("total=%d catalog_rules=%d auxiliary_files=%d skipped=%v", catalog.Total, len(catalog.Rules), len(catalog.Files), catalog.Skipped)
}

func TestFetchOfficialNuclei(t *testing.T) {
	if os.Getenv("TEST_RULESOURCE_LIVE") == "" {
		t.Skip("set TEST_RULESOURCE_LIVE=1 to download the official archive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	catalog, err := Fetch(ctx, NucleiID)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Revision) != 40 || catalog.Total < 4000 || len(catalog.Rules) == 0 || len(catalog.Files) == 0 {
		t.Fatalf("unexpected live catalog: revision=%q total=%d rules=%d files=%d", catalog.Revision, catalog.Total, len(catalog.Rules), len(catalog.Files))
	}
	for _, rule := range catalog.Rules[:min(20, len(catalog.Rules))] {
		if rule.Upstream == nil || rule.Upstream.Revision != catalog.Revision || !rule.Nuclei.CatalogOnly {
			t.Fatalf("live rule lacks frozen provenance: %+v", rule)
		}
	}
	t.Logf("revision=%s total_yaml=%d catalog_rules=%d auxiliary_files=%d skipped=%v", catalog.Revision, catalog.Total, len(catalog.Rules), len(catalog.Files), catalog.Skipped)
}
