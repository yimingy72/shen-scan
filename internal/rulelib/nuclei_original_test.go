package rulelib

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseNucleiOriginalPreservesBytesAndBasePath(t *testing.T) {
	template := "# signature: shen-fixture\r\nid: vendor/health-marker\r\ninfo:\r\n  name: Health marker\r\n  author: shen\r\n  severity: info\r\n  metadata:\r\n    product: ShenFixtureApp\r\nhttp:\r\n  - method: GET\r\n    path:\r\n      - \"{{BaseURL}}/health\"\r\n      - \"{{RootURL}}/ready\"\r\n    matchers-condition: and\r\n    matchers:\r\n      - type: status\r\n        status: [200]\r\n      - type: word\r\n        part: body\r\n        words: [\"shen-local-fixture-ready\"]\r\n"
	rule, err := ParseNucleiOriginal(template)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Template != template {
		t.Fatal("original template bytes changed")
	}
	if rule.Nuclei == nil || rule.Nuclei.TemplateID != "vendor/health-marker" || rule.Nuclei.ExecutionProfile != NucleiExecutionProfileHTTPBasic {
		t.Fatalf("unexpected metadata: %#v", rule.Nuclei)
	}
	if rule.ID == rule.Nuclei.TemplateID || rule.Purpose != "check" || len(rule.AppliesTo) != 1 || rule.AppliesTo[0] != "ShenFixtureApp" {
		t.Fatalf("unexpected rule mapping: %#v", rule)
	}
	analysis, err := AnalyzeNucleiOriginal([]byte(template))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("https://example.test/app/")
	requests, err := ResolveNucleiOriginalRequests(analysis.Plan, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0].Path != "/app/health" || requests[1].Path != "/ready" {
		t.Fatalf("unexpected resolved requests: %#v", requests)
	}
}

func TestParseNucleiOriginalRejectsUnsupportedSubset(t *testing.T) {
	base := "id: test-template\ninfo:\n  name: Test\n  author: shen\n  severity: info\n  metadata:\n    product: TestApp\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/health\"]\n    matchers:\n      - type: status\n        status: [200]\n"
	cases := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{"unknown root field", func(value string) string { return value + "flow: http(1)\n" }, "$.flow"},
		{"raw request", func(value string) string {
			return strings.Replace(value, "path: [\"{{BaseURL}}/health\"]", "raw: [\"GET /health HTTP/1.1\"]", 1)
		}, "$.http[1].raw"},
		{"redirects", func(value string) string {
			return strings.Replace(value, "method: GET", "method: GET\n    redirects: true", 1)
		}, "$.http[1].redirects"},
		{"dynamic path", func(value string) string {
			return strings.Replace(value, "{{BaseURL}}/health", "{{BaseURL}}/{{id}}", 1)
		}, "dynamic"},
		{"post method", func(value string) string { return strings.Replace(value, "method: GET", "method: POST", 1) }, "GET or HEAD"},
		{"missing product", func(value string) string { return strings.Replace(value, "  metadata:\n    product: TestApp\n", "", 1) }, "product"},
		{"alias", func(value string) string {
			return strings.Replace(value, "  severity: info", "  severity: &sev info\n  description: *sev", 1)
		}, "anchors"},
		{"duplicate key", func(value string) string {
			return strings.Replace(value, "  severity: info", "  severity: info\n  severity: low", 1)
		}, "unique"},
		{"second document", func(value string) string { return value + "---\nid: second\n" }, "exactly one"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseNucleiOriginal(test.mutate(base))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}
