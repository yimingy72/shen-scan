package control

import (
	"encoding/json"
	"strings"
	"testing"

	"scanplatform/internal/rulelib"
)

func TestNormalizeOriginalNucleiRule(t *testing.T) {
	template := "id: fixture-original\ninfo:\n  name: Fixture original\n  author: shen\n  severity: info\n  metadata:\n    product: FixtureApp\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/health\"]\n    matchers:\n      - type: status\n        status: [200]\n"
	rule := rulelib.Rule{ID: "nuclei-fixture-original", Kind: "poc", Engine: "nuclei", Severity: "info",
		Nuclei: &rulelib.NucleiMetadata{ExecutionProfile: rulelib.NucleiExecutionProfileHTTPBasic}, Template: template}
	if err := normalizeNewRule(&rule); err != nil {
		t.Fatal(err)
	}
	if rule.Purpose != "check" || rule.Nuclei.TemplateID != "fixture-original" || rule.Nuclei.ContentSHA256 == "" ||
		len(rule.AppliesTo) != 1 || rule.AppliesTo[0] != "FixtureApp" || rule.Template != template {
		t.Fatalf("unexpected normalized rule: %#v", rule)
	}
	if len(rule.Definition.Requests) != 0 || len(rule.Definition.Matchers) != 0 {
		t.Fatal("original YAML rule gained a normalized executable definition")
	}

	missingProduct := strings.Replace(template, "  metadata:\n    product: FixtureApp\n", "", 1)
	rule = rulelib.Rule{ID: "nuclei-fixture-original", Kind: "poc", Engine: "nuclei", Severity: "info",
		Nuclei: &rulelib.NucleiMetadata{ExecutionProfile: rulelib.NucleiExecutionProfileHTTPBasic}, Template: missingProduct}
	if err := normalizeNewRule(&rule); err == nil || !strings.Contains(err.Error(), "product") {
		t.Fatalf("expected product binding failure, got %v", err)
	}
}

func TestValidateOriginalPOCObservation(t *testing.T) {
	template := "id: fixture-original\ninfo:\n  name: Fixture original\n  author: shen\n  severity: info\n  metadata:\n    product: FixtureApp\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/health\"]\n    matchers:\n      - type: status\n        status: [200]\n"
	rule, err := rulelib.ParseNucleiOriginal(template)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := taskEndpoint{IP: "127.0.0.1", Port: 8080, URL: "http://127.0.0.1:8080/app"}
	payload, _ := json.Marshal(map[string]any{"endpoint": endpoint, "rules": []rulelib.Rule{rule}})
	item := Observation{Kind: "poc", Target: endpoint.URL, IP: endpoint.IP, Port: endpoint.Port, URL: "http://127.0.0.1:8080/app/health",
		RuleID: rule.ID, RuleName: rule.Name, RuleRevision: rule.Revision, Engine: rule.Engine, Severity: rule.Severity,
		FindingStatus: "matched", TemplateID: rule.Nuclei.TemplateID, ExecutionProfile: rule.Nuclei.ExecutionProfile,
		ContentSHA256: rule.Nuclei.ContentSHA256}
	if err := validatePOCObservation(payload, &item); err != nil {
		t.Fatal(err)
	}
	wrongPath := item
	wrongPath.URL = "http://127.0.0.1:8080/health"
	if err := validatePOCObservation(payload, &wrongPath); err == nil {
		t.Fatal("out-of-scope original request path was accepted")
	}
	wrongTemplate := item
	wrongTemplate.TemplateID = "other-template"
	if err := validatePOCObservation(payload, &wrongTemplate); err == nil {
		t.Fatal("mismatched original template id was accepted")
	}
}
