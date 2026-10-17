package rulelib

import (
	"reflect"
	"strings"
	"testing"
)

func testReviewedVerification() Rule {
	return Rule{
		ID: "verification-reviewed-test", Kind: "poc", Purpose: "verification", Name: "Reviewed verification test",
		Description: "Harmless probe and control fixture.", Engine: "native", Severity: "medium", Enabled: true,
		Builtin: true, Revision: 1, Tags: []string{"verification", "reviewed"}, AppliesTo: []string{"Example Product"},
		Verification: &Verification{
			ID: "reviewed-test", CVEs: []string{"CVE-2025-12345"}, Category: "path-traversal", EvidenceLevel: "direct-response",
			Summary: "A harmless fixed file differs from the control response.", References: []string{"https://example.com/advisory"},
			SourcePin: SourcePin{SourceID: "nuclei-templates", Repository: "https://github.com/projectdiscovery/nuclei-templates",
				Revision: strings.Repeat("a", 40), Path: "http/cves/2025/CVE-2025-12345.yaml", SHA256: strings.Repeat("b", 64)},
		},
		Source: "reviewed fixture", Definition: Definition{Service: "http", Product: "Example Product", Condition: "and", Requests: []Request{
			{Method: "GET", Path: "//public/%2e%2e/release.txt?fixed=1", Role: "probe", Condition: "and", Matchers: []Matcher{
				{Part: "status", Type: "status", Status: []int{200}, Condition: "or"},
				{Part: "body", Type: "word", Words: []string{"reviewed harmless marker"}, Condition: "or", CaseSensitive: true},
			}},
			{Method: "GET", Path: "/missing-reviewed-control?fixed=1", Role: "control", Condition: "and", Matchers: []Matcher{
				{Part: "status", Type: "status", Status: []int{404}, Condition: "or"},
			}},
		}},
	}
}

func TestVerificationCandidateIsImmutableOutsideAllowedFields(t *testing.T) {
	reviewed := testReviewedVerification()
	if err := validateReviewedRegistryRule(reviewed); err != nil {
		t.Fatal(err)
	}
	candidate := cloneRule(reviewed)
	candidate.Name, candidate.Description, candidate.Enabled, candidate.Revision = "Local label", "Local description", false, 9
	if err := validateVerificationCandidate(candidate, reviewed); err != nil {
		t.Fatalf("allowed presentation changes were rejected: %v", err)
	}

	mutations := map[string]func(*Rule){
		"definition":   func(rule *Rule) { rule.Definition.Requests[0].Path = "/different" },
		"matcher":      func(rule *Rule) { rule.Definition.Requests[0].Matchers[1].Words[0] = "different" },
		"applies_to":   func(rule *Rule) { rule.AppliesTo[0] = "Other Product" },
		"verification": func(rule *Rule) { rule.Verification.Summary = "different" },
		"tags":         func(rule *Rule) { rule.Tags = append(rule.Tags, "different") },
		"source":       func(rule *Rule) { rule.Source = "different" },
		"severity":     func(rule *Rule) { rule.Severity = "low" },
		"builtin":      func(rule *Rule) { rule.Builtin = false },
	}
	for name, mutate := range mutations {
		changed := cloneRule(reviewed)
		mutate(&changed)
		if err := validateVerificationCandidate(changed, reviewed); err == nil {
			t.Errorf("%s mutation was accepted", name)
		}
	}
}

func TestReviewedURIIsNarrowAndNonSensitive(t *testing.T) {
	for _, value := range []string{
		"//public/%2e%2e/release.txt?fixed=1",
		"/static/release.txt?asset=a%2Fb",
		"/public/%252e%252e/release.txt",
	} {
		if err := validateReviewedPath(value); err != nil {
			t.Errorf("reviewed safe URI %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{
		"/etc/passwd", "/download?file=..%2fconfig.yaml", "/?cmd=id", "/?action=delete",
		"/?url=http%3A%2F%2Fexample.net", "/?url=http%3A%2F%2Fshen-verify.invalid.evil", "/public/%252e%252e/passwd", "/path#fragment", "/path%0d%0aInjected:true",
	} {
		if err := validateReviewedPath(value); err == nil {
			t.Errorf("unsafe reviewed URI %q was accepted", value)
		}
	}
}

func TestVerificationRequiresProbeAndControlAndAllResponses(t *testing.T) {
	rule := testReviewedVerification()
	if err := validateReviewedRegistryRule(rule); err != nil {
		t.Fatal(err)
	}
	probe := Input{Status: 200, Body: "reviewed harmless marker"}
	control := Input{Status: 404}
	if _, ok := NativePoCMatch(rule, []Input{probe, control}); !ok {
		t.Fatal("complete probe and control did not match")
	}
	if _, ok := NativePoCMatch(rule, []Input{probe, Input{Status: 200}}); ok {
		t.Fatal("verification matched without the control response")
	}
	missingRole := cloneRule(rule)
	missingRole.Definition.Requests[1].Role = ""
	if err := validateReviewedRegistryRule(missingRole); err == nil {
		t.Fatal("verification without a control role was accepted")
	}
	oneRequest := cloneRule(rule)
	oneRequest.Definition.Requests = oneRequest.Definition.Requests[:1]
	if err := validateReviewedRegistryRule(oneRequest); err == nil {
		t.Fatal("single-request verification was accepted")
	}
}

func TestDiscoveryRemainsStrict(t *testing.T) {
	if got := VerificationPurpose(Rule{}); got != "discovery" {
		t.Fatalf("empty purpose = %q", got)
	}
	rule := testReviewedVerification()
	rule.ID = "unregistered-verification"
	if err := Validate(rule); err == nil || !strings.Contains(err.Error(), "not in the reviewed registry") {
		t.Fatalf("unregistered verification error=%v", err)
	}
	discovery := Rule{
		ID: "discovery-role-test", Kind: "poc", Name: "Discovery", Engine: "native", Severity: "info", Revision: 1,
		Definition: Definition{Condition: "and", Requests: []Request{{
			Method: "GET", Path: "/", Role: "probe", Matchers: []Matcher{{Part: "status", Type: "status", Status: []int{200}}},
		}}},
	}
	if err := Validate(discovery); err == nil || !strings.Contains(err.Error(), "cannot set role") {
		t.Fatalf("discovery role error=%v", err)
	}
	discovery.Definition.Requests[0].Role = ""
	discovery.Verification = rule.Verification
	if err := Validate(discovery); err == nil || !strings.Contains(err.Error(), "cannot contain verification") {
		t.Fatalf("discovery verification metadata error=%v", err)
	}
}

func TestReviewedVerificationsAreClonedAndValid(t *testing.T) {
	first := ReviewedVerifications()
	for _, rule := range first {
		if err := Validate(rule); err != nil {
			t.Fatalf("reviewed rule %q is invalid: %v", rule.ID, err)
		}
	}
	if len(first) == 0 {
		return
	}
	original := cloneRule(first[0])
	first[0].Definition.Requests[0].Path = "/mutated"
	first[0].AppliesTo[0] = "mutated"
	first[0].Verification.CVEs[0] = "CVE-2099-9999"
	first[0].Verification.Summary = "mutated"
	for name := range first[0].Definition.Requests[0].Headers {
		first[0].Definition.Requests[0].Headers[name] = "mutated"
		break
	}
	first[0].Definition.Requests[0].Matchers[0].Regex[0] = "mutated"
	second := ReviewedVerifications()
	if !reflect.DeepEqual(second[0], original) {
		t.Fatal("reviewed registry leaked mutable state")
	}
}
