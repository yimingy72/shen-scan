package rulelib

import (
	"fmt"
	"strings"
)

func validateHTTPCollection(rule Rule) error {
	c := rule.Collection
	if c == nil {
		return nil
	}
	if rule.Kind != "http" || rule.Engine != "native" || rule.Severity != "info" || VerificationPurpose(rule) != "discovery" || rule.Verification != nil {
		return fmt.Errorf("collection is only valid for native info HTTP product fingerprints")
	}
	if err := validateStaticPath(c.Path); err != nil {
		return fmt.Errorf("invalid HTTP collection path: %w", err)
	}
	if len(c.Products) == 0 || len(c.Products) > 16 {
		return fmt.Errorf("HTTP collection requires 1..16 product bindings")
	}
	if err := validateAppliesTo(Rule{Kind: "poc", AppliesTo: c.Products}); err != nil {
		return fmt.Errorf("invalid HTTP collection binding: %w", err)
	}
	if !matchesProductBindings(c.Products, []string{rule.Definition.Product}) {
		return fmt.Errorf("HTTP collection product must match its candidate bindings")
	}
	if c.SourceRuleID != "" && (!idPattern.MatchString(c.SourceRuleID) || c.SourceRuleRevision < 1) || c.SourceRuleID == "" && c.SourceRuleRevision != 0 {
		return fmt.Errorf("HTTP collection source requires a valid rule id and revision")
	}
	return nil
}

func CollectionMatchesProducts(rule Rule, products []string) bool {
	return rule.Enabled && rule.Kind == "http" && rule.Engine == "native" && rule.Collection != nil && matchesProductBindings(rule.Collection.Products, products)
}

// Collection rules never match the primary page through Match. Only the caller
// that selected the rule and obtained its separate complete response uses this.
func MatchCollectedHTTP(rule Rule, input Input) (MatchResult, bool) {
	if rule.Collection == nil || !rule.Enabled || rule.Kind != "http" || rule.Engine != "native" {
		return MatchResult{}, false
	}
	path := rule.Collection.Path
	rule.Collection = nil
	result, ok := Match(rule, input)
	if ok {
		result.Evidence = "GET " + path + ": " + result.Evidence
	}
	return result, ok
}

// Explicitly selected confirmation definitions, not a severity/purpose filter
// over the PoC library. Exposure and vulnerability checks are never included.
func builtinHTTPCollections(source []Rule) []Rule {
	selected := map[string]bool{
		"poc-wordpress-readme": true, "poc-joomla-version-manifest": true,
		"poc-gitlab-health": true, "poc-gitea-version-api": true,
		"poc-swagger-ui-interface": true, "poc-django-admin-login": true,
	}
	var result []Rule
	for _, rule := range source {
		if !selected[rule.ID] || rule.Engine != "native" || len(rule.Definition.Requests) != 1 {
			continue
		}
		request := rule.Definition.Requests[0]
		if request.Method != "GET" || len(request.Headers) != 0 {
			continue
		}
		confirmation := Rule{
			ID: "http-collect-" + strings.TrimPrefix(rule.ID, "poc-"), Kind: "http", Engine: "native", Purpose: "discovery",
			Name: rule.Definition.Product + " · HTTP confirmation", Description: "Candidate-bound HTTP fingerprint collection; no vulnerability conclusion.",
			Severity: "info", Enabled: true, Builtin: true, Revision: 1, Tags: []string{"http", "collection", "product-confirmation"},
			Source:     rule.Source + "; confirmation-only reuse of " + rule.ID,
			Collection: &HTTPCollection{Path: request.Path, Products: append([]string(nil), rule.AppliesTo...), SourceRuleID: rule.ID, SourceRuleRevision: rule.Revision},
			Definition: Definition{Service: "http", Product: rule.Definition.Product, Condition: request.Condition, Matchers: append([]Matcher(nil), request.Matchers...)},
		}
		switch rule.ID {
		case "poc-joomla-version-manifest":
			confirmation.Definition.VersionRegex = `(?is)<version>\s*([^<\s]+)\s*</version>`
			confirmation.Definition.VersionPart = "body"
		case "poc-gitea-version-api":
			confirmation.Definition.VersionRegex = `"version"\s*:\s*"([^"\s]+)"`
			confirmation.Definition.VersionPart = "body"
		}
		result = append(result, confirmation)
	}
	return result
}
