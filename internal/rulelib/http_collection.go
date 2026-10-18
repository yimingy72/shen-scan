package rulelib

import (
	"fmt"
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
