package rulelib

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
)

//go:embed reviewed_verifications.json
var reviewedVerificationData []byte

var (
	reviewedOnce  sync.Once
	reviewedRules []Rule
	reviewedByID  map[string]Rule
	reviewedErr   error
)

func VerificationPurpose(rule Rule) string {
	if rule.Purpose == "" {
		return "discovery"
	}
	return rule.Purpose
}

func ReviewedVerifications() []Rule {
	loadReviewedVerifications()
	if reviewedErr != nil {
		panic("invalid reviewed verification registry: " + reviewedErr.Error())
	}
	return cloneRules(reviewedRules)
}

func reviewedVerification(id string) (Rule, bool, error) {
	loadReviewedVerifications()
	if reviewedErr != nil {
		return Rule{}, false, reviewedErr
	}
	rule, ok := reviewedByID[id]
	if !ok {
		return Rule{}, false, nil
	}
	return cloneRule(rule), true, nil
}

func loadReviewedVerifications() {
	reviewedOnce.Do(func() {
		decoder := json.NewDecoder(bytes.NewReader(reviewedVerificationData))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&reviewedRules); err != nil {
			reviewedErr = fmt.Errorf("decode manifest: %w", err)
			return
		}
		if reviewedRules == nil {
			reviewedErr = errors.New("manifest must be a JSON array")
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			reviewedErr = errors.New("manifest must contain one JSON value")
			return
		}
		if len(reviewedRules) > 256 {
			reviewedErr = errors.New("manifest exceeds 256 rules")
			return
		}
		reviewedByID = make(map[string]Rule, len(reviewedRules))
		for index, rule := range reviewedRules {
			if _, duplicate := reviewedByID[rule.ID]; duplicate {
				reviewedErr = fmt.Errorf("rule %d duplicates id %q", index+1, rule.ID)
				return
			}
			if err := validateReviewedRegistryRule(rule); err != nil {
				reviewedErr = fmt.Errorf("rule %q: %w", rule.ID, err)
				return
			}
			reviewedByID[rule.ID] = cloneRule(rule)
		}
		reviewedRules = cloneRules(reviewedRules)
	})
}

// validateReviewedRegistryRule deliberately does not call Validate: registry
// loading is the trust root and must not recurse through registry lookup.
func validateReviewedRegistryRule(rule Rule) error {
	if err := validateRuleEnvelope(rule); err != nil {
		return err
	}
	if VerificationPurpose(rule) != "verification" || rule.Kind != "poc" || rule.Engine != "native" {
		return errors.New("reviewed rule must be a native poc verification")
	}
	if rule.Template != "" {
		return errors.New("reviewed native verification cannot contain a template")
	}
	if len(rule.AppliesTo) == 0 {
		return errors.New("reviewed verification requires product bindings")
	}
	if err := validateVerificationMetadata(rule.Verification); err != nil {
		return err
	}
	return validateDefinition(rule, true)
}

func validateVerificationCandidate(rule, reviewed Rule) error {
	if err := validateReviewedRegistryRule(rule); err != nil {
		return err
	}
	candidateProtected := rule
	reviewedProtected := reviewed
	candidateProtected.Name = reviewedProtected.Name
	candidateProtected.Description = reviewedProtected.Description
	candidateProtected.Enabled = reviewedProtected.Enabled
	candidateProtected.Revision = reviewedProtected.Revision
	if !reflect.DeepEqual(candidateProtected, reviewedProtected) {
		return errors.New("verification rule differs from its reviewed definition")
	}
	return nil
}

func cloneRules(rules []Rule) []Rule {
	cloned := make([]Rule, len(rules))
	for index, rule := range rules {
		cloned[index] = cloneRule(rule)
	}
	return cloned
}

func cloneRule(rule Rule) Rule {
	cloned := rule
	cloned.Tags = append([]string(nil), rule.Tags...)
	cloned.AppliesTo = append([]string(nil), rule.AppliesTo...)
	cloned.Definition.Matchers = cloneMatchers(rule.Definition.Matchers)
	cloned.Definition.Requests = make([]Request, len(rule.Definition.Requests))
	for index, request := range rule.Definition.Requests {
		cloned.Definition.Requests[index] = request
		cloned.Definition.Requests[index].Matchers = cloneMatchers(request.Matchers)
		if request.Headers != nil {
			cloned.Definition.Requests[index].Headers = make(map[string]string, len(request.Headers))
			for name, value := range request.Headers {
				cloned.Definition.Requests[index].Headers[name] = value
			}
		}
	}
	if rule.Verification != nil {
		verification := *rule.Verification
		verification.CVEs = append([]string(nil), rule.Verification.CVEs...)
		verification.References = append([]string(nil), rule.Verification.References...)
		cloned.Verification = &verification
	}
	return cloned
}

func cloneMatchers(matchers []Matcher) []Matcher {
	if matchers == nil {
		return nil
	}
	cloned := make([]Matcher, len(matchers))
	for index, matcher := range matchers {
		cloned[index] = matcher
		cloned[index].Words = append([]string(nil), matcher.Words...)
		cloned[index].Regex = append([]string(nil), matcher.Regex...)
		cloned[index].Status = append([]int(nil), matcher.Status...)
	}
	return cloned
}
