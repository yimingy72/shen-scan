package rulelib

import (
	"fmt"
	"strings"
)

// MatchesProducts reports whether a PoC is explicitly bound to any detected product.
// Empty AppliesTo is intentionally manual-only.
func MatchesProducts(rule Rule, products []string) bool {
	if rule.Kind != "poc" || len(rule.AppliesTo) == 0 || len(products) == 0 {
		return false
	}
	return matchesProductBindings(rule.AppliesTo, products)
}

func matchesProductBindings(bindings, products []string) bool {
	detected := make(map[string]bool, len(products))
	for _, product := range products {
		if normalized := normalizeProduct(product); normalized != "" && !prohibitedProductBinding(normalized) {
			detected[normalized] = true
		}
	}
	for _, appliesTo := range bindings {
		if normalized := normalizeProduct(appliesTo); normalized != "" && detected[normalized] {
			return true
		}
	}
	return false
}

func normalizeProduct(product string) string {
	product = strings.NewReplacer("_", " ", "-", " ").Replace(product)
	product = strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(product)), " "))
	switch product {
	case "springboot":
		return "spring boot"
	case "tomcat":
		return "apache tomcat"
	case "rabbitmq":
		return "rabbitmq management"
	case "iis":
		return "microsoft iis"
	case "sharepoint":
		return "microsoft sharepoint"
	case "jetty":
		return "eclipse jetty"
	case "airflow":
		return "apache airflow"
	case "solr":
		return "apache solr"
	case "flink":
		return "apache flink"
	case "nifi":
		return "apache nifi"
	case "hadoop":
		return "apache hadoop"
	case "nextjs", "next js":
		return "next.js"
	case "aspnet", "asp net":
		return "asp.net"
	}
	return product
}

func Match(rule Rule, input Input) (MatchResult, bool) {
	if rule.Kind == "poc" || rule.Engine != "native" || rule.Collection != nil {
		return MatchResult{}, false
	}
	d := rule.Definition
	matched, evidence := matchMatchers(d.Matchers, d.Condition, input)
	if !matched {
		return MatchResult{}, false
	}
	result := MatchResult{Service: d.Service, Product: d.Product, Evidence: evidence}
	if result.Service == "" {
		result.Service = input.Service
	}
	if result.Product == "" {
		result.Product = input.Product
	}
	if d.UseDetectedVersion {
		result.Version = input.Version
	}
	if d.VersionRegex != "" {
		compiled, err := compilePattern(d.VersionRegex)
		if err == nil {
			if match := compiled.FindStringSubmatch(inputPart(d.VersionPart, input)); match != nil {
				result.Version = match[0]
				if len(match) > 1 {
					result.Version = match[1]
				}
			}
		}
	}
	return result, true
}

func MatchRequest(request Request, input Input) bool {
	matched, _ := matchMatchers(request.Matchers, request.Condition, input)
	return matched
}

// NativePoCMatch evaluates responses in the same order as a native rule's requests.
func NativePoCMatch(rule Rule, responses []Input) (MatchResult, bool) {
	if rule.Kind != "poc" || rule.Engine != "native" || len(responses) < len(rule.Definition.Requests) {
		return MatchResult{}, false
	}
	results := make([]bool, len(rule.Definition.Requests))
	evidence := make([]string, 0, len(results))
	for i, request := range rule.Definition.Requests {
		results[i] = MatchRequest(request, responses[i])
		if results[i] {
			evidence = append(evidence, request.Method+" "+request.Path+" matched")
		}
	}
	if !combine(results, rule.Definition.Condition, true) {
		return MatchResult{}, false
	}
	return MatchResult{Service: rule.Definition.Service, Product: rule.Definition.Product, Evidence: strings.Join(evidence, "; ")}, true
}

func matchMatchers(matchers []Matcher, condition string, input Input) (bool, string) {
	if len(matchers) == 0 {
		return true, "service/product selector matched"
	}
	results := make([]bool, len(matchers))
	evidence := make([]string, 0, len(matchers))
	for i, matcher := range matchers {
		results[i] = matchMatcher(matcher, input)
		if results[i] {
			evidence = append(evidence, matcherEvidence(matcher))
		}
	}
	return combine(results, condition, true), strings.Join(evidence, "; ")
}

func matchMatcher(m Matcher, input Input) bool {
	matched := false
	switch m.Type {
	case "status":
		for _, status := range m.Status {
			if input.Status == status {
				matched = true
				break
			}
		}
	case "word":
		text := inputPart(m.Part, input)
		values := make([]bool, len(m.Words))
		for i, word := range m.Words {
			if m.CaseSensitive {
				values[i] = strings.Contains(text, word)
			} else {
				values[i] = strings.Contains(strings.ToLower(text), strings.ToLower(word))
			}
		}
		matched = combine(values, m.Condition, false)
	case "regex":
		text := inputPart(m.Part, input)
		values := make([]bool, len(m.Regex))
		for i, pattern := range m.Regex {
			compiled, err := compilePattern(matcherPattern(pattern, m.CaseSensitive))
			values[i] = err == nil && compiled.MatchString(text)
		}
		matched = combine(values, m.Condition, false)
	}
	if m.Negative {
		return !matched
	}
	return matched
}

func combine(values []bool, condition string, empty bool) bool {
	if len(values) == 0 {
		return empty
	}
	if condition == "or" {
		for _, value := range values {
			if value {
				return true
			}
		}
		return false
	}
	for _, value := range values {
		if !value {
			return false
		}
	}
	return true
}

func inputPart(part string, input Input) string {
	switch part {
	case "body":
		return input.Body
	case "header":
		return input.Header
	case "title":
		return input.Title
	case "banner":
		return input.Banner
	case "service":
		return input.Service
	case "product":
		return input.Product
	case "version":
		return input.Version
	default:
		return ""
	}
}

func matcherEvidence(m Matcher) string {
	verb := "matched"
	if m.Negative {
		verb = "did not match"
	}
	summary := m.Type
	if m.Type == "word" && len(m.Words) > 0 {
		summary = fmt.Sprintf("word %q", truncate(m.Words[0], 96))
	} else if m.Type == "regex" && len(m.Regex) > 0 {
		summary = fmt.Sprintf("regex %q", truncate(m.Regex[0], 96))
	} else if m.Type == "status" {
		summary = fmt.Sprintf("status %v", m.Status)
	}
	return m.Part + " " + summary + " " + verb
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}
