package rulelib

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

const (
	maxTemplateBytes = 256 << 10
	maxMatchers      = 8
	maxRequests      = 3
)

var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	headerPattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)
	pathPattern   = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
)

func Validate(rule Rule) error {
	if !idPattern.MatchString(rule.ID) {
		return fmt.Errorf("invalid rule id")
	}
	if err := bounded("name", rule.Name, 1, 200); err != nil {
		return err
	}
	if err := bounded("description", rule.Description, 0, 4096); err != nil {
		return err
	}
	if err := bounded("source", rule.Source, 0, 1024); err != nil {
		return err
	}
	if rule.Revision < 1 {
		return fmt.Errorf("revision must be positive")
	}
	if rule.Kind != "http" && rule.Kind != "port" && rule.Kind != "poc" {
		return fmt.Errorf("invalid kind %q", rule.Kind)
	}
	if rule.Engine != "native" && rule.Engine != "nuclei" {
		return fmt.Errorf("invalid engine %q", rule.Engine)
	}
	if rule.Kind != "poc" && rule.Engine != "native" {
		return fmt.Errorf("fingerprint rules must use native engine")
	}
	if !oneOf(rule.Severity, "info", "low", "medium", "high", "critical") {
		return fmt.Errorf("invalid severity %q", rule.Severity)
	}
	if len(rule.Tags) > 32 {
		return fmt.Errorf("too many tags")
	}
	for _, tag := range rule.Tags {
		if err := bounded("tag", tag, 1, 64); err != nil {
			return err
		}
	}
	if rule.Kind != "poc" && len(rule.AppliesTo) != 0 {
		return fmt.Errorf("applies_to is only valid for poc rules")
	}
	if len(rule.AppliesTo) > 32 {
		return fmt.Errorf("too many applies_to products")
	}
	seenProducts := make(map[string]bool, len(rule.AppliesTo))
	for _, product := range rule.AppliesTo {
		if err := bounded("applies_to product", product, 1, 128); err != nil {
			return err
		}
		normalized := normalizeProduct(product)
		if normalized == "" || prohibitedProductBinding(normalized) {
			return fmt.Errorf("invalid applies_to product %q", product)
		}
		if seenProducts[normalized] {
			return fmt.Errorf("duplicate applies_to product %q", product)
		}
		seenProducts[normalized] = true
	}
	if err := validateDefinition(rule); err != nil {
		return err
	}
	if rule.Engine == "nuclei" {
		if len(rule.Template) == 0 || len(rule.Template) > maxTemplateBytes {
			return fmt.Errorf("nuclei template must be 1..%d bytes", maxTemplateBytes)
		}
		parsed, err := parseNucleiTemplate(rule.Template)
		if err != nil {
			return fmt.Errorf("invalid nuclei template: %w", err)
		}
		if parsed.ID != rule.ID {
			return fmt.Errorf("nuclei template id does not match rule id")
		}
		if !reflect.DeepEqual(parsed.Definition, rule.Definition) {
			return fmt.Errorf("nuclei definition does not match normalized template")
		}
	} else if rule.Template != "" {
		return fmt.Errorf("native rules cannot contain a template")
	}
	return nil
}

func validateDefinition(rule Rule) error {
	d := rule.Definition
	if err := bounded("service", d.Service, 0, 128); err != nil {
		return err
	}
	if err := bounded("product", d.Product, 0, 200); err != nil {
		return err
	}
	if !conditionOK(d.Condition) {
		return fmt.Errorf("invalid definition condition %q", d.Condition)
	}
	if d.VersionRegex != "" {
		if len(d.VersionRegex) > 2048 {
			return fmt.Errorf("version regex is too long")
		}
		if _, err := compilePattern(d.VersionRegex); err != nil {
			return fmt.Errorf("invalid version regex: %w", err)
		}
		if !oneOf(d.VersionPart, "body", "header", "title", "banner", "service", "product", "version") {
			return fmt.Errorf("invalid version part %q", d.VersionPart)
		}
	} else if d.VersionPart != "" {
		return fmt.Errorf("version_part requires version_regex")
	}
	if len(d.Matchers) > maxMatchers {
		return fmt.Errorf("too many matchers")
	}
	if len(d.Requests) > maxRequests {
		return fmt.Errorf("too many requests")
	}
	switch rule.Kind {
	case "http", "port":
		if len(d.Requests) != 0 {
			return fmt.Errorf("%s rules cannot contain requests", rule.Kind)
		}
		if len(d.Matchers) == 0 {
			return fmt.Errorf("fingerprint rule has no matchers")
		}
		for i, matcher := range d.Matchers {
			if err := validateMatcher(matcher, rule.Kind); err != nil {
				return fmt.Errorf("matcher %d: %w", i+1, err)
			}
		}
	case "poc":
		if len(d.Matchers) != 0 {
			return fmt.Errorf("poc rules use request matchers")
		}
		if len(d.Requests) == 0 {
			return fmt.Errorf("poc rule has no requests")
		}
		totalMatchers := 0
		for i, request := range d.Requests {
			totalMatchers += len(request.Matchers)
			if err := validateRequest(request); err != nil {
				return fmt.Errorf("request %d: %w", i+1, err)
			}
		}
		if totalMatchers > maxMatchers {
			return fmt.Errorf("poc rule exceeds %d total matchers", maxMatchers)
		}
	}
	return nil
}

func validateRequest(request Request) error {
	if request.Method != "GET" && request.Method != "HEAD" {
		return fmt.Errorf("method must be GET or HEAD")
	}
	if err := validateStaticPath(request.Path); err != nil {
		return err
	}
	if !conditionOK(request.Condition) {
		return fmt.Errorf("invalid matcher condition %q", request.Condition)
	}
	if len(request.Matchers) == 0 || len(request.Matchers) > maxMatchers {
		return fmt.Errorf("request must contain 1..%d matchers", maxMatchers)
	}
	if len(request.Headers) > 16 {
		return fmt.Errorf("too many request headers")
	}
	for name, value := range request.Headers {
		if !headerPattern.MatchString(name) || len(value) > 1024 || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid request header %q", name)
		}
		if oneOf(strings.ToLower(name), "host", "content-length", "transfer-encoding", "connection", "cookie", "authorization", "proxy-authorization", "x-http-method-override", "x-method-override", "upgrade") {
			return fmt.Errorf("request header %q is not allowed", name)
		}
	}
	for i, matcher := range request.Matchers {
		if err := validateMatcher(matcher, "http"); err != nil {
			return fmt.Errorf("matcher %d: %w", i+1, err)
		}
	}
	return nil
}

func validateMatcher(m Matcher, kind string) error {
	allowedParts := map[string]bool{"body": true, "header": true, "title": true, "status": true}
	if kind == "port" {
		allowedParts = map[string]bool{"banner": true, "service": true, "product": true}
	}
	if !allowedParts[m.Part] {
		return fmt.Errorf("part %q is not valid for %s", m.Part, kind)
	}
	if !conditionOK(m.Condition) {
		return fmt.Errorf("invalid condition %q", m.Condition)
	}
	if !oneOf(m.Type, "word", "regex", "status") {
		return fmt.Errorf("invalid type %q", m.Type)
	}
	if m.Type == "status" {
		if m.Part != "status" || len(m.Status) == 0 || len(m.Status) > 32 || len(m.Words) != 0 || len(m.Regex) != 0 {
			return fmt.Errorf("status matcher has invalid values")
		}
		for _, status := range m.Status {
			if status < 100 || status > 599 {
				return fmt.Errorf("invalid HTTP status %d", status)
			}
		}
		return nil
	}
	if m.Part == "status" || len(m.Status) != 0 {
		return fmt.Errorf("only status matchers can use status values")
	}
	values := m.Words
	if m.Type == "regex" {
		values = m.Regex
	}
	if len(values) == 0 || len(values) > 32 {
		return fmt.Errorf("matcher must contain 1..32 values")
	}
	if (m.Type == "word" && len(m.Regex) != 0) || (m.Type == "regex" && len(m.Words) != 0) {
		return fmt.Errorf("matcher contains values for another type")
	}
	for _, value := range values {
		if err := bounded("matcher value", value, 1, 4096); err != nil {
			return err
		}
		if m.Type == "regex" {
			if _, err := compilePattern(matcherPattern(value, m.CaseSensitive)); err != nil {
				return fmt.Errorf("invalid regex: %w", err)
			}
		}
	}
	return nil
}

func validateStaticPath(path string) error {
	if len(path) == 0 || len(path) > 512 || !pathPattern.MatchString(path) || strings.Contains(path, "//") {
		return fmt.Errorf("path must be a static root-relative path")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("path traversal is not allowed")
		}
		for _, token := range strings.FieldsFunc(strings.ToLower(segment), func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
			if oneOf(token, "delete", "remove", "destroy", "logout", "signout", "shutdown", "restart", "reboot", "reset", "flush", "install", "upgrade", "update", "upload", "write", "create") {
				return fmt.Errorf("state-changing path segment %q is not allowed", segment)
			}
		}
	}
	return nil
}

func bounded(name, value string, min, max int) error {
	if len(value) < min || len(value) > max {
		return fmt.Errorf("%s must be %d..%d bytes", name, min, max)
	}
	return nil
}

func conditionOK(value string) bool { return value == "" || value == "and" || value == "or" }

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func prohibitedProductBinding(product string) bool {
	return strings.Contains(product, "*") || oneOf(product, "/", "all", "any", "http", "https", "web")
}
