package rulelib

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	maxTemplateBytes = 16 << 20
	maxMatchers      = 8
	maxRequests      = 3
)

var (
	idPattern                = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	headerPattern            = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)
	pathPattern              = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	cvePattern               = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	hex40Pattern             = regexp.MustCompile(`^[a-f0-9]{40}$`)
	hex64Pattern             = regexp.MustCompile(`^[a-f0-9]{64}$`)
	metadataIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	metadataValuePattern     = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	reviewedSensitivePattern = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:passwd|password|credentials?|secrets?|tokens?|sessions?|users?|configs?|configurations?|settings?|wp-config|private[-_]?keys?|env)(?:$|[^a-z0-9])`)
	reviewedActionPattern    = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:cmd|command|exec|execute|eval|script|payload|delete|remove|destroy|logout|signout|shutdown|restart|reboot|reset|flush|install|upgrade|update|upload|write|create)(?:$|[^a-z0-9])`)
	reviewedExternalPattern  = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://([^/?#\s]+)`)
)

func Validate(rule Rule) error {
	if err := validateRuleEnvelope(rule); err != nil {
		return err
	}
	if err := validateHTTPCollection(rule); err != nil {
		return err
	}
	purpose := VerificationPurpose(rule)
	if !oneOf(purpose, "discovery", "verification", "check") {
		return fmt.Errorf("invalid purpose %q", rule.Purpose)
	}
	if err := validateUpstream(rule.Upstream); err != nil {
		return err
	}
	switch rule.Engine {
	case "native":
		return validateNativeRule(rule, purpose)
	case "nuclei":
		return validateRawNucleiRule(rule, purpose)
	case "httpx-cff":
		return validateHTTPXCFFRule(rule, purpose)
	}
	return fmt.Errorf("invalid engine %q", rule.Engine)
}

func validateRuleEnvelope(rule Rule) error {
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
	if rule.Engine != "native" && rule.Engine != "nuclei" && rule.Engine != "httpx-cff" {
		return fmt.Errorf("invalid engine %q", rule.Engine)
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
	return validateAppliesTo(rule)
}

func validateNativeRule(rule Rule, purpose string) error {
	if rule.Template != "" || rule.Nuclei != nil || len(rule.Fingerprint) != 0 {
		return fmt.Errorf("native rules cannot contain engine source data")
	}
	reviewed, protected, err := reviewedVerification(rule.ID)
	if err != nil {
		return fmt.Errorf("load reviewed verification registry: %w", err)
	}
	if protected {
		return validateVerificationCandidate(rule, reviewed)
	}
	if purpose == "verification" {
		return fmt.Errorf("native verification rule %q is not in the reviewed registry", rule.ID)
	}
	if purpose == "discovery" && rule.Verification != nil {
		return fmt.Errorf("discovery rules cannot contain verification metadata")
	}
	if rule.Verification != nil {
		if err := validateVerificationMetadata(rule.Verification); err != nil {
			return err
		}
	}
	return validateDefinition(rule, false)
}

func validateRawNucleiRule(rule Rule, purpose string) error {
	if rule.Nuclei == nil {
		return validateLegacyNucleiRule(rule, purpose)
	}
	if len(rule.Fingerprint) != 0 || rule.Verification != nil {
		return fmt.Errorf("nuclei rules require nuclei metadata only")
	}
	if rule.Nuclei.ExecutionProfile == NucleiExecutionProfileHTTPBasic {
		if rule.Nuclei.CatalogOnly || rule.Nuclei.RuntimeReason != "" {
			return fmt.Errorf("http-basic-v1 rules must be executable, not catalog-only entries")
		}
		if purpose != "check" || rule.Kind != "poc" {
			return fmt.Errorf("http-basic-v1 rules must use poc kind and check purpose")
		}
		if len(rule.AppliesTo) == 0 {
			return fmt.Errorf("http-basic-v1 rules require an explicit product binding")
		}
		if len(rule.Template) == 0 || len(rule.Template) > maxOriginalTemplateBytes {
			return fmt.Errorf("original nuclei template must be 1..%d bytes", maxOriginalTemplateBytes)
		}
		if !reflect.DeepEqual(rule.Definition, Definition{}) {
			return fmt.Errorf("http-basic-v1 rules cannot contain a normalized native definition")
		}
		return validateNucleiMetadata(rule.Template, rule.Nuclei)
	}
	if rule.Nuclei.ExecutionProfile != "" {
		return fmt.Errorf("unsupported nuclei execution profile %q", rule.Nuclei.ExecutionProfile)
	}
	if !rule.Nuclei.CatalogOnly || rule.Nuclei.RuntimeReason == "" {
		return fmt.Errorf("original nuclei source rules must remain catalog-only entries")
	}
	if len(rule.Template) == 0 || len(rule.Template) > maxTemplateBytes {
		return fmt.Errorf("nuclei template must be 1..%d bytes", maxTemplateBytes)
	}
	if purpose == "discovery" {
		if rule.Kind != "http" {
			return fmt.Errorf("nuclei discovery rules must use http kind")
		}
	} else if rule.Kind != "poc" {
		return fmt.Errorf("nuclei verification/check rules must use poc kind")
	}
	if !reflect.DeepEqual(rule.Definition, Definition{}) {
		return fmt.Errorf("raw nuclei rules cannot contain native definitions")
	}
	return validateNucleiMetadata(rule.Template, rule.Nuclei)
}

func validateLegacyNucleiRule(rule Rule, purpose string) error {
	if purpose != "discovery" || rule.Kind != "poc" || rule.Verification != nil || len(rule.Fingerprint) != 0 {
		return fmt.Errorf("legacy nuclei rules must retain poc discovery shape")
	}
	if len(rule.Template) == 0 || len(rule.Template) > maxTemplateBytes {
		return fmt.Errorf("nuclei template must be 1..%d bytes", maxTemplateBytes)
	}
	if err := validateDefinition(rule, false); err != nil {
		return err
	}
	parsed, err := parseNucleiTemplate(rule.Template)
	if err != nil {
		return fmt.Errorf("invalid legacy nuclei template: %w", err)
	}
	if parsed.ID != rule.ID || !reflect.DeepEqual(parsed.Definition, rule.Definition) {
		return fmt.Errorf("legacy nuclei definition does not match normalized template")
	}
	return nil
}

func validateHTTPXCFFRule(rule Rule, purpose string) error {
	if rule.Kind != "http" || purpose != "discovery" {
		return fmt.Errorf("httpx-cff rules must be http discovery rules")
	}
	if rule.Nuclei != nil || rule.Verification != nil || rule.Template != "" || len(rule.Fingerprint) == 0 {
		return fmt.Errorf("httpx-cff rules require only a raw fingerprint")
	}
	var object map[string]any
	if err := json.Unmarshal(rule.Fingerprint, &object); err != nil || object == nil {
		return fmt.Errorf("httpx-cff fingerprint must be a JSON object")
	}
	d := rule.Definition
	if d.Product == "" || (d.Service != "" && d.Service != "http") || d.VersionRegex != "" || d.VersionPart != "" ||
		d.UseDetectedVersion || d.Condition != "" || len(d.Matchers) != 0 || len(d.Requests) != 0 {
		return fmt.Errorf("httpx-cff definition may contain only http service and product")
	}
	return nil
}

func validateUpstream(upstream *Upstream) error {
	if upstream == nil {
		return nil
	}
	if !metadataIDPattern.MatchString(upstream.SourceID) {
		return fmt.Errorf("invalid upstream source id")
	}
	if upstream.Revision != "" && !hex40Pattern.MatchString(upstream.Revision) {
		return fmt.Errorf("upstream revision must be an empty or lowercase 40-character commit")
	}
	if upstream.Path == "" || len(upstream.Path) > 1024 || strings.Contains(upstream.Path, "\\") || path.IsAbs(upstream.Path) ||
		path.Clean(upstream.Path) != upstream.Path || upstream.Path == "." || strings.HasPrefix(upstream.Path, "../") {
		return fmt.Errorf("invalid upstream path")
	}
	if !hex64Pattern.MatchString(upstream.SHA256) {
		return fmt.Errorf("upstream sha256 must be lowercase hex")
	}
	return nil
}

func validateAppliesTo(rule Rule) error {
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
	return nil
}

func validateDefinition(rule Rule, reviewed bool) error {
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
		roles := map[string]int{"probe": 0, "control": 0}
		for i, request := range d.Requests {
			totalMatchers += len(request.Matchers)
			var err error
			if reviewed {
				err = validateReviewedRequest(request)
				roles[request.Role]++
			} else {
				err = validateRequest(request)
			}
			if err != nil {
				return fmt.Errorf("request %d: %w", i+1, err)
			}
		}
		if totalMatchers > maxMatchers {
			return fmt.Errorf("poc rule exceeds %d total matchers", maxMatchers)
		}
		if reviewed {
			if d.Condition != "and" {
				return fmt.Errorf("verification requests must use and condition")
			}
			if len(d.Requests) < 2 || roles["probe"] == 0 || roles["control"] == 0 {
				return fmt.Errorf("verification rules require probe and control requests")
			}
		}
	}
	return nil
}

func validateRequest(request Request) error {
	if request.Role != "" {
		return fmt.Errorf("discovery requests cannot set role")
	}
	return validateRequestWithPath(request, validateStaticPath)
}

func validateReviewedRequest(request Request) error {
	if request.Role != "probe" && request.Role != "control" {
		return fmt.Errorf("verification request role must be probe or control")
	}
	return validateRequestWithPath(request, validateReviewedPath)
}

func validateRequestWithPath(request Request, validatePath func(string) error) error {
	if request.Method != "GET" && request.Method != "HEAD" {
		return fmt.Errorf("method must be GET or HEAD")
	}
	if err := validatePath(request.Path); err != nil {
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

func validateReviewedPath(value string) error {
	if len(value) == 0 || len(value) > 512 || !utf8.ValidString(value) || !strings.HasPrefix(value, "/") ||
		strings.ContainsAny(value, "\\#\r\n\x00") || strings.Contains(value, "{{") {
		return fmt.Errorf("reviewed URI must be a fixed root-relative request target")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return fmt.Errorf("invalid reviewed request target")
	}
	decoded := value
	for range 3 {
		next, unescapeErr := url.PathUnescape(decoded)
		if unescapeErr != nil {
			return fmt.Errorf("invalid reviewed URI encoding")
		}
		next, unescapeErr = url.QueryUnescape(next)
		if unescapeErr != nil {
			return fmt.Errorf("invalid reviewed query encoding")
		}
		if next == decoded {
			break
		}
		decoded = next
	}
	lower := strings.ToLower(decoded)
	if strings.ContainsAny(decoded, "`|;<>\r\n\x00") || strings.Contains(decoded, "$(") || strings.Contains(decoded, "${") ||
		!reviewedExternalTargetsSafe(decoded) || strings.Contains(lower, "localhost") || strings.Contains(lower, "169.254.169.254") ||
		reviewedSensitivePattern.MatchString(decoded) || reviewedActionPattern.MatchString(decoded) {
		return fmt.Errorf("reviewed URI contains a sensitive, state-changing, command, or external-target marker")
	}
	return nil
}

func reviewedExternalTargetsSafe(value string) bool {
	matches := reviewedExternalPattern.FindAllStringSubmatch(value, -1)
	stripped := reviewedExternalPattern.ReplaceAllString(value, "")
	if strings.Contains(stripped, "://") {
		return false
	}
	for _, match := range matches {
		if len(match) != 2 || !strings.EqualFold(match[1], "shen-verify.invalid") {
			return false
		}
	}
	return true
}

func validateVerificationMetadata(verification *Verification) error {
	if verification == nil {
		return fmt.Errorf("verification metadata is required")
	}
	if !metadataIDPattern.MatchString(verification.ID) {
		return fmt.Errorf("invalid verification id")
	}
	if len(verification.CVEs) == 0 || len(verification.CVEs) > 32 {
		return fmt.Errorf("verification cves must contain 1..32 values")
	}
	seenCVEs := make(map[string]bool, len(verification.CVEs))
	for _, cve := range verification.CVEs {
		if !cvePattern.MatchString(cve) || seenCVEs[cve] {
			return fmt.Errorf("invalid or duplicate verification cve %q", cve)
		}
		seenCVEs[cve] = true
	}
	if !metadataValuePattern.MatchString(verification.Category) {
		return fmt.Errorf("invalid verification category")
	}
	if !metadataValuePattern.MatchString(verification.EvidenceLevel) {
		return fmt.Errorf("invalid verification evidence level")
	}
	if err := bounded("verification summary", verification.Summary, 1, 1024); err != nil {
		return err
	}
	if len(verification.References) > 16 {
		return fmt.Errorf("too many verification references")
	}
	for _, reference := range verification.References {
		if err := validateHTTPSURL("verification reference", reference); err != nil {
			return err
		}
	}
	return validateSourcePin(verification.SourcePin)
}

func validateSourcePin(pin SourcePin) error {
	if !metadataIDPattern.MatchString(pin.SourceID) {
		return fmt.Errorf("invalid source pin source id")
	}
	if err := validateHTTPSURL("source pin repository", pin.Repository); err != nil {
		return err
	}
	if !hex40Pattern.MatchString(pin.Revision) {
		return fmt.Errorf("source pin revision must be a lowercase 40-character commit")
	}
	if pin.Path == "" || len(pin.Path) > 512 || strings.Contains(pin.Path, "\\") || path.IsAbs(pin.Path) ||
		path.Clean(pin.Path) != pin.Path || pin.Path == "." || strings.HasPrefix(pin.Path, "../") {
		return fmt.Errorf("invalid source pin path")
	}
	if !hex64Pattern.MatchString(pin.SHA256) {
		return fmt.Errorf("source pin sha256 must be lowercase hex")
	}
	return nil
}

func validateHTTPSURL(name, value string) error {
	if len(value) == 0 || len(value) > 2048 {
		return fmt.Errorf("%s must be 1..2048 bytes", name)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("%s must be an absolute HTTPS URL", name)
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
