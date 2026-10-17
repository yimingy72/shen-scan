package rulesource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"scanplatform/internal/rulelib"

	"gopkg.in/yaml.v3"
)

const (
	nucleiRepository = "https://github.com/projectdiscovery/nuclei-templates"
	nucleiLicense    = "MIT"
	maxTemplateSize  = 256 << 10
	maxNucleiSamples = 100
)

var (
	nucleiIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	allowedPrefixes = []string{
		"http/technologies/", "http/exposed-panels/", "http/misconfiguration/", "http/exposures/",
	}
	riskyTags = map[string]bool{
		"auth-bypass": true, "bruteforce": true, "cve": true, "dos": true, "lfi": true,
		"rce": true, "sqli": true, "ssrf": true, "token": true, "upload": true,
		"xss": true, "xxe": true,
	}
	riskyPhrases = []string{
		"arbitrary file", "auth bypass", "authentication bypass", "authorization bypass", "backup", "brute force",
		"build metadata", "command injection", "config exposure", "credential", "cross-site scripting", "database", "debug", "disclosure",
		"default credential", "default login", "denial of service", "directory traversal", "environment variable", "file read",
		"directory listing", "file upload", "heap dump", "interactsh", "instance information", " installer ", "job listing", "local file", "log exposure", "password", "path traversal",
		"private key", "remote code execution", "secret", "server-side request", "session", "source code",
		" sql injection", " setup ", "system properties", "thread dump", "traceback", "traffic statistics", "user data", "user enumeration", "user list", "users list", "webdav", "xml external",
	}
)

type conversionError struct {
	kind string
	err  error
}

func (e *conversionError) Error() string { return e.err.Error() }

// ConvertNuclei converts a repository archive into SHEN's strict, read-only
// Nuclei subset. Individual incompatible templates are reported, not fatal.
func ConvertNuclei(files map[string][]byte) (Catalog, error) {
	catalog := Catalog{
		Skipped: make(map[string]int), Repository: nucleiRepository, License: nucleiLicense,
	}
	licenseText := findLicense(files)
	if !strings.Contains(licenseText, "MIT License") {
		return Catalog{}, fmt.Errorf("official MIT LICENSE.md is missing")
	}
	catalog.LicenseText = licenseText
	catalog.Digest = digestFiles(files)

	paths := make([]string, 0, len(files))
	for filePath := range files {
		if isYAML(filePath) {
			paths = append(paths, filePath)
		}
	}
	sort.Strings(paths)
	catalog.Total = len(paths)
	seenIDs := make(map[string]bool)
	sampleCounts := make(map[string]int)
	for _, filePath := range paths {
		data := files[filePath]
		if !inNucleiScope(filePath) {
			reject(&catalog, sampleCounts, filePath, "outside_scope", "outside selected HTTP source directories")
			continue
		}
		if len(data) == 0 || len(data) > maxTemplateSize {
			reject(&catalog, sampleCounts, filePath, "oversized", fmt.Sprintf("template size must be 1..%d bytes", maxTemplateSize))
			continue
		}
		normalized, originalID, err := normalizeNuclei(data)
		if err != nil {
			kind, detail := conversionFailure(err)
			reject(&catalog, sampleCounts, filePath, kind, detail)
			continue
		}
		if risky, reason := unsafeTemplate(filePath, normalized); risky {
			reject(&catalog, sampleCounts, filePath, "unsafe_content", reason)
			continue
		}
		rule, err := rulelib.ParseNuclei(string(normalized))
		if err != nil {
			reject(&catalog, sampleCounts, filePath, classifyParseFailure(err), err.Error())
			continue
		}
		if requestPath, reason := sensitiveRequestPath(rule); reason != "" {
			reject(&catalog, sampleCounts, filePath, "sensitive_path", requestPath+": "+reason)
			continue
		}
		if !hasContentEvidence(rule) {
			reject(&catalog, sampleCounts, filePath, "weak_matcher", "template has no word or regex response evidence")
			continue
		}
		if seenIDs[rule.ID] {
			reject(&catalog, sampleCounts, filePath, "duplicate_id", "normalized rule id is already present")
			continue
		}
		seenIDs[rule.ID] = true
		rule.Enabled = true
		rule.Source = sourceURL(filePath) + " (upstream id: " + originalID + ")"
		catalog.Rules = append(catalog.Rules, rule)
	}
	return catalog, nil
}

func normalizeNuclei(data []byte) ([]byte, string, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, "", fail("invalid_yaml", "decode YAML: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, "", fail("invalid_yaml", "multiple YAML documents are not allowed")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, "", fail("invalid_yaml", "template root must be a mapping")
	}
	root := document.Content[0]
	if err := validateYAMLNode(root, 0); err != nil {
		return nil, "", err
	}
	stripNucleiDigestComments(root)
	if err := allowMapping(root, map[string]bool{"id": true, "info": true, "http": true}, nil, "unsupported_root"); err != nil {
		return nil, "", err
	}
	idNode := mappingValue(root, "id")
	if idNode == nil || idNode.Kind != yaml.ScalarNode || strings.TrimSpace(idNode.Value) == "" {
		return nil, "", fail("invalid_yaml", "template id must be a non-empty scalar")
	}
	originalID := strings.TrimSpace(idNode.Value)
	idNode.Value, idNode.Tag = normalizedNucleiID(originalID), "!!str"

	info := mappingValue(root, "info")
	if info == nil || info.Kind != yaml.MappingNode {
		return nil, "", fail("invalid_yaml", "info must be a mapping")
	}
	if err := allowMapping(info, map[string]bool{
		"name": true, "author": true, "severity": true, "description": true, "tags": true,
		"reference": true, "remediation": true, "metadata": true, "classification": true,
	}, map[string]bool{"impact": true}, "unsupported_info"); err != nil {
		return nil, "", err
	}

	httpBlocks := mappingValue(root, "http")
	if httpBlocks == nil || httpBlocks.Kind != yaml.SequenceNode || len(httpBlocks.Content) == 0 {
		return nil, "", fail("unsupported_protocol", "template must contain HTTP request blocks")
	}
	for blockIndex, block := range httpBlocks.Content {
		if block.Kind != yaml.MappingNode {
			return nil, "", fail("unsupported_http", "http block %d must be a mapping", blockIndex+1)
		}
		if err := allowMapping(block, map[string]bool{
			"method": true, "path": true, "headers": true, "matchers-condition": true, "matchers": true,
		}, nil, "unsupported_http"); err != nil {
			return nil, "", err
		}
		matchers := mappingValue(block, "matchers")
		if matchers == nil || matchers.Kind != yaml.SequenceNode || len(matchers.Content) == 0 {
			return nil, "", fail("unsupported_matcher", "http block %d has no matchers", blockIndex+1)
		}
		for matcherIndex, matcher := range matchers.Content {
			if matcher.Kind != yaml.MappingNode {
				return nil, "", fail("unsupported_matcher", "matcher %d in block %d must be a mapping", matcherIndex+1, blockIndex+1)
			}
			if err := allowMapping(matcher, map[string]bool{
				"type": true, "part": true, "words": true, "regex": true, "status": true,
				"condition": true, "negative": true, "case-insensitive": true,
			}, map[string]bool{"name": true}, "unsupported_matcher"); err != nil {
				return nil, "", err
			}
		}
	}

	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(root); err != nil {
		return nil, "", fail("invalid_yaml", "encode normalized YAML: %w", err)
	}
	_ = encoder.Close()
	return output.Bytes(), originalID, nil
}

func stripNucleiDigestComments(node *yaml.Node) {
	node.HeadComment = withoutDigestComment(node.HeadComment)
	node.LineComment = withoutDigestComment(node.LineComment)
	node.FootComment = withoutDigestComment(node.FootComment)
	for _, child := range node.Content {
		stripNucleiDigestComments(child)
	}
}

func withoutDigestComment(comment string) string {
	if comment == "" {
		return ""
	}
	lines := strings.Split(comment, "\n")
	kept := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		if strings.HasPrefix(strings.ToLower(trimmed), "digest:") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func allowMapping(node *yaml.Node, allowed, removable map[string]bool, kind string) error {
	filtered := make([]*yaml.Node, 0, len(node.Content))
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if removable[key.Value] {
			continue
		}
		if !allowed[key.Value] {
			return fail(kind, "field %q is not supported", key.Value)
		}
		filtered = append(filtered, key, value)
	}
	node.Content = filtered
	return nil
}

func validateYAMLNode(node *yaml.Node, depth int) error {
	if depth > 16 {
		return fail("invalid_yaml", "YAML nesting is too deep")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fail("invalid_yaml", "YAML anchors and aliases are not allowed")
	}
	if node.Kind == yaml.ScalarNode && len(node.Value) > 8192 {
		return fail("oversized", "YAML scalar exceeds 8192 bytes")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]bool, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || seen[key.Value] {
				return fail("invalid_yaml", "YAML mapping keys must be unique strings")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateYAMLNode(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func unsafeTemplate(filePath string, normalized []byte) (bool, string) {
	root := yaml.Node{}
	if err := yaml.Unmarshal(normalized, &root); err != nil || len(root.Content) == 0 {
		return true, "normalized template cannot be inspected"
	}
	mapping := root.Content[0]
	if mapping.Kind == yaml.DocumentNode && len(mapping.Content) > 0 {
		mapping = mapping.Content[0]
	}
	info := mappingValue(mapping, "info")
	severity := strings.ToLower(scalarValue(mappingValue(info, "severity")))
	if severity == "high" || severity == "critical" {
		return true, "high and critical templates are outside non-intrusive discovery scope"
	}
	tags := stringListValue(mappingValue(info, "tags"))
	for _, tag := range tags {
		if riskyTags[strings.ToLower(strings.TrimSpace(tag))] {
			return true, "risky tag " + tag
		}
	}
	lower := strings.ToLower(strings.Join([]string{
		filePath, scalarValue(mappingValue(mapping, "id")), scalarValue(mappingValue(info, "name")),
		scalarValue(mappingValue(info, "description")), strings.Join(tags, " "),
	}, " "))
	lower = strings.NewReplacer("-", " ", "_", " ", ".", " ", "/", " ", "\\", " ").Replace(lower)
	if strings.HasPrefix(filePath, "http/exposures/") {
		return true, "exposure templates require manual review for returned data"
	}
	if strings.HasPrefix(filePath, "http/misconfiguration/") && !safeMisconfiguration(filePath, scalarValue(mappingValue(info, "name"))) {
		return true, "misconfiguration template is not a minimal health/version probe"
	}
	if strings.HasPrefix(filePath, "http/exposures/backups/") ||
		strings.HasPrefix(filePath, "http/exposures/configs/") ||
		strings.HasPrefix(filePath, "http/exposures/files/") ||
		strings.HasPrefix(filePath, "http/exposures/logs/") ||
		strings.HasPrefix(filePath, "http/exposures/tokens/") {
		return true, "sensitive exposure category"
	}
	for _, phrase := range riskyPhrases {
		if strings.Contains(lower, phrase) {
			return true, "risky or sensitive marker " + phrase
		}
	}
	return false, ""
}

func safeMisconfiguration(filePath, name string) bool {
	summary := strings.ToLower(filePath + " " + name)
	summary = strings.NewReplacer("-", " ", "_", " ", ".", " ", "/", " ", "\\", " ").Replace(summary)
	for _, marker := range []string{" health ", " readiness ", " liveness ", " ping ", " version ", " default page "} {
		if strings.Contains(" "+summary+" ", marker) {
			return true
		}
	}
	return false
}

func hasContentEvidence(rule rulelib.Rule) bool {
	for _, request := range rule.Definition.Requests {
		for _, matcher := range request.Matchers {
			if matcher.Type == "word" || matcher.Type == "regex" {
				return true
			}
		}
	}
	return false
}

func sensitiveRequestPath(rule rulelib.Rule) (string, string) {
	for _, request := range rule.Definition.Requests {
		lower := strings.ToLower(request.Path)
		for _, marker := range []string{
			"/.env", "/.git", "/actuator/configprops", "/actuator/env", "/actuator/logfile",
			"/api/json", "/backup", "/config", "/dump", "/jobs", "/logs", "/projects",
			"/records", "/repositories", "/sessions", "/settings", "/system/properties",
		} {
			if strings.Contains(lower, marker) {
				return request.Path, "path may return configuration, logs, backups, or records"
			}
		}
		if (strings.Contains(lower, "/api/users") || strings.Contains(lower, "/security/users") || strings.Contains(lower, "/users/")) &&
			!strings.Contains(lower, "login") && !strings.Contains(lower, "sign_in") && !strings.Contains(lower, "signin") && !strings.Contains(lower, "signup") {
			return request.Path, "path may return user records"
		}
	}
	return "", ""
}

func normalizedNucleiID(original string) string {
	direct := "nt-" + original
	if len(direct) <= 128 && nucleiIDPattern.MatchString(direct) {
		return direct
	}
	var sanitized strings.Builder
	for _, char := range original {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._:-", char) {
			sanitized.WriteRune(char)
		} else {
			sanitized.WriteByte('-')
		}
	}
	base := strings.Trim(sanitized.String(), "-._:")
	if base == "" {
		base = "template"
	}
	sum := sha256.Sum256([]byte(original))
	suffix := hex.EncodeToString(sum[:8])
	const maxBase = 128 - len("nt--") - 16
	if len(base) > maxBase {
		base = base[:maxBase]
	}
	return "nt-" + base + "-" + suffix
}

func mappingValue(mapping *yaml.Node, name string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == name {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(node.Value)
}

func stringListValue(node *yaml.Node) []string {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		return strings.Split(node.Value, ",")
	}
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	values := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode {
			values = append(values, item.Value)
		}
	}
	return values
}

func inNucleiScope(filePath string) bool {
	cleaned := strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(filePath, "\\", "/")), "/")
	if cleaned != strings.ReplaceAll(filePath, "\\", "/") {
		return false
	}
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(cleaned, prefix) {
			return true
		}
	}
	return false
}

func sourceURL(filePath string) string {
	u := &url.URL{Scheme: "https", Host: "github.com", Path: "/projectdiscovery/nuclei-templates/blob/main/" + filePath}
	return u.String()
}

func isYAML(filePath string) bool {
	lower := strings.ToLower(filePath)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

func findLicense(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for filePath := range files {
		if !strings.Contains(strings.Trim(filePath, "/"), "/") &&
			(strings.EqualFold(filePath, "LICENSE.md") || strings.EqualFold(filePath, "LICENSE")) {
			paths = append(paths, filePath)
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return ""
	}
	return string(files[paths[0]])
}

func digestFiles(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for filePath := range files {
		paths = append(paths, filePath)
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, filePath := range paths {
		_, _ = hash.Write([]byte(filePath))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(files[filePath])
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func reject(catalog *Catalog, sampleCounts map[string]int, filePath, kind, detail string) {
	catalog.Skipped[kind]++
	if len(catalog.Samples) < maxNucleiSamples && sampleCounts[kind] < 5 {
		catalog.Samples = append(catalog.Samples, Rejection{Path: filePath, Reason: kind + ": " + detail})
		sampleCounts[kind]++
	}
}

func fail(kind, format string, args ...any) error {
	return &conversionError{kind: kind, err: fmt.Errorf(format, args...)}
}

func conversionFailure(err error) (string, string) {
	if converted, ok := err.(*conversionError); ok {
		return converted.kind, converted.err.Error()
	}
	return "invalid_yaml", err.Error()
}

func classifyParseFailure(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "path"), strings.Contains(message, "query"), strings.Contains(message, "traversal"):
		return "unsafe_path"
	case strings.Contains(message, "matcher"), strings.Contains(message, "part"):
		return "unsupported_matcher"
	case strings.Contains(message, "header"):
		return "unsafe_header"
	case strings.Contains(message, "exceeds"), strings.Contains(message, "too many"):
		return "limit_exceeded"
	default:
		return "validation_failed"
	}
}
