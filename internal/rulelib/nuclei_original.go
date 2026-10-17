package rulelib

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	// NucleiExecutionProfileHTTPBasic marks rules executed from their original
	// YAML bytes with the narrow HTTP request subset checked below.
	NucleiExecutionProfileHTTPBasic = "http-basic-v1"
	maxOriginalTemplateBytes        = 256 << 10
)

type NucleiOriginalRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Root   bool   `json:"root"`
}

type NucleiOriginalPlan struct {
	TemplateID             string                  `json:"template_id"`
	ContentSHA256          string                  `json:"content_sha256"`
	Requests               []NucleiOriginalRequest `json:"requests"`
	HasNegativeBodyMatcher bool                    `json:"has_negative_body_matcher,omitempty"`
}

type NucleiOriginalAnalysis struct {
	Metadata    NucleiMetadata
	Plan        NucleiOriginalPlan
	Name        string
	Description string
	Severity    string
	Tags        []string
	Products    []string
}

var nucleiOriginalRootFields = map[string]bool{
	"id": true, "info": true, "http": true, "requests": true,
}

var nucleiOriginalInfoFields = map[string]bool{
	"name": true, "author": true, "severity": true, "description": true, "tags": true,
	"reference": true, "remediation": true, "metadata": true, "classification": true,
	"impact": true, "solution": true,
}

var nucleiOriginalHTTPFields = map[string]bool{
	"method": true, "path": true, "headers": true, "matchers-condition": true, "matchers": true,
}

var nucleiOriginalMatcherFields = map[string]bool{
	"type": true, "part": true, "words": true, "regex": true, "status": true,
	"condition": true, "negative": true, "case-insensitive": true,
}

// ParseNucleiOriginal builds an executable PoC rule while retaining the exact
// uploaded YAML bytes. Nuclei, not the platform, evaluates matchers.
func ParseNucleiOriginal(content string) (Rule, error) {
	if len(content) == 0 || len(content) > maxOriginalTemplateBytes {
		return Rule{}, fmt.Errorf("original nuclei template must be 1..%d bytes", maxOriginalTemplateBytes)
	}
	analysis, err := AnalyzeNucleiOriginal([]byte(content))
	if err != nil {
		return Rule{}, err
	}
	if len(analysis.Products) == 0 {
		return Rule{}, fmt.Errorf("http-basic-v1 requires an explicit info.metadata.product binding")
	}
	rule := Rule{
		ID: originalRuleID(analysis.Plan.TemplateID, analysis.Plan.ContentSHA256), Kind: "poc", Purpose: "check",
		Name: analysis.Name, Description: analysis.Description, Engine: "nuclei", Severity: analysis.Severity,
		Enabled: false, Builtin: false, Revision: 1, Tags: analysis.Tags, AppliesTo: analysis.Products,
		Source: "Imported original Nuclei HTTP YAML", Nuclei: &analysis.Metadata, Template: content,
	}
	if err := Validate(rule); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

// AnalyzeNucleiOriginal validates the compatibility subset and extracts only
// the information needed for dispatch and proxy scope. It never re-encodes YAML.
func AnalyzeNucleiOriginal(data []byte) (NucleiOriginalAnalysis, error) {
	if len(data) == 0 || len(data) > maxOriginalTemplateBytes {
		return NucleiOriginalAnalysis{}, fmt.Errorf("original nuclei template must be 1..%d bytes", maxOriginalTemplateBytes)
	}
	if !utf8.Valid(data) {
		return NucleiOriginalAnalysis{}, fmt.Errorf("original nuclei template must be UTF-8")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return NucleiOriginalAnalysis{}, fmt.Errorf("decode nuclei YAML: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return NucleiOriginalAnalysis{}, fmt.Errorf("nuclei template must contain exactly one YAML document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return NucleiOriginalAnalysis{}, fmt.Errorf("nuclei template root must be a mapping")
	}
	root := document.Content[0]
	if err := validateOriginalYAML(root, "$"); err != nil {
		return NucleiOriginalAnalysis{}, err
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		key := root.Content[index].Value
		if !nucleiOriginalRootFields[key] {
			return NucleiOriginalAnalysis{}, unsupportedNucleiField("$." + key)
		}
	}
	templateID := strings.TrimSpace(scalarValue(mappingNode(root, "id")))
	if templateID == "" || len(templateID) > 512 {
		return NucleiOriginalAnalysis{}, fmt.Errorf("nuclei template has no bounded id")
	}
	infoNode := mappingNode(root, "info")
	if infoNode == nil || infoNode.Kind != yaml.MappingNode {
		return NucleiOriginalAnalysis{}, fmt.Errorf("nuclei template has no info mapping")
	}
	if err := validateOriginalInfo(infoNode); err != nil {
		return NucleiOriginalAnalysis{}, err
	}
	name := strings.TrimSpace(scalarValue(mappingNode(infoNode, "name")))
	if name == "" || len(name) > 200 {
		return NucleiOriginalAnalysis{}, fmt.Errorf("info.name must be 1..200 bytes")
	}
	severity := strings.ToLower(strings.TrimSpace(scalarValue(mappingNode(infoNode, "severity"))))
	if severity == "" || severity == "unknown" {
		severity = "info"
	}
	if !oneOf(severity, "info", "low", "medium", "high", "critical") {
		return NucleiOriginalAnalysis{}, fmt.Errorf("unsupported info.severity %q", severity)
	}
	author, err := scalarList(mappingNode(infoNode, "author"), 32, 128)
	if err != nil {
		return NucleiOriginalAnalysis{}, fmt.Errorf("info.author: %w", err)
	}
	if len(author) == 0 {
		return NucleiOriginalAnalysis{}, fmt.Errorf("info.author is required by nuclei strict syntax")
	}
	description := scalarValue(mappingNode(infoNode, "description"))
	if len(description) > 4096 {
		return NucleiOriginalAnalysis{}, fmt.Errorf("info.description exceeds 4096 bytes")
	}
	tags, err := scalarList(mappingNode(infoNode, "tags"), 32, 64)
	if err != nil {
		return NucleiOriginalAnalysis{}, fmt.Errorf("info.tags: %w", err)
	}
	infoJSON, err := nodeJSON(infoNode)
	if err != nil {
		return NucleiOriginalAnalysis{}, fmt.Errorf("index nuclei info: %w", err)
	}
	classificationNode := mappingNode(infoNode, "classification")
	var classificationJSON json.RawMessage
	if classificationNode != nil {
		classificationJSON, err = nodeJSON(classificationNode)
		if err != nil {
			return NucleiOriginalAnalysis{}, fmt.Errorf("index nuclei classification: %w", err)
		}
	}
	products, err := originalProducts(mappingNode(infoNode, "metadata"))
	if err != nil {
		return NucleiOriginalAnalysis{}, err
	}

	httpNode := mappingNode(root, "http")
	if requestsNode := mappingNode(root, "requests"); requestsNode != nil {
		if httpNode != nil {
			return NucleiOriginalAnalysis{}, fmt.Errorf("nuclei template cannot contain both http and requests")
		}
		httpNode = requestsNode
	}
	if httpNode == nil || httpNode.Kind != yaml.SequenceNode || len(httpNode.Content) == 0 {
		return NucleiOriginalAnalysis{}, fmt.Errorf("nuclei template must contain a non-empty http sequence")
	}
	requests := make([]NucleiOriginalRequest, 0, maxRequests)
	negativeBody := false
	for blockIndex, block := range httpNode.Content {
		if block.Kind != yaml.MappingNode {
			return NucleiOriginalAnalysis{}, fmt.Errorf("$.http[%d] must be a mapping", blockIndex+1)
		}
		base := fmt.Sprintf("$.http[%d]", blockIndex+1)
		for index := 0; index+1 < len(block.Content); index += 2 {
			key := block.Content[index].Value
			if !nucleiOriginalHTTPFields[key] {
				return NucleiOriginalAnalysis{}, unsupportedNucleiField(base + "." + key)
			}
		}
		method := strings.ToUpper(strings.TrimSpace(scalarValue(mappingNode(block, "method"))))
		if method == "" {
			method = "GET"
		}
		if method != "GET" && method != "HEAD" {
			return NucleiOriginalAnalysis{}, fmt.Errorf("%s.method must be GET or HEAD", base)
		}
		if headers := mappingNode(block, "headers"); headers != nil {
			var values map[string]string
			if headers.Kind != yaml.MappingNode || headers.Decode(&values) != nil {
				return NucleiOriginalAnalysis{}, fmt.Errorf("%s.headers must be a string mapping", base)
			}
			if err := validateImportedHeaders(values); err != nil {
				return NucleiOriginalAnalysis{}, fmt.Errorf("%s.headers: %w", base, err)
			}
		}
		if condition := strings.ToLower(strings.TrimSpace(scalarValue(mappingNode(block, "matchers-condition")))); condition != "" && condition != "and" && condition != "or" {
			return NucleiOriginalAnalysis{}, fmt.Errorf("%s.matchers-condition must be and or or", base)
		}
		matchers := mappingNode(block, "matchers")
		if matchers == nil || matchers.Kind != yaml.SequenceNode || len(matchers.Content) == 0 {
			return NucleiOriginalAnalysis{}, fmt.Errorf("%s.matchers must contain at least one matcher", base)
		}
		for matcherIndex, matcher := range matchers.Content {
			path := fmt.Sprintf("%s.matchers[%d]", base, matcherIndex+1)
			negative, err := validateOriginalMatcher(matcher, path)
			if err != nil {
				return NucleiOriginalAnalysis{}, err
			}
			negativeBody = negativeBody || negative
		}
		paths := mappingNode(block, "path")
		if paths == nil {
			return NucleiOriginalAnalysis{}, fmt.Errorf("%s.path is required", base)
		}
		items := []*yaml.Node{paths}
		if paths.Kind == yaml.SequenceNode {
			items = paths.Content
		} else if paths.Kind != yaml.ScalarNode {
			return NucleiOriginalAnalysis{}, fmt.Errorf("%s.path must be a string or string list", base)
		}
		if len(items) == 0 {
			return NucleiOriginalAnalysis{}, fmt.Errorf("%s.path must not be empty", base)
		}
		for pathIndex, item := range items {
			request, err := originalRequestPath(item, method)
			if err != nil {
				return NucleiOriginalAnalysis{}, fmt.Errorf("%s.path[%d]: %w", base, pathIndex+1, err)
			}
			requests = append(requests, request)
			if len(requests) > maxRequests {
				return NucleiOriginalAnalysis{}, fmt.Errorf("template exceeds %d HTTP requests/paths", maxRequests)
			}
		}
	}
	digest := sha256.Sum256(data)
	contentSHA := hex.EncodeToString(digest[:])
	requestCount := len(requests)
	metadata := NucleiMetadata{
		TemplateID: templateID, ExecutionProfile: NucleiExecutionProfileHTTPBasic, ContentSHA256: contentSHA,
		Protocols: []string{"http"}, Capabilities: []string{}, Info: infoJSON, Classification: classificationJSON,
		RequestCount: &requestCount,
	}
	return NucleiOriginalAnalysis{
		Metadata: metadata, Plan: NucleiOriginalPlan{TemplateID: templateID, ContentSHA256: contentSHA,
			Requests: requests, HasNegativeBodyMatcher: negativeBody},
		Name: name, Description: description, Severity: severity, Tags: tags, Products: products,
	}, nil
}

// ResolveNucleiOriginalRequests maps BaseURL/RootURL path expressions to the
// concrete origin-relative paths the scope proxy must allow.
func ResolveNucleiOriginalRequests(plan NucleiOriginalPlan, base *url.URL) ([]Request, error) {
	if base == nil || (base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" || base.User != nil {
		return nil, fmt.Errorf("invalid nuclei base URL")
	}
	prefix := strings.TrimSuffix(base.EscapedPath(), "/")
	result := make([]Request, 0, len(plan.Requests))
	for _, item := range plan.Requests {
		path := item.Path
		if item.Root {
			if path == "" {
				path = "/"
			}
		} else if path == "" {
			path = prefix
			if path == "" {
				path = "/"
			}
		} else {
			path = prefix + path
		}
		if err := validateStaticPath(path); err != nil {
			return nil, fmt.Errorf("resolved request path: %w", err)
		}
		result = append(result, Request{Method: item.Method, Path: path})
	}
	return result, nil
}

func originalRuleID(templateID, digest string) string {
	var builder strings.Builder
	lastDash := false
	for _, value := range templateID {
		allowed := value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
			value >= '0' && value <= '9' || strings.ContainsRune("._:-", value)
		if !allowed {
			if !lastDash && builder.Len() > 0 {
				builder.WriteByte('-')
				lastDash = true
			}
			continue
		}
		builder.WriteRune(value)
		lastDash = value == '-'
	}
	safe := strings.Trim(builder.String(), ".-_:")
	if safe == "" {
		safe = "template"
	}
	if len(safe) > 96 {
		safe = strings.TrimRight(safe[:96], ".-_:")
	}
	if len(digest) < 8 {
		digest = digest + strings.Repeat("0", 8-len(digest))
	}
	return "nuclei-" + safe + "-" + strings.ToLower(digest[:8])
}

func validateOriginalYAML(node *yaml.Node, path string) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("%s: YAML anchors and aliases are not allowed", path)
	}
	if node.Kind == yaml.ScalarNode && len(node.Value) > 8192 {
		return fmt.Errorf("%s: scalar exceeds 8192 bytes", path)
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]bool, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Value == "" || seen[key.Value] {
				return fmt.Errorf("%s: YAML mapping keys must be unique non-empty strings", path)
			}
			seen[key.Value] = true
		}
	}
	if len(path) > 512 {
		return fmt.Errorf("%s: YAML nesting path is too long", path)
	}
	for index, child := range node.Content {
		childPath := path
		if node.Kind == yaml.MappingNode && index%2 == 1 {
			childPath = path + "." + node.Content[index-1].Value
		} else if node.Kind == yaml.SequenceNode {
			childPath = path + "[" + strconv.Itoa(index+1) + "]"
		}
		if err := validateOriginalYAML(child, childPath); err != nil {
			return err
		}
	}
	return nil
}

func validateOriginalInfo(info *yaml.Node) error {
	for index := 0; index+1 < len(info.Content); index += 2 {
		key := info.Content[index].Value
		if !nucleiOriginalInfoFields[key] {
			return unsupportedNucleiField("$.info." + key)
		}
	}
	for _, name := range []string{"metadata", "classification"} {
		value := mappingNode(info, name)
		if value == nil {
			continue
		}
		if value.Kind != yaml.MappingNode {
			return fmt.Errorf("$.info.%s must be a mapping", name)
		}
		if err := validateNucleiMetadataValue(value, "$.info."+name, 0); err != nil {
			return err
		}
	}
	return nil
}

func validateNucleiMetadataValue(node *yaml.Node, path string, depth int) error {
	if depth > 6 {
		return fmt.Errorf("%s: metadata nesting is too deep", path)
	}
	switch node.Kind {
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			if err := validateNucleiMetadataValue(node.Content[index+1], path+"."+node.Content[index].Value, depth+1); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if len(node.Content) > 64 {
			return fmt.Errorf("%s: metadata list exceeds 64 items", path)
		}
		for index, child := range node.Content {
			if err := validateNucleiMetadataValue(child, path+"["+strconv.Itoa(index+1)+"]", depth+1); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if len(node.Value) > 4096 {
			return fmt.Errorf("%s: metadata value exceeds 4096 bytes", path)
		}
	default:
		return fmt.Errorf("%s: unsupported metadata value", path)
	}
	return nil
}

func originalProducts(metadata *yaml.Node) ([]string, error) {
	if metadata == nil {
		return nil, nil
	}
	if metadata.Kind == yaml.ScalarNode && metadata.Tag == "!!null" {
		return nil, nil
	}
	if metadata.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("info.metadata must be a mapping")
	}
	productNode := mappingNode(metadata, "product")
	if productNode == nil {
		return nil, nil
	}
	values, err := scalarList(productNode, 32, 128)
	if err != nil {
		return nil, fmt.Errorf("info.metadata.product: %w", err)
	}
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(value), "cpe:") {
			continue
		}
		normalized := normalizeProduct(value)
		if normalized == "" || prohibitedProductBinding(normalized) || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, value)
	}
	return result, nil
}

func validateOriginalMatcher(node *yaml.Node, path string) (bool, error) {
	if node == nil || node.Kind != yaml.MappingNode {
		return false, fmt.Errorf("%s must be a mapping", path)
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if !nucleiOriginalMatcherFields[key] {
			return false, unsupportedNucleiField(path + "." + key)
		}
	}
	typeName := strings.ToLower(strings.TrimSpace(scalarValue(mappingNode(node, "type"))))
	if typeName == "" {
		return false, fmt.Errorf("%s.type is required", path)
	}
	if typeName != "word" && typeName != "regex" && typeName != "status" {
		return false, fmt.Errorf("%s.type %q is outside the supported word/regex/status subset", path, typeName)
	}
	part := strings.ToLower(strings.TrimSpace(scalarValue(mappingNode(node, "part"))))
	if part == "" {
		part = "body"
		if typeName == "status" {
			part = "status"
		}
	}
	if typeName == "status" {
		if part != "status" {
			return false, fmt.Errorf("%s.part must be status for a status matcher", path)
		}
		statuses, err := integerList(mappingNode(node, "status"), 32)
		if err != nil {
			return false, fmt.Errorf("%s.status: %w", path, err)
		}
		if len(statuses) == 0 {
			return false, fmt.Errorf("%s.status must not be empty", path)
		}
		for _, status := range statuses {
			if status < 100 || status > 599 {
				return false, fmt.Errorf("%s.status contains invalid HTTP status %d", path, status)
			}
		}
	} else {
		if part != "body" && part != "header" && part != "all" {
			return false, fmt.Errorf("%s.part %q is outside the supported body/header/all subset", path, part)
		}
		values, err := scalarList(mappingNode(node, typeName+"s"), 32, 4096)
		if err != nil {
			return false, fmt.Errorf("%s.%ss: %w", path, typeName, err)
		}
		if len(values) == 0 {
			return false, fmt.Errorf("%s.%ss must not be empty", path, typeName)
		}
		for _, value := range values {
			if strings.Contains(value, "{{") || strings.Contains(strings.ToLower(value), "interactsh") {
				return false, fmt.Errorf("%s.%ss contains a dynamic or external-callback value", path, typeName)
			}
			if typeName == "regex" {
				if _, err := compilePattern(matcherPattern(value, false)); err != nil {
					return false, fmt.Errorf("%s.regex: %w", path, err)
				}
			}
		}
	}
	if condition := strings.ToLower(strings.TrimSpace(scalarValue(mappingNode(node, "condition")))); condition != "" && condition != "and" && condition != "or" {
		return false, fmt.Errorf("%s.condition must be and or or", path)
	}
	negative := false
	if value := mappingNode(node, "negative"); value != nil {
		if value.Kind != yaml.ScalarNode || (value.Value != "true" && value.Value != "false") {
			return false, fmt.Errorf("%s.negative must be a boolean", path)
		}
		negative = value.Value == "true"
	}
	if value := mappingNode(node, "case-insensitive"); value != nil {
		if value.Kind != yaml.ScalarNode || (value.Value != "true" && value.Value != "false") {
			return false, fmt.Errorf("%s.case-insensitive must be a boolean", path)
		}
	}
	return negative && (part == "body" || part == "all"), nil
}

func originalRequestPath(node *yaml.Node, method string) (NucleiOriginalRequest, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return NucleiOriginalRequest{}, fmt.Errorf("path must be a string")
	}
	value := strings.TrimSpace(node.Value)
	root := false
	suffix := ""
	switch {
	case value == "{{BaseURL}}":
		suffix = ""
	case strings.HasPrefix(value, "{{BaseURL}}/"):
		suffix = strings.TrimPrefix(value, "{{BaseURL}}")
	case value == "{{RootURL}}":
		root, suffix = true, ""
	case strings.HasPrefix(value, "{{RootURL}}/"):
		root, suffix = true, strings.TrimPrefix(value, "{{RootURL}}")
	default:
		return NucleiOriginalRequest{}, fmt.Errorf("path must be static and rooted at {{BaseURL}} or {{RootURL}}")
	}
	if len(value) > 1024 || strings.Contains(suffix, "{{") || strings.ContainsAny(suffix, "\\#?\r\n\x00") {
		return NucleiOriginalRequest{}, fmt.Errorf("path must be a static request path without query, fragment, dynamic values, or control characters")
	}
	if suffix != "" {
		if err := validateStaticPath(suffix); err != nil {
			return NucleiOriginalRequest{}, err
		}
	}
	return NucleiOriginalRequest{Method: method, Path: suffix, Root: root}, nil
}

func scalarList(node *yaml.Node, maxItems, maxBytes int) ([]string, error) {
	if node == nil {
		return nil, nil
	}
	values := make([]string, 0, 4)
	add := func(value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if len(value) > maxBytes {
			return fmt.Errorf("value exceeds %d bytes", maxBytes)
		}
		values = append(values, value)
		if len(values) > maxItems {
			return fmt.Errorf("list exceeds %d items", maxItems)
		}
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		for _, value := range strings.Split(node.Value, ",") {
			if err := add(value); err != nil {
				return nil, err
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if child.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("list items must be scalar values")
			}
			if err := add(child.Value); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("must be a string or string list")
	}
	return values, nil
}

func integerList(node *yaml.Node, maxItems int) ([]int, error) {
	if node == nil {
		return nil, nil
	}
	values := make([]int, 0, 4)
	add := func(value string) error {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("status must be an integer")
		}
		values = append(values, parsed)
		if len(values) > maxItems {
			return fmt.Errorf("list exceeds %d items", maxItems)
		}
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if err := add(node.Value); err != nil {
			return nil, err
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if child.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("status values must be integers")
			}
			if err := add(child.Value); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("status must be an integer or integer list")
	}
	return values, nil
}

func unsupportedNucleiField(path string) error {
	return fmt.Errorf("unsupported http-basic-v1 field %s", path)
}
