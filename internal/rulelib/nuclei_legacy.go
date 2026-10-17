package rulelib

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

type nucleiTemplate struct {
	ID   string       `yaml:"id"`
	Info nucleiInfo   `yaml:"info"`
	HTTP []nucleiHTTP `yaml:"http"`
}

type nucleiInfo struct {
	Name           string                 `yaml:"name"`
	Author         stringList             `yaml:"author,omitempty"`
	Severity       string                 `yaml:"severity"`
	Description    string                 `yaml:"description,omitempty"`
	Tags           stringList             `yaml:"tags,omitempty"`
	Reference      stringList             `yaml:"reference,omitempty"`
	Remediation    string                 `yaml:"remediation,omitempty"`
	Metadata       map[string]interface{} `yaml:"metadata,omitempty"`
	Classification map[string]interface{} `yaml:"classification,omitempty"`
}

type nucleiHTTP struct {
	Method            string            `yaml:"method,omitempty"`
	Path              []string          `yaml:"path"`
	Headers           map[string]string `yaml:"headers,omitempty"`
	MatchersCondition string            `yaml:"matchers-condition,omitempty"`
	Matchers          []nucleiMatcher   `yaml:"matchers"`
}

type nucleiMatcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part,omitempty"`
	Words           []string `yaml:"words,omitempty"`
	Regex           []string `yaml:"regex,omitempty"`
	Status          []int    `yaml:"status,omitempty"`
	Condition       string   `yaml:"condition,omitempty"`
	Negative        bool     `yaml:"negative,omitempty"`
	CaseInsensitive bool     `yaml:"case-insensitive,omitempty"`
}

type stringList []string

func (s *stringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var value string
		if err := node.Decode(&value); err != nil {
			return err
		}
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				*s = append(*s, item)
			}
		}
		return nil
	case yaml.SequenceNode:
		return node.Decode((*[]string)(s))
	default:
		return fmt.Errorf("must be a string or string list")
	}
}

func parseNucleiTemplate(content string) (Rule, error) {
	root, normalized, err := decodeYAMLNode(content)
	if err != nil {
		return Rule{}, err
	}
	if err := validateYAMLTree(root, 0); err != nil {
		return Rule{}, err
	}
	decoder := yaml.NewDecoder(strings.NewReader(content))
	decoder.KnownFields(true)
	var template nucleiTemplate
	if err := decoder.Decode(&template); err != nil {
		return Rule{}, fmt.Errorf("decode template: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return Rule{}, fmt.Errorf("template must contain one YAML document")
	}
	if len(template.HTTP) == 0 {
		return Rule{}, fmt.Errorf("template must contain HTTP requests")
	}
	requests := make([]Request, 0, maxRequests)
	for index, block := range template.HTTP {
		method := strings.ToUpper(strings.TrimSpace(block.Method))
		if method == "" {
			method = "GET"
		}
		if method != "GET" && method != "HEAD" {
			return Rule{}, fmt.Errorf("http block %d method must be GET or HEAD", index+1)
		}
		if len(block.Path) == 0 {
			return Rule{}, fmt.Errorf("http block %d has no paths", index+1)
		}
		if err := validateImportedHeaders(block.Headers); err != nil {
			return Rule{}, fmt.Errorf("http block %d: %w", index+1, err)
		}
		matchers := make([]Matcher, len(block.Matchers))
		for matcherIndex, matcher := range block.Matchers {
			typeName := strings.ToLower(strings.TrimSpace(matcher.Type))
			part := strings.ToLower(strings.TrimSpace(matcher.Part))
			if part == "" {
				part = "body"
				if typeName == "status" {
					part = "status"
				}
			}
			condition := strings.ToLower(strings.TrimSpace(matcher.Condition))
			if condition == "" {
				condition = "or"
			}
			matchers[matcherIndex] = Matcher{Part: part, Type: typeName, Words: matcher.Words, Regex: matcher.Regex,
				Status: matcher.Status, Condition: condition, Negative: matcher.Negative, CaseSensitive: !matcher.CaseInsensitive}
		}
		condition := strings.ToLower(strings.TrimSpace(block.MatchersCondition))
		if condition == "" {
			condition = "and"
		}
		for _, rawPath := range block.Path {
			requestPath, err := importedPath(rawPath)
			if err != nil {
				return Rule{}, fmt.Errorf("http block %d: %w", index+1, err)
			}
			requests = append(requests, Request{Method: method, Path: requestPath, Headers: block.Headers, Condition: condition, Matchers: matchers})
			if len(requests) > maxRequests {
				return Rule{}, fmt.Errorf("template exceeds %d HTTP requests/paths", maxRequests)
			}
		}
	}
	severity := strings.ToLower(strings.TrimSpace(template.Info.Severity))
	if severity == "unknown" || severity == "" {
		severity = "info"
	}
	return Rule{
		ID: template.ID, Kind: "poc", Name: template.Info.Name, Description: template.Info.Description,
		Engine: "nuclei", Severity: severity, Enabled: false, Builtin: false, Revision: 1,
		Tags: []string(template.Info.Tags), AppliesTo: metadataProducts(template.Info.Metadata),
		Source: "Imported read-only Nuclei HTTP template", Definition: Definition{Service: "http", Condition: "and", Requests: requests},
		Template: normalized,
	}, nil
}

func metadataProducts(metadata map[string]interface{}) []string {
	value, ok := metadata["product"]
	if !ok {
		return nil
	}
	var products []string
	switch value := value.(type) {
	case string:
		for _, product := range strings.Split(value, ",") {
			if product = strings.TrimSpace(product); product != "" {
				products = append(products, product)
			}
		}
	case []interface{}:
		for _, item := range value {
			if product, ok := item.(string); ok && strings.TrimSpace(product) != "" {
				products = append(products, strings.TrimSpace(product))
			}
		}
	}
	return products
}

func decodeYAMLNode(content string) (*yaml.Node, string, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, "", fmt.Errorf("decode YAML: %w", err)
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, "", fmt.Errorf("template root must be a mapping")
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(root.Content[0]); err != nil {
		return nil, "", fmt.Errorf("normalize YAML: %w", err)
	}
	_ = encoder.Close()
	return root.Content[0], output.String(), nil
}

func validateYAMLTree(node *yaml.Node, depth int) error {
	if depth > 16 {
		return fmt.Errorf("YAML nesting is too deep")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("YAML anchors and aliases are not allowed")
	}
	if node.Kind == yaml.ScalarNode && len(node.Value) > 8192 {
		return fmt.Errorf("YAML scalar is too large")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]bool, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || seen[key.Value] {
				return fmt.Errorf("YAML mapping keys must be unique strings")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateYAMLTree(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func validateImportedHeaders(headers map[string]string) error {
	for name, value := range headers {
		if !oneOf(strings.ToLower(name), "accept", "accept-language", "accept-encoding", "user-agent", "cache-control", "pragma") {
			return fmt.Errorf("header %q is outside the read-only subset", name)
		}
		if strings.Contains(value, "{{") || strings.Contains(strings.ToLower(value), "interactsh") {
			return fmt.Errorf("dynamic or external-callback header values are not allowed")
		}
	}
	return nil
}

func importedPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	requestPath := ""
	for _, prefix := range []string{"{{BaseURL}}", "{{RootURL}}"} {
		if value == prefix {
			requestPath = "/"
			break
		}
		if strings.HasPrefix(value, prefix+"/") {
			requestPath = strings.TrimPrefix(value, prefix)
			break
		}
	}
	if requestPath == "" || strings.Contains(requestPath, "{{") || strings.Contains(strings.ToLower(requestPath), "interactsh") {
		return "", fmt.Errorf("path must be static and rooted at {{BaseURL}} or {{RootURL}}")
	}
	if err := validateStaticPath(requestPath); err != nil {
		return "", err
	}
	return requestPath, nil
}
