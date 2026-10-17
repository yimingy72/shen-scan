package rulelib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var nucleiProtocolKeys = map[string]string{
	"http": "http", "requests": "http", "dns": "dns", "network": "tcp", "tcp": "tcp", "whois": "whois",
	"ssl": "ssl", "websocket": "websocket", "headless": "headless", "code": "code",
	"javascript": "javascript", "file": "file", "workflow": "workflow", "workflows": "workflow",
}

func ParseNuclei(content string) (Rule, error) {
	if len(content) == 0 || len(content) > maxTemplateBytes {
		return Rule{}, fmt.Errorf("template must be 1..%d bytes", maxTemplateBytes)
	}
	rule, err := parseNucleiTemplate(content)
	if err != nil {
		return Rule{}, err
	}
	if err := Validate(rule); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

// InspectNucleiTemplate reads index metadata without rewriting the YAML.
func InspectNucleiTemplate(data []byte) (NucleiMetadata, error) {
	if len(data) == 0 || len(data) > maxTemplateBytes {
		return NucleiMetadata{}, fmt.Errorf("template must be 1..%d bytes", maxTemplateBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return NucleiMetadata{}, fmt.Errorf("decode nuclei YAML: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return NucleiMetadata{}, fmt.Errorf("nuclei template root must be a mapping")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return NucleiMetadata{}, fmt.Errorf("nuclei template must contain one YAML document")
	}
	root := document.Content[0]
	templateID := strings.TrimSpace(scalarValue(mappingNode(root, "id")))
	if templateID == "" || len(templateID) > 512 {
		return NucleiMetadata{}, fmt.Errorf("nuclei template has no bounded id")
	}
	infoNode := mappingNode(root, "info")
	if infoNode == nil || infoNode.Kind != yaml.MappingNode {
		return NucleiMetadata{}, fmt.Errorf("nuclei template has no info mapping")
	}
	infoJSON, err := nodeJSON(infoNode)
	if err != nil {
		return NucleiMetadata{}, fmt.Errorf("index nuclei info: %w", err)
	}
	classificationNode := mappingNode(infoNode, "classification")
	var classificationJSON json.RawMessage
	if classificationNode != nil {
		classificationJSON, err = nodeJSON(classificationNode)
		if err != nil {
			return NucleiMetadata{}, fmt.Errorf("index nuclei classification: %w", err)
		}
	}
	protocols := make([]string, 0, 4)
	seenProtocols := map[string]bool{}
	for index := 0; index+1 < len(root.Content); index += 2 {
		if protocol := nucleiProtocolKeys[strings.ToLower(root.Content[index].Value)]; protocol != "" && !seenProtocols[protocol] {
			seenProtocols[protocol] = true
			protocols = append(protocols, protocol)
		}
	}
	sort.Strings(protocols)
	if len(protocols) == 0 {
		return NucleiMetadata{}, fmt.Errorf("nuclei template has no recognized protocol")
	}
	capabilitySet := map[string]bool{}
	collectNucleiCapabilities(root, capabilitySet)
	capabilities := sortedSet(capabilitySet)
	return NucleiMetadata{
		TemplateID: templateID, Protocols: protocols, Raw: capabilitySet["raw"], Capabilities: capabilities,
		Info: infoJSON, Classification: classificationJSON, RequestCount: estimateNucleiRequests(root, capabilitySet),
	}, nil
}

func validateNucleiMetadata(template string, metadata *NucleiMetadata) error {
	if metadata == nil {
		return fmt.Errorf("nuclei metadata is required")
	}
	if metadata.ExecutionProfile != "" {
		if metadata.ExecutionProfile != NucleiExecutionProfileHTTPBasic {
			return fmt.Errorf("unsupported nuclei execution profile %q", metadata.ExecutionProfile)
		}
		analysis, err := AnalyzeNucleiOriginal([]byte(template))
		if err != nil {
			return err
		}
		indexed := analysis.Metadata
		if metadata.TemplateID != indexed.TemplateID || metadata.ContentSHA256 != indexed.ContentSHA256 ||
			metadata.Raw != indexed.Raw || !equalStrings(metadata.Protocols, indexed.Protocols) ||
			!equalStrings(metadata.Capabilities, indexed.Capabilities) || !equalOptionalInt(metadata.RequestCount, indexed.RequestCount) ||
			!equalJSON(metadata.Info, indexed.Info) || !equalJSON(metadata.Classification, indexed.Classification) {
			return fmt.Errorf("executable nuclei metadata does not match the original template")
		}
		if metadata.CatalogOnly || metadata.RuntimeReason != "" {
			return fmt.Errorf("executable nuclei metadata cannot be catalog-only")
		}
		return nil
	}
	if metadata.ContentSHA256 != "" {
		return fmt.Errorf("content_sha256 requires an execution profile")
	}
	indexed, err := InspectNucleiTemplate([]byte(template))
	if err != nil {
		return err
	}
	if metadata.TemplateID != indexed.TemplateID || metadata.Raw != indexed.Raw ||
		!equalStrings(metadata.Protocols, indexed.Protocols) || !equalStrings(metadata.Capabilities, indexed.Capabilities) ||
		!equalOptionalInt(metadata.RequestCount, indexed.RequestCount) || !equalJSON(metadata.Info, indexed.Info) ||
		!equalJSON(metadata.Classification, indexed.Classification) {
		return fmt.Errorf("nuclei metadata does not match the original template")
	}
	if len(metadata.DefaultDisabledReason) > 1024 || len(metadata.RuntimeReason) > 1024 {
		return fmt.Errorf("nuclei runtime/default reason is too long")
	}
	return nil
}

func collectNucleiCapabilities(node *yaml.Node, found map[string]bool) {
	if node == nil {
		return
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := strings.ToLower(node.Content[index].Value)
			switch key {
			case "raw", "dsl", "flow", "code", "headless", "javascript", "payloads", "fuzz", "fuzzing",
				"extractors", "interactsh", "workflows", "workflow", "race", "attack", "redirects":
				found[key] = true
			}
			collectNucleiCapabilities(node.Content[index+1], found)
		}
	} else {
		for _, child := range node.Content {
			collectNucleiCapabilities(child, found)
		}
	}
	if node.Kind == yaml.ScalarNode && strings.Contains(strings.ToLower(node.Value), "interactsh") {
		found["interactsh"] = true
	}
}

func estimateNucleiRequests(root *yaml.Node, capabilities map[string]bool) *int {
	for _, dynamic := range []string{"flow", "payloads", "fuzz", "fuzzing", "race", "attack", "workflow", "workflows"} {
		if capabilities[dynamic] {
			return nil
		}
	}
	total := 0
	for index := 0; index+1 < len(root.Content); index += 2 {
		key := strings.ToLower(root.Content[index].Value)
		if nucleiProtocolKeys[key] == "" {
			continue
		}
		section := root.Content[index+1]
		if section.Kind != yaml.SequenceNode {
			total++
			continue
		}
		for _, request := range section.Content {
			count := 1
			if request.Kind == yaml.MappingNode {
				for _, field := range []string{"path", "raw", "inputs"} {
					if value := mappingNode(request, field); value != nil && value.Kind == yaml.SequenceNode && len(value.Content) > count {
						count = len(value.Content)
					}
				}
			}
			total += count
		}
	}
	if total == 0 {
		return nil
	}
	return &total
}

func mappingNode(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if strings.EqualFold(node.Content[index].Value, key) {
			return node.Content[index+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func nodeJSON(node *yaml.Node) (json.RawMessage, error) {
	var value any
	if err := node.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func sortedSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalOptionalInt(left, right *int) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalJSON(left, right json.RawMessage) bool {
	if len(left) == 0 || len(right) == 0 {
		return len(left) == len(right)
	}
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil && json.Unmarshal(right, &rightValue) == nil &&
		reflect.DeepEqual(leftValue, rightValue)
}
