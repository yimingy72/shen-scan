package rulesource

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"scanplatform/internal/rulelib"
)

const (
	nucleiRepository = "https://github.com/projectdiscovery/nuclei-templates"
	nucleiLicense    = "MIT"
)

func ConvertNuclei(files map[string][]byte) (Catalog, error) {
	licenseText := findLicense(files)
	if !strings.Contains(licenseText, "MIT License") {
		return Catalog{}, fmt.Errorf("official MIT LICENSE.md is missing")
	}
	paths := make([]string, 0, len(files))
	for filePath := range files {
		paths = append(paths, filePath)
	}
	sort.Strings(paths)
	catalog := Catalog{
		Rules: make([]rulelib.Rule, 0, len(paths)), Skipped: map[string]int{}, Repository: nucleiRepository,
		License: nucleiLicense, LicenseText: licenseText, Digest: digestArchiveFiles(files),
	}
	for _, filePath := range paths {
		data := files[filePath]
		if !isYAML(filePath) {
			catalog.Files = append(catalog.Files, sourceFile(filePath, data))
			continue
		}
		catalog.Total++
		metadata, err := rulelib.InspectNucleiTemplate(data)
		if err != nil {
			catalog.Skipped["not_template"]++
			addSample(&catalog, filePath, err.Error())
			catalog.Files = append(catalog.Files, sourceFile(filePath, data))
			continue
		}
		rule, err := nucleiSourceRule(filePath, data, metadata)
		if err != nil {
			catalog.Skipped["invalid_template"]++
			addSample(&catalog, filePath, err.Error())
			catalog.Files = append(catalog.Files, sourceFile(filePath, data))
			continue
		}
		catalog.Rules = append(catalog.Rules, rule)
	}
	return catalog, nil
}

func nucleiSourceRule(filePath string, data []byte, metadata rulelib.NucleiMetadata) (rulelib.Rule, error) {
	var info map[string]any
	if err := json.Unmarshal(metadata.Info, &info); err != nil {
		return rulelib.Rule{}, err
	}
	tags := sourceListValue(info["tags"])
	purpose, kind := nucleiPurpose(filePath, metadata.Classification, tags)
	runtimeReason := nucleiRuntimeReason(metadata)
	riskReason := nucleiRiskReason(filePath, tags, metadata.Capabilities)
	metadata.CatalogOnly = true
	metadata.RuntimeReason = runtimeReason
	metadata.DefaultDisabledReason = riskReason
	name := sourceStringValue(info["name"])
	if name == "" {
		name = metadata.TemplateID
	}
	severity := strings.ToLower(sourceStringValue(info["severity"]))
	if severity != "info" && severity != "low" && severity != "medium" && severity != "high" && severity != "critical" {
		severity = "info"
	}
	digest := sha256.Sum256(data)
	rule := rulelib.Rule{
		ID: stableNucleiSourceID(metadata.TemplateID, filePath), Kind: kind, Purpose: purpose,
		Name: truncateSourceText(name, 200), Description: truncateSourceText(sourceStringValue(info["description"]), 4096),
		Engine: "nuclei", Severity: severity, Enabled: false, Builtin: false, Revision: 1,
		Tags: boundedSourceValues(tags, 32, 64), Source: nucleiRepository, Template: string(data), Nuclei: &metadata,
		Upstream: &rulelib.Upstream{SourceID: NucleiID, Path: filePath, SHA256: hex.EncodeToString(digest[:])},
	}
	if kind == "poc" {
		rule.AppliesTo = boundedProducts(sourceProducts(info))
	}
	if err := rulelib.Validate(rule); err != nil {
		return rulelib.Rule{}, err
	}
	return rule, nil
}

func nucleiPurpose(filePath string, classification json.RawMessage, tags []string) (string, string) {
	clean := strings.ToLower(path.Clean(filePath))
	if strings.HasPrefix(clean, "http/technologies/") || strings.HasPrefix(clean, "http/exposed-panels/") {
		return "discovery", "http"
	}
	if strings.Contains(clean, "/cves/") || strings.HasPrefix(clean, "http/cves/") ||
		strings.Contains(strings.ToLower(string(classification)), "cve-") || hasSourceTag(tags, "cve") {
		return "verification", "poc"
	}
	return "check", "poc"
}

func nucleiRuntimeReason(metadata rulelib.NucleiMetadata) string {
	unsupported := make([]string, 0)
	for _, protocol := range metadata.Protocols {
		if protocol != "http" {
			unsupported = append(unsupported, protocol)
		}
	}
	for _, capability := range metadata.Capabilities {
		switch capability {
		case "code", "headless", "javascript", "workflow", "workflows", "interactsh":
			unsupported = append(unsupported, capability)
		}
	}
	unsupported = uniqueSortedStrings(unsupported)
	if len(unsupported) == 0 {
		return "catalog only: original Nuclei execution runtime is not integrated"
	}
	return "catalog only: original Nuclei execution runtime is not integrated; capabilities: " + strings.Join(unsupported, ", ")
}

func nucleiRiskReason(filePath string, tags, capabilities []string) string {
	lowerPath := strings.ToLower(filePath)
	risky := make([]string, 0)
	for _, marker := range []string{"dos", "destructive", "bruteforce", "brute-force", "default-login", "default-logins", "password-spray", "credential-stuffing", "fuzz", "fuzzing", "intrusive", "race"} {
		if hasSourceTag(tags, marker) || hasSourceTag(capabilities, marker) || strings.Contains(lowerPath, "/"+marker+"/") {
			risky = append(risky, marker)
		}
	}
	risky = uniqueSortedStrings(risky)
	if len(risky) == 0 {
		return ""
	}
	return "risk policy: " + strings.Join(risky, ", ")
}

func stableNucleiSourceID(templateID, filePath string) string {
	digest := sha256.Sum256([]byte(templateID + "\x00" + filePath))
	slug := strings.Trim(sourceSlug(templateID), "-")
	if slug == "" {
		slug = "template"
	}
	if len(slug) > 92 {
		slug = strings.TrimRight(slug[:92], "-")
	}
	return "nt-" + slug + "-" + hex.EncodeToString(digest[:8])
}

func sourceSlug(value string) string {
	var output strings.Builder
	dash := false
	for _, char := range strings.ToLower(value) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			output.WriteRune(char)
			dash = false
		} else if output.Len() > 0 && !dash {
			output.WriteByte('-')
			dash = true
		}
	}
	return output.String()
}

func sourceFile(filePath string, data []byte) SourceFile {
	digest := sha256.Sum256(data)
	return SourceFile{Path: filePath, SHA256: hex.EncodeToString(digest[:]), Data: append([]byte(nil), data...)}
}

func findLicense(files map[string][]byte) string {
	for _, name := range []string{"LICENSE.md", "LICENSE"} {
		if data, ok := files[name]; ok {
			return string(data)
		}
	}
	return ""
}

func isYAML(filePath string) bool {
	extension := strings.ToLower(path.Ext(filePath))
	return extension == ".yaml" || extension == ".yml"
}

func sourceStringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func sourceListValue(value any) []string {
	var result []string
	switch value := value.(type) {
	case string:
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				result = append(result, item)
			}
		}
	case []any:
		for _, item := range value {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				result = append(result, strings.TrimSpace(text))
			}
		}
	}
	return result
}

func sourceProducts(info map[string]any) []string {
	metadata, _ := info["metadata"].(map[string]any)
	return sourceListValue(metadata["product"])
}

func hasSourceTag(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), wanted) {
			return true
		}
	}
	return false
}

func uniqueSortedStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func boundedSourceValues(values []string, count, size int) []string {
	result := make([]string, 0, min(len(values), count))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > size || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
		if len(result) == count {
			break
		}
	}
	return result
}

func boundedProducts(values []string) []string {
	result := make([]string, 0, min(len(values), 32))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		lower := strings.ToLower(value)
		normalized := strings.Join(strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(lower)), " ")
		if value == "" || len(value) > 128 || strings.Contains(value, "*") || lower == "/" || lower == "all" || lower == "any" || lower == "http" || lower == "https" || lower == "web" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, value)
		if len(result) == 32 {
			break
		}
	}
	return result
}

func truncateSourceText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	value = value[:max]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
