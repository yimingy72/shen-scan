package rulelib

import "encoding/json"

type Rule struct {
	ID           string          `json:"id" yaml:"id"`
	Kind         string          `json:"kind" yaml:"kind"`
	Purpose      string          `json:"purpose,omitempty" yaml:"purpose,omitempty"`
	Name         string          `json:"name" yaml:"name"`
	Description  string          `json:"description,omitempty" yaml:"description,omitempty"`
	Engine       string          `json:"engine" yaml:"engine"`
	Severity     string          `json:"severity" yaml:"severity"`
	Enabled      bool            `json:"enabled" yaml:"enabled"`
	Builtin      bool            `json:"builtin" yaml:"builtin"`
	Revision     int             `json:"revision" yaml:"revision"`
	Tags         []string        `json:"tags,omitempty" yaml:"tags,omitempty"`
	AppliesTo    []string        `json:"applies_to,omitempty" yaml:"applies_to,omitempty"`
	Verification *Verification   `json:"verification,omitempty" yaml:"verification,omitempty"`
	Upstream     *Upstream       `json:"upstream,omitempty" yaml:"upstream,omitempty"`
	Nuclei       *NucleiMetadata `json:"nuclei,omitempty" yaml:"nuclei,omitempty"`
	Fingerprint  json.RawMessage `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Source       string          `json:"source,omitempty" yaml:"source,omitempty"`
	Definition   Definition      `json:"definition" yaml:"definition"`
	Template     string          `json:"template,omitempty" yaml:"template,omitempty"`
}

type Upstream struct {
	SourceID string `json:"source_id" yaml:"source_id"`
	Revision string `json:"revision,omitempty" yaml:"revision,omitempty"`
	Path     string `json:"path" yaml:"path"`
	SHA256   string `json:"sha256" yaml:"sha256"`
}

type NucleiMetadata struct {
	TemplateID            string          `json:"template_id" yaml:"template_id"`
	CatalogOnly           bool            `json:"catalog_only,omitempty" yaml:"catalog_only,omitempty"`
	Protocols             []string        `json:"protocols,omitempty" yaml:"protocols,omitempty"`
	Raw                   bool            `json:"raw,omitempty" yaml:"raw,omitempty"`
	Capabilities          []string        `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	DefaultDisabledReason string          `json:"default_disabled_reason,omitempty" yaml:"default_disabled_reason,omitempty"`
	Info                  json.RawMessage `json:"info,omitempty" yaml:"info,omitempty"`
	Classification        json.RawMessage `json:"classification,omitempty" yaml:"classification,omitempty"`
	RuntimeReason         string          `json:"runtime_reason,omitempty" yaml:"runtime_reason,omitempty"`
	RequestCount          *int            `json:"request_count" yaml:"request_count"`
}

type Definition struct {
	Service            string    `json:"service,omitempty" yaml:"service,omitempty"`
	Product            string    `json:"product,omitempty" yaml:"product,omitempty"`
	VersionRegex       string    `json:"version_regex,omitempty" yaml:"version_regex,omitempty"`
	VersionPart        string    `json:"version_part,omitempty" yaml:"version_part,omitempty"`
	UseDetectedVersion bool      `json:"use_detected_version,omitempty" yaml:"use_detected_version,omitempty"`
	Condition          string    `json:"condition,omitempty" yaml:"condition,omitempty"`
	Matchers           []Matcher `json:"matchers,omitempty" yaml:"matchers,omitempty"`
	Requests           []Request `json:"requests,omitempty" yaml:"requests,omitempty"`
}

type Matcher struct {
	Part          string   `json:"part" yaml:"part"`
	Type          string   `json:"type" yaml:"type"`
	Words         []string `json:"words,omitempty" yaml:"words,omitempty"`
	Regex         []string `json:"regex,omitempty" yaml:"regex,omitempty"`
	Status        []int    `json:"status,omitempty" yaml:"status,omitempty"`
	Condition     string   `json:"condition,omitempty" yaml:"condition,omitempty"`
	Negative      bool     `json:"negative,omitempty" yaml:"negative,omitempty"`
	CaseSensitive bool     `json:"case_sensitive,omitempty" yaml:"case_sensitive,omitempty"`
}

type Request struct {
	Method    string            `json:"method" yaml:"method"`
	Path      string            `json:"path" yaml:"path"`
	Role      string            `json:"role,omitempty" yaml:"role,omitempty"`
	Headers   map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Condition string            `json:"condition,omitempty" yaml:"condition,omitempty"`
	Matchers  []Matcher         `json:"matchers" yaml:"matchers"`
}

type Verification struct {
	ID            string    `json:"id" yaml:"id"`
	CVEs          []string  `json:"cves" yaml:"cves"`
	Category      string    `json:"category" yaml:"category"`
	EvidenceLevel string    `json:"evidence_level" yaml:"evidence_level"`
	Summary       string    `json:"summary" yaml:"summary"`
	References    []string  `json:"references,omitempty" yaml:"references,omitempty"`
	SourcePin     SourcePin `json:"source_pin" yaml:"source_pin"`
}

type SourcePin struct {
	SourceID   string `json:"source_id" yaml:"source_id"`
	Repository string `json:"repository" yaml:"repository"`
	Revision   string `json:"revision" yaml:"revision"`
	Path       string `json:"path" yaml:"path"`
	SHA256     string `json:"sha256" yaml:"sha256"`
}

type CheckEvidence struct {
	RequestRaw  string `json:"request_raw"`
	ResponseRaw string `json:"response_raw"`
}

type Input struct {
	Body    string `json:"body,omitempty"`
	Header  string `json:"header,omitempty"`
	Title   string `json:"title,omitempty"`
	Status  int    `json:"status,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Service string `json:"service,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
}

type MatchResult struct {
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}
