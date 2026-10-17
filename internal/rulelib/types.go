package rulelib

type Rule struct {
	ID          string     `json:"id" yaml:"id"`
	Kind        string     `json:"kind" yaml:"kind"`
	Name        string     `json:"name" yaml:"name"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Engine      string     `json:"engine" yaml:"engine"`
	Severity    string     `json:"severity" yaml:"severity"`
	Enabled     bool       `json:"enabled" yaml:"enabled"`
	Builtin     bool       `json:"builtin" yaml:"builtin"`
	Revision    int        `json:"revision" yaml:"revision"`
	Tags        []string   `json:"tags,omitempty" yaml:"tags,omitempty"`
	AppliesTo   []string   `json:"applies_to,omitempty" yaml:"applies_to,omitempty"`
	Source      string     `json:"source,omitempty" yaml:"source,omitempty"`
	Definition  Definition `json:"definition" yaml:"definition"`
	Template    string     `json:"template,omitempty" yaml:"template,omitempty"`
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
	Headers   map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Condition string            `json:"condition,omitempty" yaml:"condition,omitempty"`
	Matchers  []Matcher         `json:"matchers" yaml:"matchers"`
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
