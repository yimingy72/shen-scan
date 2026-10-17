package rulesource

import "scanplatform/internal/rulelib"

const (
	WappalyzerID         = "wappalyzer"
	NucleiID             = "nuclei-templates"
	WappalyzerRepository = "https://github.com/projectdiscovery/wappalyzergo"
	WappalyzerLicense    = "MIT"
)

type Rejection struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type Catalog struct {
	Rules         []rulelib.Rule `json:"rules"`
	Total         int            `json:"total"`
	Skipped       map[string]int `json:"skipped"`
	SignalSkipped map[string]int `json:"signal_skipped,omitempty"`
	Samples       []Rejection    `json:"samples,omitempty"`
	Revision      string         `json:"revision,omitempty"`
	Digest        string         `json:"digest,omitempty"`
	Repository    string         `json:"repository"`
	License       string         `json:"license"`
	LicenseText   string         `json:"license_text"`
}
