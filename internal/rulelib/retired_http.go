package rulelib

import (
	_ "embed"
	"encoding/json"
)

// RetiredHTTPSeeds identifies the former platform-authored HTTP rules. Source
// and ID are both required: an imported rule for the same product is unrelated.
// The original matchers remain in historical run snapshots, not fresh seeds.
//
//go:embed retired_http.json
var retiredHTTPSeedsJSON []byte

func RetiredHTTPSeeds() (ids, sources []string) {
	var bySource map[string][]string
	if err := json.Unmarshal(retiredHTTPSeedsJSON, &bySource); err != nil {
		panic("invalid built-in HTTP retirement manifest: " + err.Error())
	}
	for source, names := range bySource {
		for _, id := range names {
			ids = append(ids, id)
			sources = append(sources, source)
		}
	}
	return ids, sources
}
