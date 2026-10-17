package rulelib

import "gopkg.in/yaml.v3"

const NucleiSingleResponseBatchProfile = "nuclei-3.11.1-single-http-batch-v1"
const MaxNucleiBatchTemplates = 4

// NucleiBatchEligible is deliberately narrower than http-basic-v1: one planned
// request only, original byte identity intact, and no change to matcher scope.
func NucleiBatchEligible(rule Rule) bool {
	if rule.Kind != "poc" || rule.Engine != "nuclei" || !rule.Enabled || rule.Nuclei == nil || rule.Nuclei.ExecutionProfile != NucleiExecutionProfileHTTPBasic {
		return false
	}
	analysis, err := AnalyzeNucleiOriginal([]byte(rule.Template))
	if err != nil {
		return false
	}
	// One matcher produces one terminal event; multi-matcher templates retain
	// their established single-template execution path.
	var document map[string]any
	if yaml.Unmarshal([]byte(rule.Template), &document) != nil {
		return false
	}
	blocks, ok := document["http"].([]any)
	if !ok {
		blocks, ok = document["requests"].([]any)
	}
	if !ok || len(blocks) != 1 {
		return false
	}
	block, ok := blocks[0].(map[string]any)
	if !ok {
		return false
	}
	matchers, ok := block["matchers"].([]any)
	if !ok || len(matchers) != 1 {
		return false
	}
	return len(analysis.Plan.Requests) == 1 && analysis.Plan.TemplateID == rule.Nuclei.TemplateID && analysis.Plan.ContentSHA256 == rule.Nuclei.ContentSHA256
}
