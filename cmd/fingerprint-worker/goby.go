package main

import (
	"strings"

	fingers "github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/common"
)

// Preserve every original Goby match and its evidence. A separate assessment
// marks only an rdp-inside-another-word dependency as candidate. Independent
// support from another original rule for the same product prevents downgrade.
func gobyMatches(engine *fingers.Engine, raw string) (common.Frameworks, map[*common.Framework]string) {
	raw = strings.ToLower(raw)
	frames := make(common.Frameworks)
	supported := map[string]bool{}
	reasons := map[string]string{}
	for _, finger := range engine.Goby().Fingers {
		frame := finger.Match(raw)
		if frame == nil {
			continue
		}
		reason := finger.CandidateReason(raw)
		key := strings.ToLower(frame.Name)
		supported[key] = supported[key] || reason == ""
		if reason != "" {
			reasons[key] = reason
		}
		frames.Add(frame)
	}
	assessment := map[*common.Framework]string{}
	for _, frame := range frames {
		if !supported[frame.Name] {
			assessment[frame] = reasons[frame.Name]
		}
	}
	return engine.MergeFrameworks(make(common.Frameworks), frames), assessment
}
