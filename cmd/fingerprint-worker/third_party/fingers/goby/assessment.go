package goby

import (
	"github.com/chainreactors/words/logic"
	"strings"
)

const EmbeddedRDPCandidateReason = "goby_rdp_inside_word_required"

// CandidateReason is an evidence assessment, not a different rule matcher.
// A substring such as wo[rdp]ress cannot establish RDP. Mark only matches whose
// original Boolean expression loses support when those positive rdp labels are
// removed. Other rules, standalone tokens and independent branches stay intact.
func (finger *GobyFinger) CandidateReason(raw string) string {
	raw = strings.ToLower(raw)
	if !strings.Contains(raw, "rdp") || standaloneRDP(raw) {
		return ""
	}
	env := make(map[string]bool, len(finger.Rule))
	removed := false
	for _, r := range finger.Rule {
		match := strings.Contains(raw, r.Feature)
		env[r.Label] = match == r.IsEquel
		if r.Feature == "rdp" && r.IsEquel && match {
			env[r.Label] = false
			removed = true
		}
	}
	if removed && !logic.EvalLogic(finger.logicExpr, env) {
		return EmbeddedRDPCandidateReason
	}
	return ""
}
func standaloneRDP(raw string) bool {
	for offset := 0; offset < len(raw); {
		i := strings.Index(raw[offset:], "rdp")
		if i < 0 {
			return false
		}
		i += offset
		if (i == 0 || !wordByte(raw[i-1])) && (i+3 == len(raw) || !wordByte(raw[i+3])) {
			return true
		}
		offset = i + 3
	}
	return false
}
func wordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_' || b >= 128
}
