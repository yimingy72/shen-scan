package browserfp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	wapp "github.com/projectdiscovery/wappalyzergo"
)

const (
	matchBudget         = 500 * time.Millisecond
	compatibilityBudget = 10 * time.Millisecond
	maxValueBytes       = 1 << 20
)

// Official compilation remains the first choice. Only rejected expressions use
// ECMAScript matching, without the Go parser's quantifier rewriting.
func compilePattern(raw string) (*wapp.ParsedPattern, *regexp2.Regexp, error) {
	pattern, err := wapp.ParsePattern(raw)
	if err == nil {
		return pattern, nil, nil
	}
	expression, metadata, hasMetadata := strings.Cut(raw, "\\;")
	tags := ""
	if hasMetadata {
		tags = "\\;" + metadata
	}
	pattern, err = wapp.ParsePattern(tags)
	if err != nil {
		return nil, nil, err
	}
	// JavaScript's non-Unicode Annex B grammar treats a hyphen whose
	// endpoint is a class escape as literal. regexp2 rejects this one shipped
	// Shaka expression even in ECMAScript mode; move that literal hyphen to
	// the class edge without changing its character set.
	if expression == `v([\d\.-\w]+)` {
		expression = `v([\d.\w-]+)`
	}
	fallback, err := regexp2.Compile(expression, regexp2.ECMAScript|regexp2.IgnoreCase)
	if err != nil {
		return nil, nil, err
	}
	// Cached regexes are immutable after compilation and safe for concurrent use.
	// regexp2 checks its timeout clock at ~100ms granularity; this is a bounded
	// backtracking guard, not a claim of exact 10ms cancellation latency.
	fallback.MatchTimeout = compatibilityBudget
	return pattern, fallback, nil
}

func (r rule) evaluate(ctx context.Context, target string) (bool, string, error) {
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	if r.fallback == nil {
		matched, version := r.pattern.Evaluate(target)
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		return matched, version, nil
	}
	match, err := r.fallback.FindStringMatch(target)
	if err != nil {
		// regexp2's raw timeout error includes the entire target: don't duplicate
		// page contents into status/error messages.
		return false, "", fmt.Errorf("compatibility regex timed out")
	}
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	if match == nil {
		return false, "", nil
	}
	groups := match.Groups()
	captures := make([]string, 0, len(groups)-1)
	for _, group := range groups[1:] {
		captures = append(captures, group.String())
	}
	return true, fallbackVersion(r.pattern.Version, captures), nil
}

// The official Go version extractor is private. This narrow adapter mirrors its
// backreference/ternary behavior for regexp2 captures; metadata itself is still
// parsed by official ParsePattern. It intentionally adds no new version syntax.
func fallbackVersion(version string, captures []string) string {
	for index, capture := range captures {
		version = strings.ReplaceAll(version, fmt.Sprintf("\\%d", index+1), capture)
	}
	if strings.Contains(version, "?") {
		parts := strings.Split(version, "?")
		if len(parts) != 2 {
			return ""
		}
		branches := strings.Split(parts[1], ":")
		if len(branches) != 2 {
			return ""
		}
		switch {
		case branches[0] != "":
			if len(captures) == 0 {
				return strings.TrimSpace(branches[1])
			}
			return strings.TrimSpace(branches[0])
		case branches[1] == "":
			return ""
		default:
			return strings.TrimSpace(branches[1])
		}
	}
	return strings.TrimSpace(version)
}
