package operators

import (
	"github.com/dlclark/regexp2"
	"regexp"
	"time"
)

type compiledRegex interface {
	MatchString(string) bool
	FindAllString(string, int) []string
	FindAllStringSubmatch(string, int) [][]string
}

// Preserve extended-mode and lookaround expressions instead of dropping records.
func compileRegex(expr string) (compiledRegex, error) {
	if r, err := regexp.Compile(expr); err == nil {
		return r, nil
	}
	r, err := regexp2.Compile(expr, regexp2.None)
	if err != nil {
		return nil, err
	}
	r.MatchTimeout = time.Second
	return backtrackingRegex{r}, nil
}

type backtrackingRegex struct{ r *regexp2.Regexp }

func (r backtrackingRegex) MatchString(s string) bool {
	ok, err := r.r.MatchString(s)
	return err == nil && ok
}
func (r backtrackingRegex) FindAllStringSubmatch(s string, n int) [][]string {
	var out [][]string
	m, err := r.r.FindStringMatch(s)
	for err == nil && m != nil && (n < 0 || len(out) < n) {
		groups := m.Groups()
		row := make([]string, len(groups))
		for i, g := range groups {
			row[i] = g.String()
		}
		out = append(out, row)
		m, err = r.r.FindNextMatch(m)
	}
	return out
}
func (r backtrackingRegex) FindAllString(s string, n int) []string {
	var out []string
	for _, m := range r.FindAllStringSubmatch(s, n) {
		out = append(out, m[0])
	}
	return out
}
