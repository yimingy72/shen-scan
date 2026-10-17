package rulesource

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"scanplatform/internal/rulelib"
)

const WappalyzerLicenseText = `MIT License

Copyright (c) 2021 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

const (
	maxWappalyzerBytes   = 32 << 20
	wappalyzerMaxSamples = 100
	maxRuleMatchers      = 8
	maxMatcherPatterns   = 32
)

type wappalyzerDocument struct {
	Apps map[string]wappalyzerApp `json:"apps"`
}

type wappalyzerApp struct {
	Description string              `json:"description"`
	Headers     map[string]string   `json:"headers"`
	Cookies     map[string]string   `json:"cookies"`
	HTML        []string            `json:"html"`
	Meta        map[string][]string `json:"meta"`
	ScriptSrc   []string            `json:"scriptSrc"`
	Implies     []string            `json:"implies"`
	Requires    []string            `json:"requires"`
	Excludes    []string            `json:"excludes"`
	JS          map[string]string   `json:"js"`
	DOM         map[string]any      `json:"dom"`
	CSS         []string            `json:"css"`
	Scripts     []string            `json:"scripts"`
}

type conversion struct {
	catalog Catalog
}

type parsedPattern struct {
	pattern string
	start   bool
	end     bool
	empty   bool
}

func ConvertWappalyzer(data []byte) (Catalog, error) {
	if len(data) == 0 || len(data) > maxWappalyzerBytes {
		return Catalog{}, fmt.Errorf("wappalyzer catalog must be 1..%d bytes", maxWappalyzerBytes)
	}
	var document wappalyzerDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return Catalog{}, fmt.Errorf("decode wappalyzer catalog: %w", err)
	}
	if len(document.Apps) == 0 {
		return Catalog{}, fmt.Errorf("wappalyzer catalog has no apps")
	}
	digest := sha256.Sum256(data)
	digestHex := hex.EncodeToString(digest[:])
	c := &conversion{catalog: Catalog{
		Rules: make([]rulelib.Rule, 0, len(document.Apps)), Total: len(document.Apps),
		Skipped: make(map[string]int), SignalSkipped: make(map[string]int), Revision: digestHex[:16], Digest: "sha256:" + digestHex,
		Repository: WappalyzerRepository, License: WappalyzerLicense, LicenseText: WappalyzerLicenseText,
	}}
	names := make([]string, 0, len(document.Apps))
	for name := range document.Apps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if rule, ok := c.convertApp(name, document.Apps[name]); ok {
			c.catalog.Rules = append(c.catalog.Rules, rule)
		}
	}
	return c.catalog, nil
}

func (c *conversion) convertApp(name string, app wappalyzerApp) (rulelib.Rule, bool) {
	basePath := "apps." + name
	if name == "" || len(name) > 200 || !utf8.ValidString(name) {
		c.rejectProduct(basePath, "product-invalid", "product name is empty, invalid UTF-8, or exceeds 200 bytes")
		return rulelib.Rule{}, false
	}
	if len(app.Requires) > 0 {
		c.rejectProduct(basePath+".requires", "product-requires", "requires semantics cannot be represented by one native rule")
		return rulelib.Rule{}, false
	}
	if len(app.Excludes) > 0 {
		c.rejectProduct(basePath+".excludes", "product-excludes", "excludes semantics cannot be represented by one native rule")
		return rulelib.Rule{}, false
	}
	if len(app.Implies) > 0 {
		c.rejectProduct(basePath+".implies", "product-implies", "implied product emission cannot be preserved by one native rule")
		return rulelib.Rule{}, false
	}

	headerPatterns := make([]string, 0, len(app.Headers)+len(app.Cookies))
	bodyPatterns := make([]string, 0, len(app.HTML)+len(app.ScriptSrc))

	for _, key := range sortedKeys(app.Headers) {
		path := basePath + ".headers." + key
		parsed, ok := c.parsePattern(path, app.Headers[key], true)
		if !ok {
			continue
		}
		pattern, err := wrapHeader(key, parsed)
		if err != nil {
			c.rejectSignal(path, "signal-invalid-header", err.Error())
			continue
		}
		if c.acceptPattern(path, pattern) {
			headerPatterns = append(headerPatterns, pattern)
		}
	}
	for _, key := range sortedKeys(app.Cookies) {
		path := basePath + ".cookies." + key
		parsed, ok := c.parsePattern(path, app.Cookies[key], true)
		if !ok {
			continue
		}
		pattern, err := wrapCookie(key, parsed)
		if err != nil {
			c.rejectSignal(path, "signal-invalid-cookie", err.Error())
			continue
		}
		if c.acceptPattern(path, pattern) {
			headerPatterns = append(headerPatterns, pattern)
		}
	}
	for i, raw := range app.HTML {
		path := fmt.Sprintf("%s.html[%d]", basePath, i)
		parsed, ok := c.parsePattern(path, raw, false)
		if !ok {
			continue
		}
		if parsed.empty {
			c.rejectSignal(path, "signal-empty-regex", "an empty HTML regex would match every response")
			continue
		}
		pattern := directPattern(parsed)
		compiled, err := regexp.Compile(pattern)
		if len(pattern) > 4096 || err != nil || compiled.MatchString("") {
			reason := "regex matches an empty body"
			if len(pattern) > 4096 {
				reason = "converted regex exceeds 4096 bytes"
			} else if err != nil {
				reason = err.Error()
			}
			c.rejectSignal(path, "signal-invalid-regex", reason)
			continue
		}
		bodyPatterns = append(bodyPatterns, pattern)
	}
	for _, key := range sortedKeys(app.Meta) {
		for i, raw := range app.Meta[key] {
			path := fmt.Sprintf("%s.meta.%s[%d]", basePath, key, i)
			parsed, ok := c.parsePattern(path, raw, true)
			if !ok {
				continue
			}
			pattern, err := wrapMeta(key, parsed)
			if err != nil {
				c.rejectSignal(path, "signal-invalid-meta", err.Error())
				continue
			}
			if c.acceptPattern(path, pattern) {
				bodyPatterns = append(bodyPatterns, pattern)
			}
		}
	}
	for i, raw := range app.ScriptSrc {
		path := fmt.Sprintf("%s.scriptSrc[%d]", basePath, i)
		parsed, ok := c.parsePattern(path, raw, false)
		if !ok {
			continue
		}
		if parsed.empty {
			c.rejectSignal(path, "signal-empty-regex", "an empty scriptSrc regex would match every script element")
			continue
		}
		pattern, err := wrapScriptSrc(parsed)
		if err != nil {
			c.rejectSignal(path, "signal-invalid-script-src", err.Error())
			continue
		}
		if c.acceptPattern(path, pattern) {
			bodyPatterns = append(bodyPatterns, pattern)
		}
	}

	c.unsupportedSignals(basePath, app)
	headerPatterns = uniqueSorted(headerPatterns)
	bodyPatterns = uniqueSorted(bodyPatterns)
	matchers := c.makeMatchers(basePath, headerPatterns, bodyPatterns)
	if len(matchers) == 0 {
		c.rejectProduct(basePath, "product-no-supported-signal", "no exact passive response signal remained")
		return rulelib.Rule{}, false
	}
	rule := rulelib.Rule{
		ID: stableWappalyzerID(name), Kind: "http", Name: name,
		Description: truncateUTF8(app.Description, 4096), Engine: "native", Severity: "info",
		Enabled: true, Builtin: false, Revision: 1,
		Tags: []string{"fingerprint", "http", WappalyzerID}, Source: WappalyzerRepository,
		Definition: rulelib.Definition{Service: "http", Product: name, Condition: "or", Matchers: matchers},
	}
	if err := rulelib.Validate(rule); err != nil {
		c.rejectProduct(basePath, "product-invalid-rule", err.Error())
		return rulelib.Rule{}, false
	}
	return rule, true
}

func (c *conversion) parsePattern(path, raw string, allowEmpty bool) (parsedPattern, bool) {
	parts := strings.Split(raw, `\;`)
	confidence := 100
	for _, directive := range parts[1:] {
		key, value, ok := strings.Cut(directive, ":")
		if !ok {
			c.rejectSignal(path, "signal-unknown-directive", "malformed pattern directive")
			return parsedPattern{}, false
		}
		switch key {
		case "confidence":
			parsed, err := strconv.Atoi(value)
			if err != nil {
				c.rejectSignal(path, "signal-invalid-confidence", "confidence is not an integer")
				return parsedPattern{}, false
			}
			confidence = parsed
		case "version":
			c.catalog.SignalSkipped["version-metadata-omitted"]++
		case "requires":
			c.rejectSignal(path, "signal-requires", "requires directive cannot be preserved")
			return parsedPattern{}, false
		case "excludes":
			c.rejectSignal(path, "signal-excludes", "excludes directive cannot be preserved")
			return parsedPattern{}, false
		default:
			c.rejectSignal(path, "signal-unknown-directive", "unsupported pattern directive "+key)
			return parsedPattern{}, false
		}
	}
	if confidence < 100 {
		c.rejectSignal(path, "signal-low-confidence", fmt.Sprintf("confidence %d is below 100", confidence))
		return parsedPattern{}, false
	}
	pattern := parts[0]
	if pattern == "" {
		if !allowEmpty {
			return parsedPattern{empty: true}, true
		}
		return parsedPattern{empty: true}, true
	}
	start, end, inner, err := boundaryAnchors(pattern)
	if err != nil {
		c.rejectSignal(path, "signal-embedded-anchor", err.Error())
		return parsedPattern{}, false
	}
	inner = wappalyzerRegex(inner)
	if len(inner) > 4096 {
		c.rejectSignal(path, "signal-regex-too-long", "source regex exceeds 4096 bytes")
		return parsedPattern{}, false
	}
	if _, err := regexp.Compile("(?i)" + inner); err != nil {
		c.rejectSignal(path, "signal-invalid-regex", err.Error())
		return parsedPattern{}, false
	}
	return parsedPattern{pattern: inner, start: start, end: end}, true
}

func (c *conversion) acceptPattern(path, pattern string) bool {
	if len(pattern) > 4096 {
		c.rejectSignal(path, "signal-regex-too-long", "converted regex exceeds 4096 bytes")
		return false
	}
	if _, err := regexp.Compile(pattern); err != nil {
		c.rejectSignal(path, "signal-invalid-regex", err.Error())
		return false
	}
	return true
}

func (c *conversion) unsupportedSignals(basePath string, app wappalyzerApp) {
	for _, unsupported := range []struct {
		field string
		count int
	}{{"js", len(app.JS)}, {"dom", len(app.DOM)}, {"css", len(app.CSS)}, {"scripts", len(app.Scripts)}} {
		field, count := unsupported.field, unsupported.count
		if count == 0 {
			continue
		}
		c.catalog.SignalSkipped["signal-unsupported-"+field] += count
		if len(c.catalog.Samples) < wappalyzerMaxSamples {
			c.catalog.Samples = append(c.catalog.Samples, Rejection{
				Path:   basePath + "." + field,
				Reason: field + " requires runtime, rendered DOM, CSS evaluation, or fetched script content",
			})
		}
	}
}

func (c *conversion) makeMatchers(basePath string, headerPatterns, bodyPatterns []string) []rulelib.Matcher {
	matchers := make([]rulelib.Matcher, 0, maxRuleMatchers)
	for _, group := range []struct {
		part     string
		patterns []string
	}{{"header", headerPatterns}, {"body", bodyPatterns}} {
		for start := 0; start < len(group.patterns); start += maxMatcherPatterns {
			if len(matchers) == maxRuleMatchers {
				c.catalog.SignalSkipped["signal-matcher-limit"] += len(group.patterns) - start
				if len(c.catalog.Samples) < wappalyzerMaxSamples {
					c.catalog.Samples = append(c.catalog.Samples, Rejection{Path: basePath, Reason: "native rule exceeds 8 matchers"})
				}
				break
			}
			end := min(start+maxMatcherPatterns, len(group.patterns))
			matchers = append(matchers, rulelib.Matcher{
				Part: group.part, Type: "regex", Regex: group.patterns[start:end], Condition: "or", CaseSensitive: true,
			})
		}
	}
	return matchers
}

func (c *conversion) rejectProduct(path, key, reason string) {
	c.catalog.Skipped[key]++
	c.sample(path, reason)
}

func (c *conversion) rejectSignal(path, key, reason string) {
	c.catalog.SignalSkipped[key]++
	c.sample(path, reason)
}

func (c *conversion) sample(path, reason string) {
	if len(c.catalog.Samples) < wappalyzerMaxSamples {
		c.catalog.Samples = append(c.catalog.Samples, Rejection{Path: path, Reason: reason})
	}
}

func wrapHeader(key string, pattern parsedPattern) (string, error) {
	if !validFieldName(key) {
		return "", fmt.Errorf("invalid header name")
	}
	value, err := boundedValue(pattern, []rune{'\r', '\n'})
	if err != nil {
		return "", err
	}
	return `(?im)^` + regexp.QuoteMeta(key) + `:\s*` + value + `\s*$`, nil
}

func wrapCookie(key string, pattern parsedPattern) (string, error) {
	if !validFieldName(key) {
		return "", fmt.Errorf("invalid cookie name")
	}
	value, err := boundedValue(pattern, []rune{';', '\r', '\n'})
	if err != nil {
		return "", err
	}
	return `(?im)^Set-Cookie:\s*` + regexp.QuoteMeta(key) + `=` + value + `(?:;|\s*$)`, nil
}

func wrapMeta(key string, pattern parsedPattern) (string, error) {
	if key == "" || strings.ContainsAny(key, "\"'<>\r\n") {
		return "", fmt.Errorf("invalid meta name")
	}
	value, err := quotedValue(pattern)
	if err != nil {
		return "", err
	}
	name := `\bname\s*=\s*(?:"` + regexp.QuoteMeta(key) + `"|'` + regexp.QuoteMeta(key) + `')`
	content := `\bcontent\s*=\s*` + value
	return `(?is)<meta\b(?:[^>]*` + name + `[^>]*` + content + `|[^>]*` + content + `[^>]*` + name + `)[^>]*>`, nil
}

func wrapScriptSrc(pattern parsedPattern) (string, error) {
	value, err := quotedValue(pattern)
	if err != nil {
		return "", err
	}
	return `(?is)<script\b[^>]*\bsrc\s*=\s*` + value + `[^>]*>`, nil
}

func boundedValue(pattern parsedPattern, forbidden []rune) (string, error) {
	if pattern.empty {
		return classExcept(forbidden) + `*`, nil
	}
	inner, err := restrictPattern(pattern.pattern, forbidden)
	if err != nil {
		return "", err
	}
	prefix, suffix := "", ""
	if !pattern.start {
		prefix = classExcept(forbidden) + `*?`
	}
	if !pattern.end {
		suffix = classExcept(forbidden) + `*`
	}
	return prefix + `(?:` + inner + `)` + suffix, nil
}

func directPattern(pattern parsedPattern) string {
	value := "(?i)" + pattern.pattern
	if pattern.start {
		value = "^" + value
	}
	if pattern.end {
		value += "$"
	}
	return value
}

func quotedValue(pattern parsedPattern) (string, error) {
	forbidden := []rune{'\'', '"', '<', '>', '\r', '\n'}
	value, err := boundedValue(pattern, forbidden)
	if err != nil {
		return "", err
	}
	return `(?:"` + value + `"|'` + value + `')`, nil
}

func restrictPattern(pattern string, forbidden []rune) (string, error) {
	re, err := syntax.Parse("(?i)"+pattern, syntax.Perl)
	if err != nil {
		return "", err
	}
	sort.Slice(forbidden, func(i, j int) bool { return forbidden[i] < forbidden[j] })
	if !restrictRegexp(re, forbidden) {
		return "", fmt.Errorf("regex explicitly matches a field delimiter")
	}
	if containsAnchor(re) {
		return "", fmt.Errorf("regex contains an embedded anchor")
	}
	return re.String(), nil
}

func restrictRegexp(re *syntax.Regexp, forbidden []rune) bool {
	switch re.Op {
	case syntax.OpLiteral:
		for _, value := range re.Rune {
			for _, denied := range forbidden {
				if value == denied {
					return false
				}
			}
		}
	case syntax.OpCharClass:
		re.Rune = subtractRunes(re.Rune, forbidden)
		if len(re.Rune) == 0 {
			return false
		}
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		re.Op = syntax.OpCharClass
		re.Rune = subtractRunes([]rune{0, unicode.MaxRune}, forbidden)
	}
	for _, child := range re.Sub {
		if !restrictRegexp(child, forbidden) {
			return false
		}
	}
	return true
}

func subtractRunes(ranges, forbidden []rune) []rune {
	result := make([]rune, 0, len(ranges)+len(forbidden)*2)
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		cursor := lo
		for _, denied := range forbidden {
			if denied < cursor || denied > hi {
				continue
			}
			if cursor < denied {
				result = append(result, cursor, denied-1)
			}
			cursor = denied + 1
		}
		if cursor <= hi {
			result = append(result, cursor, hi)
		}
	}
	return result
}

func containsAnchor(re *syntax.Regexp) bool {
	if re.Op == syntax.OpBeginLine || re.Op == syntax.OpEndLine || re.Op == syntax.OpBeginText || re.Op == syntax.OpEndText {
		return true
	}
	for _, child := range re.Sub {
		if containsAnchor(child) {
			return true
		}
	}
	return false
}

func boundaryAnchors(pattern string) (bool, bool, string, error) {
	prefix := ""
	for strings.HasPrefix(pattern, "(?") {
		end := strings.IndexByte(pattern, ')')
		if end < 3 || !onlyRegexpFlags(pattern[2:end]) {
			break
		}
		prefix += pattern[:end+1]
		pattern = pattern[end+1:]
	}
	start := strings.HasPrefix(pattern, "^")
	if start {
		pattern = pattern[1:]
	}
	end := strings.HasSuffix(pattern, "$") && !escapedAt(pattern, len(pattern)-1)
	if end {
		pattern = pattern[:len(pattern)-1]
	}
	compiled, err := syntax.Parse("(?i)"+prefix+wappalyzerRegex(pattern), syntax.Perl)
	if err != nil {
		return false, false, "", err
	}
	if containsAnchor(compiled) {
		return false, false, "", fmt.Errorf("anchors are only supported at the outer pattern boundaries")
	}
	return start, end, prefix + pattern, nil
}

func onlyRegexpFlags(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("imsU-", char) {
			return false
		}
	}
	return true
}

func escapedAt(value string, index int) bool {
	backslashes := 0
	for index--; index >= 0 && value[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func wappalyzerRegex(pattern string) string {
	const (
		versionOne = `(\d+(?:\.\d+)+)`
		versionTwo = `((?:\d+\.)+\d+)`
	)
	pattern = strings.ReplaceAll(pattern, versionOne, `__waVersionOne__`)
	pattern = strings.ReplaceAll(pattern, versionTwo, `__waVersionTwo__`)
	pattern = strings.ReplaceAll(pattern, `\+`, `__waEscapedPlus__`)
	pattern = strings.ReplaceAll(pattern, "+", "{1,250}")
	pattern = strings.ReplaceAll(pattern, "*", "{0,250}")
	pattern = strings.ReplaceAll(pattern, `__waEscapedPlus__`, `\+`)
	pattern = strings.ReplaceAll(pattern, `__waVersionOne__`, `(\d{1,20}(?:\.\d{1,20}){1,20})`)
	pattern = strings.ReplaceAll(pattern, `__waVersionTwo__`, `((?:\d{1,20}\.){1,20}\d{1,20})`)
	return pattern
}

func stableWappalyzerID(name string) string {
	digest := sha256.Sum256([]byte(name))
	slug := strings.Trim(slugify(name), "-")
	if slug == "" {
		slug = "product"
	}
	if len(slug) > 59 {
		slug = strings.TrimRight(slug[:59], "-")
	}
	return "wa-" + slug + "-" + hex.EncodeToString(digest[:])
}

func slugify(value string) string {
	var output strings.Builder
	dash := false
	for _, char := range strings.ToLower(value) {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			output.WriteRune(char)
			dash = false
		} else if output.Len() > 0 && !dash {
			output.WriteByte('-')
			dash = true
		}
	}
	return output.String()
}

func validFieldName(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			return false
		}
	}
	return true
}

func classExcept(forbidden []rune) string {
	var value strings.Builder
	value.WriteString("[^")
	for _, char := range forbidden {
		switch char {
		case '\\', ']', '^', '-':
			value.WriteByte('\\')
			value.WriteRune(char)
		case '\r':
			value.WriteString(`\r`)
		case '\n':
			value.WriteString(`\n`)
		default:
			value.WriteRune(char)
		}
	}
	value.WriteByte(']')
	return value.String()
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func truncateUTF8(value string, max int) string {
	if len(value) <= max {
		return value
	}
	value = value[:max]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
