// Package browserfp compiles the original Wappalyzer JS/DOM rules into a
// deduplicated browser collection plan and evaluates typed browser observations.
package browserfp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
	wapp "github.com/projectdiscovery/wappalyzergo"
)

type JSPath struct {
	Key   string   `json:"key"`
	Parts []string `json:"parts"`
}
type DOMSelector struct {
	Selector   string   `json:"selector"`
	Exists     bool     `json:"exists,omitempty"`
	Text       bool     `json:"text,omitempty"`
	Attributes []string `json:"attributes,omitempty"`
	Properties []string `json:"properties,omitempty"`
}
type Plan struct {
	Digest      string        `json:"digest"`
	JS          []JSPath      `json:"js"`
	DOM         []DOMSelector `json:"dom"`
	Unsupported []RuleStatus  `json:"unsupported,omitempty"`
}

// Value retains original JS type; Value is String(value) for primitive values.
// Exists means the requested own property/attribute is present, not truthy.
type Value struct {
	Exists    bool   `json:"exists"`
	Type      string `json:"type"`
	Value     string `json:"value,omitempty"`
	Error     string `json:"error,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}
type Node struct {
	Text       Value            `json:"text"`
	Attributes map[string]Value `json:"attributes,omitempty"`
	Properties map[string]Value `json:"properties,omitempty"`
}
type DOMObservation struct {
	Nodes     []Node `json:"nodes"`
	Error     string `json:"error,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}
type Observations struct {
	JS  map[string]Value          `json:"js"`
	DOM map[string]DOMObservation `json:"dom"`
}
type RuleStatus struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Key       string `json:"key"`
	Operation string `json:"operation,omitempty"`
	Field     string `json:"field,omitempty"`
	Pattern   string `json:"pattern"`
	Engine    string `json:"engine,omitempty"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}
type Evidence struct {
	RuleID     int    `json:"rule_id"`
	Source     string `json:"source"`
	Key        string `json:"key"`
	Operation  string `json:"operation,omitempty"`
	Field      string `json:"field,omitempty"`
	Node       int    `json:"node,omitempty"`
	Type       string `json:"type"`
	Value      string `json:"value"`
	Confidence int    `json:"confidence"`
	Version    string `json:"version,omitempty"`
}
type Match struct {
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Confidence int        `json:"confidence"`
	Evidence   []Evidence `json:"evidence,omitempty"`
	Implies    []string   `json:"implies,omitempty"`
	ImpliedBy  []string   `json:"implied_by,omitempty"`
}
type Result struct {
	Digest           string       `json:"digest"`
	Matches          []Match      `json:"matches"`
	Rules            []RuleStatus `json:"rules"`
	TotalRules       int          `json:"total_rules"`
	EvaluatedRules   int          `json:"evaluated_rules"`
	MatchedRules     int          `json:"matched_rules"`
	UnsupportedRules int          `json:"unsupported_rules"`
	Complete         bool         `json:"complete"`
}
type rule struct {
	status   RuleStatus
	pattern  *wapp.ParsedPattern
	fallback *regexp2.Regexp
}
type Matcher struct {
	plan    Plan
	rules   []rule
	implies map[string][]string
}

var compiledCache = struct {
	sync.Mutex
	entries map[string]*Matcher
	order   []string
}{entries: make(map[string]*Matcher)}

// Compile uses the whole selected CFF, including JS-only technologies. The small
// bounded cache retains no browser observations or target-specific information.
func Compile(cff []byte) (*Matcher, error) {
	if len(cff) == 0 || len(cff) > 32<<20 {
		return nil, fmt.Errorf("browser CFF must be 1..33554432 bytes")
	}
	sum := sha256.Sum256(cff)
	digest := hex.EncodeToString(sum[:])
	compiledCache.Lock()
	defer compiledCache.Unlock()
	if m := compiledCache.entries[digest]; m != nil {
		return m, nil
	}
	var data struct {
		Apps map[string]*wapp.Fingerprint `json:"apps"`
	}
	if err := json.Unmarshal(cff, &data); err != nil {
		return nil, fmt.Errorf("decode browser CFF: %w", err)
	}
	if len(data.Apps) == 0 {
		return nil, fmt.Errorf("browser CFF has no apps")
	}
	m := &Matcher{plan: Plan{Digest: digest, JS: []JSPath{}, DOM: []DOMSelector{}}, implies: make(map[string][]string)}
	paths := make(map[string]bool)
	selectors := make(map[string]*DOMSelector)
	add := func(name, source, key, op, field string, raw any) {
		status := RuleStatus{ID: len(m.rules), Name: name, Source: source, Key: key, Operation: op, Field: field, Status: "unsupported"}
		// Keep the full raw collection scope even when the official parser
		// cannot compile an individual expression.
		if source == "js" {
			paths[key] = true
		} else {
			sel := selectors[key]
			if sel == nil {
				sel = &DOMSelector{Selector: key}
				selectors[key] = sel
			}
			switch op {
			case "exists":
				sel.Exists = true
			case "text":
				sel.Text = true
			case "attributes":
				sel.Attributes = append(sel.Attributes, field)
			case "properties":
				sel.Properties = append(sel.Properties, field)
			}
		}
		pattern, ok := raw.(string)
		status.Pattern = pattern
		var parsed *wapp.ParsedPattern
		var fallback *regexp2.Regexp
		switch {
		case !ok:
			status.Reason = "pattern must be a string"
		case source == "dom" && op != "exists" && op != "text" && op != "attributes" && op != "properties":
			status.Reason = "unsupported DOM operation"
		case source == "js" && key == "":
			status.Reason = "empty JS path"
		default:
			var err error
			parsed, fallback, err = compilePattern(pattern)
			if err != nil {
				status.Reason = "invalid pattern: " + err.Error()
			} else {
				status.Status = "pending"
				status.Engine = "wappalyzergo"
				if fallback != nil {
					status.Engine = "regexp2-ecmascript"
				}
			}
		}
		m.rules = append(m.rules, rule{status: status, pattern: parsed, fallback: fallback})
		if status.Status == "unsupported" {
			m.plan.Unsupported = append(m.plan.Unsupported, status)
			return
		}
	}
	for _, name := range keys(data.Apps) {
		app := data.Apps[name]
		if app == nil {
			return nil, fmt.Errorf("browser CFF app %q is null", name)
		}
		m.implies[name] = append([]string(nil), app.Implies...)
		for _, key := range keys(app.JS) {
			add(name, "js", key, "", "", app.JS[key])
		}
		for _, selector := range keys(app.Dom) {
			for _, op := range keys(app.Dom[selector]) {
				raw := app.Dom[selector][op]
				if op == "attributes" || op == "properties" {
					fields, ok := raw.(map[string]any)
					if !ok {
						add(name, "dom", selector, op, "", raw)
						continue
					}
					for _, field := range keys(fields) {
						add(name, "dom", selector, op, field, fields[field])
					}
				} else {
					add(name, "dom", selector, op, "", raw)
				}
			}
		}
	}
	for _, key := range keys(paths) {
		m.plan.JS = append(m.plan.JS, JSPath{Key: key, Parts: strings.Split(key, ".")})
	}
	for _, key := range keys(selectors) {
		sel := selectors[key]
		sel.Attributes = unique(sel.Attributes)
		sel.Properties = unique(sel.Properties)
		m.plan.DOM = append(m.plan.DOM, *sel)
	}
	// ponytail: serialize compilation under one lock; split singleflight by digest
	// only if concurrent CFF compilation becomes measurable.
	if len(compiledCache.order) == 4 {
		delete(compiledCache.entries, compiledCache.order[0])
		compiledCache.order = compiledCache.order[1:]
	}
	compiledCache.entries[digest] = m
	compiledCache.order = append(compiledCache.order, digest)
	return m, nil
}

// Plan returns an independent copy so a caller cannot mutate the cached plan.
func (m *Matcher) Plan() Plan {
	data, _ := json.Marshal(m.plan)
	var plan Plan
	_ = json.Unmarshal(data, &plan)
	return plan
}

func (m *Matcher) Match(observations Observations) Result {
	return m.MatchContext(context.Background(), observations)
}

// MatchContext limits total matching work to 500ms or the earlier caller
// deadline. A compatibility regex may overrun cancellation by regexp2's timeout
// clock granularity; no detached matching goroutine is left running.
func (m *Matcher) MatchContext(ctx context.Context, observations Observations) Result {
	ctx, cancel := context.WithTimeout(ctx, matchBudget)
	defer cancel()
	result := Result{Digest: m.plan.Digest, Matches: []Match{}, Rules: make([]RuleStatus, 0, len(m.rules)), TotalRules: len(m.rules), Complete: true}
	matches := make(map[string]*Match)
	fingerprints := wapp.NewUniqueFingerprints()
	for _, rule := range m.rules {
		status := rule.status
		if status.Status == "unsupported" {
			result.UnsupportedRules++
			result.Complete = false
			result.Rules = append(result.Rules, status)
			continue
		}
		if err := ctx.Err(); err != nil {
			status.Status = "incomplete"
			status.Reason = err.Error()
			result.Complete = false
			result.Rules = append(result.Rules, status)
			continue
		}
		values, reason := observed(rule.status, observations)
		status.Status = "not_matched"
		if reason != "" {
			status.Status = "incomplete"
			status.Reason = reason
			result.Complete = false
		} else {
			result.EvaluatedRules++
		}
		ruleMatched := false
		for index, value := range values {
			if err := ctx.Err(); err != nil {
				status.Status = "incomplete"
				status.Reason = err.Error()
				result.Complete = false
				break
			}
			target, present, err := scalar(value, rule.status)
			if err != "" {
				status.Status = "incomplete"
				status.Reason = err
				result.Complete = false
				continue
			}
			if !present || ruleMatched {
				continue
			}
			matched, version, evaluationError := rule.evaluate(ctx, target)
			if evaluationError != nil {
				status.Status = "incomplete"
				status.Reason = evaluationError.Error()
				result.Complete = false
				continue
			}
			if !matched {
				continue
			}
			confidence := max(0, min(100, rule.pattern.Confidence))
			match := matches[status.Name]
			if match == nil {
				match = &Match{Name: status.Name, Implies: append([]string(nil), m.implies[status.Name]...)}
				matches[status.Name] = match
			}
			match.Evidence = append(match.Evidence, Evidence{RuleID: status.ID, Source: status.Source, Key: status.Key, Operation: status.Operation, Field: status.Field, Node: index, Type: value.Type, Value: target, Confidence: confidence, Version: version})
			// Count one confidence contribution per rule, not once per repeated DOM node.
			fingerprints.SetIfNotExists(status.Name, version, confidence)
			match.Confidence = min(100, match.Confidence+confidence)
			if match.Version == "" {
				match.Version = version
			}
			result.MatchedRules++
			if status.Status != "incomplete" {
				status.Status = "matched"
			}
			ruleMatched = true
		}
		// A typed field failure counts as incomplete, even when the selector itself
		// succeeded. Keep the counts consistent with the per-rule status.
		if status.Status == "incomplete" && reason == "" {
			result.EvaluatedRules--
		}
		result.Rules = append(result.Rules, status)
	}
	// Resolve the direct implies declarations, preserving raw metadata on the
	// source match. This follows the Go engine's direct (one-hop) implication scope.
	direct := make([]Match, 0, len(matches))
	for _, name := range keys(matches) {
		direct = append(direct, *matches[name])
	}
	for _, source := range direct {
		name := source.Name
		for _, raw := range source.Implies {
			impliedName, metadata, hasMetadata := strings.Cut(raw, "\\;")
			tags := ""
			if hasMetadata {
				tags = "\\;" + metadata
			}
			// A technology name is not a regex; parse only official tags.
			pattern, err := wapp.ParsePattern(tags)
			if err != nil || impliedName == "" {
				continue
			}
			confidence := max(0, min(source.Confidence, pattern.Confidence))
			implied := matches[impliedName]
			if implied == nil {
				implied = &Match{Name: impliedName, Confidence: confidence, Version: pattern.Version}
				matches[impliedName] = implied
			}
			implied.Confidence = max(implied.Confidence, confidence)
			implied.ImpliedBy = append(implied.ImpliedBy, name)
			fingerprints.SetIfNotExists(impliedName, implied.Version, confidence)
		}
	}
	visible := fingerprints.GetValues()
	for _, name := range keys(matches) {
		match := matches[name]
		if _, ok := visible[wapp.FormatAppVersion(name, match.Version)]; ok {
			result.Matches = append(result.Matches, *match)
		}
	}
	return result
}

func observed(status RuleStatus, observations Observations) ([]Value, string) {
	if status.Source == "js" {
		value, ok := observations.JS[status.Key]
		if !ok {
			return nil, "JS observation missing"
		}
		return []Value{value}, ""
	}
	dom, ok := observations.DOM[status.Key]
	if !ok {
		return nil, "DOM observation missing"
	}
	reason := dom.Error
	if dom.Truncated {
		reason = "DOM observation truncated"
	}
	if status.Operation == "exists" {
		if len(dom.Nodes) > 0 {
			return []Value{{Exists: true, Type: "string"}}, reason
		}
		return nil, reason
	}
	values := make([]Value, 0, len(dom.Nodes))
	for _, node := range dom.Nodes {
		var value Value
		var ok bool
		switch status.Operation {
		case "text":
			value = node.Text
			ok = value.Type != "" || value.Error != "" || value.Truncated
		case "attributes":
			value, ok = node.Attributes[status.Field]
		case "properties":
			value, ok = node.Properties[status.Field]
		}
		if !ok {
			reason = "DOM field observation missing"
			value = Value{Error: reason}
		}
		values = append(values, value)
	}
	return values, reason
}

// Historical upstream toScalar preserves string/number and boolean-coerces all
// other values. False/null therefore become "false", while number zero is "0".
func scalar(value Value, status RuleStatus) (string, bool, string) {
	if value.Error != "" {
		return "", false, value.Error
	}
	if value.Truncated {
		return "", false, "value truncated"
	}
	if len(value.Value) > maxValueBytes {
		return "", false, "value exceeds 1048576 bytes"
	}
	if !value.Exists {
		return "", false, ""
	}
	if status.Operation == "text" {
		text := strings.TrimSpace(value.Value)
		return text, text != "", ""
	}
	switch value.Type {
	case "string", "number":
		return value.Value, true, ""
	case "boolean":
		if value.Value != "true" && value.Value != "false" {
			return "", false, "invalid boolean observation"
		}
		return value.Value, true, ""
	case "null":
		return "false", true, ""
	case "undefined":
		return "false", status.Source == "js", ""
	case "object", "function", "symbol":
		return "true", true, ""
	case "bigint":
		if value.Value == "0" {
			return "false", true, ""
		}
		return "true", true, ""
	default:
		return "", false, "unsupported observation type: " + value.Type
	}
}
func keys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
func unique(values []string) []string {
	set := make(map[string]bool)
	for _, value := range values {
		set[value] = true
	}
	return keys(set)
}
