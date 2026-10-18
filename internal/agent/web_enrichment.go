package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"scanplatform/internal/rulelib"
	"scanplatform/internal/webevidence"
)

type supplementRuleResult struct {
	RuleID       string `json:"rule_id"`
	RuleRevision int    `json:"rule_revision"`
	Outcome      string `json:"outcome"`
}
type supplementStorage struct {
	Body             string `json:"body"`
	RequestTruncated bool   `json:"request_truncated"`
	HeadersTruncated bool   `json:"headers_truncated"`
}
type webSupplement struct {
	URL         string                 `json:"url"`
	RuleIDs     []string               `json:"rule_ids"`
	Outcome     string                 `json:"outcome"`
	Response    *webevidence.Response  `json:"response,omitempty"`
	Matches     []Technology           `json:"matches,omitempty"`
	RuleResults []supplementRuleResult `json:"rule_results"`
	Error       string                 `json:"error,omitempty"`
	Reused      bool                   `json:"reused,omitempty"`
	Storage     supplementStorage      `json:"storage"`
}

func entryMillis(ctx context.Context) int {
	if deadline, ok := ctx.Deadline(); ok {
		return max(1, min(90000, int(time.Until(deadline).Milliseconds())))
	}
	return 90000
}
func webOrigin(left, right *url.URL) bool {
	return left.Scheme == right.Scheme && strings.EqualFold(left.Hostname(), right.Hostname()) && urlPort(left) == urlPort(right)
}
func parseWebURL(raw string) (*url.URL, error) {
	if len(raw) > 8192 {
		return nil, fmt.Errorf("HTTP evidence URL exceeds bound")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid HTTP evidence URL")
	}
	return u, nil
}
func sameWebURL(left, right string) bool {
	a, e := parseWebURL(left)
	b, f := parseWebURL(right)
	return e == nil && f == nil && webOrigin(a, b) && a.EscapedPath() == b.EscapedPath() && a.RawQuery == b.RawQuery && a.ForceQuery == b.ForceQuery
}
func redirectStatus(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

// Every path change must have its preceding response and a contiguous followed
// edge. A blocked destination never becomes an attempt or an icon request.
func validateWebResult(input webevidence.ProbeRequest, result webevidence.ProbeResult) error {
	if result.ID != input.ID || result.Protocol != webevidence.Protocol || result.CFFSHA256 != input.CFFSHA256 {
		return fmt.Errorf("web helper contract/digest mismatch")
	}
	base, e := parseWebURL(input.URL)
	if e != nil {
		return e
	}
	observed, e := parseWebURL(result.Response.URL)
	if e != nil {
		return e
	}
	if input.EnrichmentProfile == "" {
		if result.EnrichmentProfile != "" || len(result.Redirects) > 0 || !sameAuthority(observed, base) || observed.EscapedPath() != base.EscapedPath() || observed.RawQuery != base.RawQuery || observed.Scheme != base.Scheme && !input.AlternateScheme || result.Response.ConnectIP != input.ConnectIP {
			return fmt.Errorf("web helper returned an unrelated legacy endpoint")
		}
		return nil
	}
	if input.EnrichmentProfile != webevidence.EnrichmentProfile || result.EnrichmentProfile != input.EnrichmentProfile || result.Profile != webevidence.Profile || result.InputURL != input.URL {
		return fmt.Errorf("web helper enrichment identity mismatch")
	}
	limit := input.MaxRequests
	if limit <= 0 {
		limit = 8
	}
	if result.Requests < 1 || result.Requests > limit || len(result.Attempts) < 1 || len(result.Icons) > 2 || result.Requests != len(result.Attempts) {
		return fmt.Errorf("invalid web request/attempt budget")
	}
	if input.Step == "supplement" && (result.Requests != 1 || len(result.Attempts) != 1 || len(result.Icons) != 0 || len(result.Redirects) != 0 || input.AlternateScheme) {
		return fmt.Errorf("supplement must be one exact GET")
	}
	primaryCount := len(result.Attempts) - len(result.Icons)
	if primaryCount < 1 || result.Requests != len(result.Attempts) {
		return fmt.Errorf("invalid primary/icon attempt partition")
	}
	for index, icon := range result.Icons {
		attempt := result.Attempts[primaryCount+index]
		u, err := parseWebURL(icon.URL)
		if err != nil || !webOrigin(u, observed) || icon.ConnectIP != input.ConnectIP || !sameWebURL(attempt.URL, icon.URL) || attempt.StatusCode != icon.StatusCode || attempt.BodySHA256 != icon.BodySHA256 {
			return fmt.Errorf("icon escaped primary origin or attempt trace")
		}
	}
	edges := make(map[int]webevidence.RedirectStep)
	lastEdge := -1
	followed := 0
	finalIndex := primaryCount - 1
	for _, edge := range result.Redirects {
		if edge.AttemptIndex <= lastEdge || edge.AttemptIndex < 0 || edge.AttemptIndex >= primaryCount {
			return fmt.Errorf("invalid redirect trace ordering")
		}
		lastEdge = edge.AttemptIndex
		from := result.Attempts[edge.AttemptIndex]
		if !sameWebURL(from.URL, edge.FromURL) || from.StatusCode != edge.StatusCode || !redirectStatus(from.StatusCode) {
			return fmt.Errorf("redirect source does not match attempt")
		}
		u, _ := parseWebURL(from.URL)
		ref, err := url.Parse(strings.TrimSpace(from.Headers.Get("Location")))
		var target *url.URL
		if err == nil {
			target = u.ResolveReference(ref)
			target.Fragment = ""
			target.RawFragment = ""
			target.Scheme = strings.ToLower(target.Scheme)
		}
		if edge.Outcome == "followed" {
			followed++
			if followed > 3 || target == nil || target.User != nil || !webOrigin(target, u) || !sameWebURL(target.String(), edge.ToURL) || edge.AttemptIndex+1 >= primaryCount || !sameWebURL(result.Attempts[edge.AttemptIndex+1].URL, edge.ToURL) {
				return fmt.Errorf("unrelated or noncontiguous redirect")
			}
		} else {
			switch edge.Outcome {
			case "blocked_cross_origin", "invalid_location", "missing_location", "location_too_long", "loop", "hop_limit", "skipped_budget", "canceled", "fetch_failed":
			default:
				return fmt.Errorf("unknown stopped redirect outcome")
			}
			switch edge.Outcome {
			case "blocked_cross_origin":
				if target == nil || webOrigin(target, u) {
					return fmt.Errorf("cross-origin stop has no cross-origin destination")
				}
			case "loop":
				seen := false
				for _, attempt := range result.Attempts[:edge.AttemptIndex+1] {
					if target != nil && sameWebURL(target.String(), attempt.URL) {
						seen = true
					}
				}
				if !seen {
					return fmt.Errorf("loop stop is not a loop")
				}
			case "hop_limit":
				if followed != 3 {
					return fmt.Errorf("redirect hop-limit stop before limit")
				}
			case "skipped_budget":
				if result.Requests < limit {
					return fmt.Errorf("redirect budget stop before limit")
				}
			case "missing_location":
				if strings.TrimSpace(from.Headers.Get("Location")) != "" {
					return fmt.Errorf("missing-location stop has a location")
				}
			}
			if edge.ToURL != "" && (target == nil || target.String() != edge.ToURL) {
				return fmt.Errorf("stopped destination mismatch")
			}
			failed := (edge.Outcome == "fetch_failed" || edge.Outcome == "canceled") && edge.AttemptIndex+2 == primaryCount
			if failed {
				attempt := result.Attempts[edge.AttemptIndex+1]
				next, err := parseWebURL(attempt.URL)
				if err != nil || !webOrigin(next, u) || !sameWebURL(attempt.URL, edge.ToURL) || attempt.StatusCode != 0 || attempt.Error == "" {
					return fmt.Errorf("invalid failed redirect attempt")
				}
				finalIndex = edge.AttemptIndex
			} else if edge.AttemptIndex != primaryCount-1 {
				return fmt.Errorf("stopped redirect was fetched")
			}
		}
		edges[edge.AttemptIndex] = edge
	}
	for index, response := range result.Attempts[:primaryCount] {
		if input.Step != "supplement" && redirectStatus(response.StatusCode) {
			if _, ok := edges[index]; !ok {
				return fmt.Errorf("redirect response omitted its terminal/followed trace")
			}
		}
		u, err := parseWebURL(response.URL)
		if err != nil || response.ConnectIP != input.ConnectIP || !(strings.EqualFold(u.Hostname(), base.Hostname()) && urlPort(u) == urlPort(base)) {
			return fmt.Errorf("attempt escaped fixed endpoint")
		}
		if index == 0 {
			if !sameWebURL(response.URL, input.URL) {
				return fmt.Errorf("unrelated first attempt")
			}
		} else {
			previous := result.Attempts[index-1]
			edge, exists := edges[index-1]
			fallback := index == 1 && previous.StatusCode == 0 && input.AlternateScheme && u.Scheme != base.Scheme && u.EscapedPath() == base.EscapedPath() && u.RawQuery == base.RawQuery
			traced := exists && (edge.Outcome == "followed" || edge.Outcome == "fetch_failed" || edge.Outcome == "canceled") && sameWebURL(response.URL, edge.ToURL)
			if !traced && !fallback {
				return fmt.Errorf("untraced HTTP path/scheme change")
			}
		}
	}
	last := result.Attempts[finalIndex]
	if !sameWebURL(last.URL, result.Response.URL) || last.StatusCode != result.Response.StatusCode || last.BodySHA256 != result.Response.BodySHA256 || result.Response.ConnectIP != input.ConnectIP {
		return fmt.Errorf("final response does not match primary attempt")
	}
	if input.Step == "supplement" && !sameWebURL(result.Response.URL, input.URL) {
		return fmt.Errorf("supplement changed URL")
	}

	if result.Response.Completeness == "full" && (len(result.Response.Body) > webevidence.MaxBody || result.Response.DecodedBytes != len(result.Response.Body) || webevidence.SHA256(result.Response.Body) != result.Response.BodySHA256) {
		return fmt.Errorf("response body integrity mismatch")
	}
	return nil
}

func compactSupplementResponse(response webevidence.Response) (*webevidence.Response, supplementStorage) {
	response.Body = append([]byte(nil), response.Body...)
	response.BodyStorage = "complete"
	if len(response.Body) > 32<<10 {
		response.Body = response.Body[:32<<10]
		response.BodyStorage = "prefix"
	}
	if response.Completeness != "full" {
		response.BodyStorage = "prefix"
	}
	var requestCut, headerCut bool
	response.RequestRaw, requestCut = truncateBytes([]byte(response.RequestRaw), 16<<10)
	response.HeaderRaw, headerCut = truncateBytes([]byte(response.HeaderRaw), 16<<10)
	headers, _ := json.Marshal(response.Headers)
	if len(headers) > 16<<10 {
		response.Headers = nil
		headerCut = true
	}
	response.TLS = nil // Primary TLS evidence remains in the parent probe.
	return &response, supplementStorage{Body: response.BodyStorage, RequestTruncated: requestCut, HeadersTruncated: headerCut}
}

func (a *Agent) collectWebSupplements(ctx context.Context, binary string, input webevidence.ProbeRequest, main webevidence.ProbeResult, rules []rulelib.Rule, products []string, budget *webEntryBudget) ([]webSupplement, []Technology, supplementPlan) {
	if input.EnrichmentProfile == "" || main.Response.StatusCode == 0 {
		return nil, nil, supplementPlan{}
	}
	selected := make([]rulelib.Rule, 0)
	for _, rule := range rules {
		if rule.Enabled && rule.Kind == "http" && rule.Engine == "native" && rule.Collection != nil && rulelib.CollectionMatchesProducts(rule, products) {
			selected = append(selected, rule)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	plan := supplementPlan{MatchedRules: len(selected)}
	if len(selected) > 64 {
		plan.Truncated = true
		plan.OmittedRules = len(selected) - 64
		selected = selected[:64]
	}
	plan.SelectedRules = len(selected)
	base, _ := parseWebURL(main.Response.URL)
	type group struct {
		url   string
		rules []rulelib.Rule
	}
	var groups []group
	positions := map[string]int{}
	for _, rule := range selected {
		if rulelib.Validate(rule) != nil {
			continue
		}
		target := base.ResolveReference(&url.URL{Path: rule.Collection.Path})
		raw := target.String()
		if !webOrigin(base, target) {
			continue
		}
		if index, exists := positions[raw]; exists {
			groups[index].rules = append(groups[index].rules, rule)
		} else {
			positions[raw] = len(groups)
			groups = append(groups, group{raw, []rulelib.Rule{rule}})
		}
	}
	collected := map[string]webevidence.Response{main.Response.URL: main.Response}
	seen := map[string]bool{main.Response.URL: true}
	for _, response := range main.Attempts {
		seen[response.URL] = true
	}
	for _, response := range main.Icons {
		seen[response.URL] = true
		if response.Completeness == "full" && len(response.Body) == response.DecodedBytes {
			collected[response.URL] = response
		}
	}
	var evidence []webSupplement
	var technologies []Technology
	fetched := 0
	for _, group := range groups {
		item := webSupplement{URL: group.url, Outcome: "not_matched", Storage: supplementStorage{Body: "hash_only"}}
		for _, rule := range group.rules {
			item.RuleIDs = append(item.RuleIDs, rule.ID)
		}
		response, reused := collected[group.url]
		complete := reused && response.Completeness == "full" && response.Error == "" && len(response.Body) == response.DecodedBytes
		if seen[group.url] && !complete {
			item.Outcome = "skipped_incomplete_reuse"
		} else if complete {
			item.Reused = true
		} else if fetched >= 2 {
			item.Outcome = "skipped_limit"
		} else if budget.count() >= 8 {
			item.Outcome = "skipped_budget"
		} else if ctx.Err() != nil {
			item.Outcome = "error"
			item.Error = context.Cause(ctx).Error()
		} else {
			fetched++
			before := budget.count()
			supp := input
			id, idErr := RandomID()
			supp.ID = id
			supp.URL = group.url
			supp.Step = "supplement"
			supp.MaxRequests = 1
			supp.AlternateScheme = false
			supp.CFF = nil
			supp.CFFSHA256 = webevidence.SHA256(nil)
			supp.EntryTimeoutMillis = entryMillis(ctx)
			u, _ := parseWebURL(group.url)
			var admission, token string
			var closeAdmission func()
			err := idErr
			if err == nil {
				admission, token, closeAdmission, err = startWebAdmissionLimited(ctx, supp.ID, supp.ConnectIP, u, false, &webAdmissionLimit{entry: budget, exactURL: true, maxRequests: 1})
			}
			if err == nil {
				supp.AdmissionURL, supp.AdmissionToken = admission, token
				var raw []byte
				raw, err = a.runWebHelper(ctx, binary, supp)
				closeAdmission()
				if err == nil {
					var result webevidence.ProbeResult
					if err = json.Unmarshal(raw, &result); err == nil {
						err = validateWebResult(supp, result)
						response = result.Response
					}
				}
			}
			budget.consumeAtLeast(before + 1)
			if err != nil {
				item.Outcome = "error"
				item.Error = err.Error()
			} else {
				collected[group.url] = response
				seen[group.url] = true
			}
		}
		if item.Outcome == "not_matched" {
			item.Response, item.Storage = compactSupplementResponse(response)
			if response.Error != "" {
				item.Outcome = "error"
				item.Error = response.Error
			} else if response.Completeness != "full" {
				item.Outcome = "partial"
			} else {
				in := rulelib.Input{Body: string(response.Body), Header: response.HeaderRaw, Title: collectedTitle(response.Body), Status: response.StatusCode}
				for _, rule := range group.rules {
					if ctx.Err() != nil {
						item.RuleResults = append(item.RuleResults, supplementRuleResult{rule.ID, rule.Revision, "partial"})
						if item.Outcome != "matched" {
							item.Outcome = "partial"
						}
						item.Error = context.Cause(ctx).Error()
						continue
					}
					outcome := "not_matched"
					if match, ok := rulelib.MatchCollectedHTTP(rule, in); ok {
						outcome = "matched"
						item.Outcome = "matched"
						name := match.Product
						if name == "" {
							name = rule.Name
						}
						item.Matches = append(item.Matches, Technology{Name: name, Version: match.Version, RuleID: rule.ID, RuleRevision: rule.Revision, Evidence: match.Evidence + "; collected " + group.url})
					}
					item.RuleResults = append(item.RuleResults, supplementRuleResult{rule.ID, rule.Revision, outcome})
				}
				technologies = mergeTechnologies(technologies, item.Matches)
			}
		}
		if len(item.RuleResults) == 0 {
			for _, rule := range group.rules {
				item.RuleResults = append(item.RuleResults, supplementRuleResult{rule.ID, rule.Revision, item.Outcome})
			}
		}
		evidence = append(evidence, item)
	}
	return evidence, technologies, plan
}

func collectedTitle(body []byte) string {
	if m := titlePattern.FindSubmatch(body); len(m) > 1 {
		return string(m[1])
	}
	return ""
}

// Existing raw request/response excerpts remain bounded independently. This last
// storage guard applies only to the new profile and never changes network work.
type supplementPlan struct {
	MatchedRules  int  `json:"matched_rules_count"`
	SelectedRules int  `json:"selected_rules_count"`
	OmittedRules  int  `json:"omitted_rules_count"`
	Truncated     bool `json:"truncated_plan"`
}
type webEvidenceEnvelope struct {
	RequestsBudgetUsed int                     `json:"requests_budget_used,omitempty"`
	SupplementPlan     *supplementPlan         `json:"supplement_plan,omitempty"`
	Probe              webevidence.ProbeResult `json:"probe"`
	Fingerprint        webevidence.MatchResult `json:"fingerprint"`
	AssignedBundle     string                  `json:"assigned_fingerprint_bundle"`
	BundleSchema       string                  `json:"fingerprint_bundle_schema,omitempty"`
	Supplements        []webSupplement         `json:"supplements,omitempty"`
	Storage            *webEvidenceStorage     `json:"storage,omitempty"`
}
type webEvidenceStorage struct {
	Bounded             bool `json:"bounded"`
	HeadersOmitted      bool `json:"headers_omitted,omitempty"`
	OmittedSupplements  int  `json:"omitted_supplements,omitempty"`
	OmittedTechnologies int  `json:"omitted_technologies,omitempty"`
}

func storeWebEvidence(obs *Observation, evidence *webEvidenceEnvelope, bounded bool) {
	if bounded {
		evidence.Probe.Title, _ = truncateBytes([]byte(evidence.Probe.Title), 2048)
		evidence.Storage = &webEvidenceStorage{Bounded: true}
	}
	for {
		encoded, _ := json.Marshal(evidence)
		obs.Evidence = string(encoded)
		raw, _ := json.Marshal(obs)
		if !bounded || len(raw) < maxBatchBytes-8192 {
			return
		}
		if !evidence.Storage.HeadersOmitted {
			evidence.Storage.HeadersOmitted = true
			strip := func(r *webevidence.Response) { r.Headers = nil; r.HeaderRaw = ""; r.RequestRaw = ""; r.TLS = nil }
			strip(&evidence.Probe.Response)
			for i := range evidence.Probe.Attempts {
				strip(&evidence.Probe.Attempts[i])
			}
			for i := range evidence.Probe.Icons {
				strip(&evidence.Probe.Icons[i])
			}
			for i := range evidence.Supplements {
				if evidence.Supplements[i].Response != nil {
					strip(evidence.Supplements[i].Response)
					evidence.Supplements[i].Storage.HeadersTruncated = true
					evidence.Supplements[i].Storage.RequestTruncated = true
				}
			}
			obs.Headers = nil
			continue
		}
		if len(evidence.Supplements) > 0 {
			keep := len(evidence.Supplements) / 2
			evidence.Storage.OmittedSupplements += len(evidence.Supplements) - keep
			evidence.Supplements = evidence.Supplements[:keep]
			continue
		}
		if len(obs.Technologies) > 0 {
			keep := len(obs.Technologies) / 2
			evidence.Storage.OmittedTechnologies += len(obs.Technologies) - keep
			obs.Technologies = obs.Technologies[:keep]
			continue
		}
		if len(evidence.Fingerprint.Matches) > 0 || len(evidence.Probe.Technologies) > 0 {
			evidence.Fingerprint.Matches = nil
			evidence.Probe.Technologies = nil
			continue
		}
		// No remaining reduction can make progress. Preserve the actual oversized
		// record so the common emit guard rejects it as non-retryable.
		return
	}
}
