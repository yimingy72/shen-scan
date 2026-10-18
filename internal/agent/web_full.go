package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	fb "scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/webevidence"
)

// The HTTP task remains the scheduling unit. Segments only checkpoint whole
// template progress through the existing result batch and completion fence.
func (a *Agent) runWebFull(ctx context.Context, task Task, payload httpPayload, binary string, emit func(Observation) error) error {
	if payload.WebExecutionProfile != webevidence.FullProfile || (payload.FingerprintBundleSchema != fb.Schema && !(payload.FingerprintBundleSchema == "" && payload.FingerprintBundle == fb.EmbeddedBundle)) || payload.HTTPProgress == nil || len(payload.Endpoints) != 1 {
		return &TaskError{Reason: "full HTTP requires a v2 bundle and initialized single-entry progress", Retryable: false}
	}
	ep := payload.Endpoints[0]
	progress := *payload.HTTPProgress
	progress.CompletedRuleIDs = append([]string(nil), progress.CompletedRuleIDs...)
	progress.Matches = append([]webevidence.Match(nil), progress.Matches...)
	failure := func(err error) Observation {
		obs := fullWebFailure(ep, progress, err)
		obs.WebScanOptions = payload.WebScanOptions
		return obs
	}

	release, err := a.acquireHTTPTarget(ctx, httpTargetKey(ep))
	if err != nil {
		return err
	}
	defer release()
	select {
	case a.endpointSlots <- struct{}{}:
		defer func() { <-a.endpointSlots }()
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	select {
	case a.httpxSlots <- struct{}{}:
		defer func() { <-a.httpxSlots }()
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	targets, err := prepareHTTPXTargets(ctx, a, []Endpoint{ep})
	if err != nil {
		return emit(failure(err))
	}
	raw := targets[0].url.String()
	parsed := targets[0].url
	ip, err := a.httpDialHost(ctx, parsed.Hostname(), urlPort(parsed), ep.IP, parsed.Hostname())
	if err != nil {
		return emit(failure(err))
	}
	cff, cached := a.ruleSets.cff(payload.RulesRef)
	if !cached {
		cff, err = buildHTTPXCFF(payload.Rules)
		if err != nil {
			return emit(failure(err))
		}
	}
	entryID := ep.WorkKey
	if entryID == "" {
		entryID = webevidence.SHA256([]byte(raw))
	}
	budget := &webEntryBudget{used: progress.RequestsUsed, maximum: progress.RequestsUsed + progress.SegmentRequestLimit - progress.SegmentRequestsUsed}
	if progress.Segment > progress.MaxSegments || progress.RequestsUsed >= progress.MaxRequests || progress.SegmentRequestLimit <= 0 {
		progress.StopReason = "cumulative_limit"
		return emit(failure(fmt.Errorf("full HTTP cumulative execution limit reached")))
	}
	segmentCtx := context.WithValue(ctx, httpFullSegmentKey{}, progress.Segment)
	identity := webevidence.ExecutionIdentity{EntryURL: progress.EntryURL, RulesRef: progress.RulesRef, SelectionProfileHash: progress.SelectionProfileHash, ManifestHash: progress.ManifestHash, TaskID: task.ID, AttemptNo: task.AttemptNo, EntryID: entryID, Segment: progress.Segment}
	id, err := RandomID()
	if err != nil {
		return err
	}
	input := webevidence.ProbeRequest{WebScanOptions: payload.WebScanOptions, ID: id, Protocol: webevidence.Protocol, Profile: webevidence.FullProfile, ExecutionProfile: webevidence.FullProfile, Identity: identity, URL: raw, ConnectIP: ip, Host: parsed.Host, HTTPHost: parsed.Host, SNI: parsed.Hostname(), TLSSNI: parsed.Hostname(), AlternateScheme: ep.URL == "", TimeoutMillis: int(minDuration(boundedTimeout(payload.TimeoutSeconds, 8*time.Second), 20*time.Second) / time.Millisecond), EntryTimeoutMillis: 90000, MaxRequests: progress.SegmentRequestLimit - progress.SegmentRequestsUsed, CFF: cff, CFFSHA256: webevidence.SHA256(cff)}
	admission, token, closeAdmission, err := startWebAdmissionLimited(segmentCtx, id, ip, parsed, input.AlternateScheme, &webAdmissionLimit{entry: budget, maxRequests: input.MaxRequests})
	if err != nil {
		return emit(failure(err))
	}
	input.AdmissionURL, input.AdmissionToken = admission, token
	output, probeErr := a.runWebHelper(segmentCtx, binary, input)
	closeAdmission()
	var probe webevidence.ProbeResult
	if probeErr == nil {
		probeErr = json.Unmarshal(output, &probe)
	}
	if probeErr == nil {
		probeErr = validateFullWebResult(input, probe)
	}
	if probeErr == nil && probe.Requests > budget.count()-progress.RequestsUsed {
		probeErr = fmt.Errorf("full probe made unadmitted requests")
	}
	progress.SegmentRequestsUsed += budget.count() - progress.RequestsUsed
	progress.RequestsUsed = budget.count()
	if probeErr != nil {
		return emit(failure(probeErr))
	}
	rulesForPassive := payload.Rules
	if payload.WebScanOptions != nil && !payload.WebScanOptions.Passive {
		rulesForPassive = nil
	}
	obs := webProbeObservation(ep, probe, rulesForPassive)
	obs.WebScanOptions = payload.WebScanOptions
	if payload.WebScanOptions != nil && !payload.WebScanOptions.Passive {
		obs.Technologies = nil
	}
	for _, technology := range obs.Technologies {
		progress.Matches = mergeFullMatches(progress.Matches, []webevidence.Match{{Candidate: technology.Candidate, CandidateReason: technology.CandidateReason, Name: technology.Name, Version: technology.Version, Engine: "httpx", Evidence: json.RawMessage(strconv.Quote(technology.Evidence))}})
	}
	var match webevidence.MatchResult
	if payload.WebScanOptions != nil && !payload.WebScanOptions.Active {
		match = webevidence.MatchResult{Protocol: webevidence.Protocol, ExecutionProfile: webevidence.FullProfile, Identity: identity, Bundle: payload.FingerprintBundle}
		if payload.WebScanOptions.Passive && probe.Response.StatusCode > 0 && probe.Response.Completeness == "full" {
			matchID, e := RandomID()
			if e != nil {
				return e
			}
			request := webevidence.MatchRequest{WebScanOptions: payload.WebScanOptions, Protocol: webevidence.Protocol, ID: matchID, ExecutionProfile: webevidence.FullProfile, Identity: identity, ExpectedBundle: payload.FingerprintBundle, Response: probe.Response, Icons: probe.Icons}
			resolve := func(c context.Context) (string, error) {
				return a.fingerprints.cache.get(c, a.client, a.workerID, a.cfg.SessionID, task, payload.FingerprintBundle)
			}
			match, err = a.fingerprints.matchBundle(ctx, request, payload.FingerprintBundleSchema, resolve)
			if err != nil {
				obs.Error = joinWebError(obs.Error, err.Error())
			} else if match.ExecutionProfile != webevidence.FullProfile || match.Identity != identity {
				obs.Error = joinWebError(obs.Error, "passive matcher changed execution identity")
			}
		}
		progress.Matches = mergeFullMatches(progress.Matches, match.Matches)
		progress.Complete = obs.Error == "" && probe.Response.Completeness == "full"
		progress.StopReason = "active-disabled"
		match.Active = &webevidence.ActiveResult{Complete: progress.Complete, StopReason: "active-disabled"}
		return emit(fullWebObservation(obs, probe, match, payload, progress))
	}
	for {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if !time.Now().Before(progress.Deadline) {
			progress.StopReason = "deadline"
			break
		}
		identity.Segment = progress.Segment
		matchID, err := RandomID()
		if err != nil {
			return err
		}
		remaining := progress.SegmentRequestLimit - progress.SegmentRequestsUsed
		if remaining <= 0 || progress.Segment > progress.MaxSegments {
			progress.StopReason = "cumulative_limit"
			break
		}
		segmentCtx = context.WithValue(ctx, httpFullSegmentKey{}, progress.Segment)
		// The helper returns its explicit partial state before this context expires.
		segmentDeadline := time.Now().Add(45 * time.Second)
		if segmentDeadline.After(progress.Deadline) {
			segmentDeadline = progress.Deadline
		}
		admission, token, closeAdmission, err = startWebAdmissionLimited(segmentCtx, matchID, ip, parsed, false, &webAdmissionLimit{entry: budget, maxRequests: min(1024, remaining)})
		if err != nil {
			return err
		}
		responses := []webevidence.Response{probe.Response}
		seenResponses := map[string]bool{probe.Response.URL: true}
		for _, response := range probe.Attempts {
			if !seenResponses[response.URL] {
				responses = append(responses, response)
				seenResponses[response.URL] = true
			}
		}
		products := append([]string(nil), probe.Technologies...)
		for _, m := range progress.Matches {
			products = append(products, m.Name)
		}
		request := webevidence.MatchRequest{WebScanOptions: payload.WebScanOptions, Protocol: webevidence.Protocol, ID: matchID, ExecutionProfile: webevidence.FullProfile, Identity: identity, ExpectedBundle: payload.FingerprintBundle, Response: probe.Response, Icons: probe.Icons, Active: &webevidence.ActiveRequest{EntryURL: raw, ConnectIP: ip, Host: parsed.Host, SNI: parsed.Hostname(), Responses: responses, CompletedRuleIDs: progress.CompletedRuleIDs, RemainingRuleIDs: progress.RemainingRuleIDs, CandidateProducts: products, RequestsUsed: budget.count(), MaxRequests: progress.MaxRequests, SegmentMaxRequests: min(1024, remaining), Deadline: progress.Deadline, SegmentDeadline: segmentDeadline, AdmissionURL: admission, AdmissionToken: token, TimeoutMillis: input.TimeoutMillis}}
		resolve := func(ctx context.Context) (string, error) {
			return a.fingerprints.cache.get(ctx, a.client, a.workerID, a.cfg.SessionID, task, payload.FingerprintBundle)
		}
		beforeMatch := budget.count()
		match, err = a.fingerprints.matchBundle(segmentCtx, request, payload.FingerprintBundleSchema, resolve)
		closeAdmission()
		progress.SegmentRequestsUsed += budget.count() - progress.RequestsUsed
		progress.RequestsUsed = budget.count()
		progress.Matches = mergeFullMatches(progress.Matches, match.Matches)
		if err != nil {
			progress.StopReason = "matcher_failed"
			obs.Error = joinWebError(obs.Error, err.Error())
			break
		}
		if match.Active != nil && match.Active.Requests > budget.count()-beforeMatch {
			progress.StopReason = "unadmitted_active_requests"
			obs.Error = joinWebError(obs.Error, "active matcher made unadmitted requests")
			break
		}
		if match.ExecutionProfile != webevidence.FullProfile || match.Identity != identity || match.Active == nil {
			progress.StopReason = "invalid_matcher_progress"
			obs.Error = joinWebError(obs.Error, "full matcher omitted execution identity/progress")
			break
		}
		completed := len(progress.CompletedRuleIDs)
		progress.CompletedRuleIDs = mergeFullIDs(progress.CompletedRuleIDs, match.Active.CompletedRuleIDs)
		progress.RemainingRuleIDs = match.Active.RemainingRuleIDs
		progress.Complete = match.Active.Complete
		progress.StopReason = match.Active.StopReason
		checkpoint := fullWebObservation(obs, probe, match, payload, progress)
		if progress.Complete || progress.Segment >= progress.MaxSegments || progress.ReservedRequests >= progress.MaxRequests {
			return emit(checkpoint)
		}
		if len(progress.CompletedRuleIDs) == completed && match.Active.Requests == 0 {
			progress.StopReason = "no_progress"
			break
		}
		if err = emit(checkpoint); err != nil {
			return err
		}
		progress.Segment++
		progress.SegmentRequestLimit = max(0, min(1024, progress.MaxRequests-progress.ReservedRequests))
		progress.ReservedRequests += progress.SegmentRequestLimit
		progress.ReservedSegment = progress.Segment
		progress.SegmentRequestsUsed = 0
		budget.maximum = budget.count() + progress.SegmentRequestLimit
	}
	return emit(fullWebObservation(obs, probe, match, payload, progress))
}

func fullWebFailure(ep Endpoint, p webevidence.EntryProgress, err error) Observation {
	obs := webFailure(ep, err)
	obs.ExecutionProfile = webevidence.FullProfile
	obs.HTTPProgress = &p
	for _, m := range p.Matches {
		obs.Technologies = append(obs.Technologies, Technology{Candidate: m.Candidate, CandidateReason: m.CandidateReason, Name: m.Name, Version: m.Version, RuleID: "fingers:" + m.Engine + ":" + m.Name, Evidence: string(m.Evidence)})
	}
	return obs
}
func fullWebObservation(base Observation, probe webevidence.ProbeResult, match webevidence.MatchResult, payload httpPayload, progress webevidence.EntryProgress) Observation {
	base.ExecutionProfile = webevidence.FullProfile
	base.WebScanOptions = payload.WebScanOptions
	options := payload.WebScanOptions
	browserSelected := options == nil || options.JSDOM
	hasBrowserGap := false
	for _, gap := range probe.CapabilityGaps {
		if gap == "wappalyzer-browser-js-dom" {
			hasBrowserGap = true
		}
	}
	applicable := webevidence.BrowserApplicable(probe.Response)
	if hasBrowserGap && (!browserSelected || !applicable) {
		filtered := []string{}
		for _, gap := range probe.CapabilityGaps {
			if gap != "wappalyzer-browser-js-dom" {
				filtered = append(filtered, gap)
			}
		}
		probe.CapabilityGaps = filtered
	}
	if payload.WebBrowserProfile == webevidence.BrowserProfile && browserSelected && hasBrowserGap {
		state := "pending"
		if !applicable {
			state = "not_applicable"
		}
		base.Browser = &webevidence.BrowserStage{Profile: webevidence.BrowserProfile, State: state}
	}
	if options != nil && options.Screenshot && probe.Response.StatusCode > 0 {
		base.Screenshot = &webevidence.ScreenshotMetadata{WebStage: webevidence.WebStage{State: "pending"}}
	}
	base.HTTPProgress = &progress
	var additional []Technology
	for _, m := range progress.Matches {
		additional = append(additional, Technology{Candidate: m.Candidate, CandidateReason: m.CandidateReason, Name: m.Name, Version: m.Version, RuleID: "fingers:" + m.Engine + ":" + m.Name, Evidence: string(m.Evidence)})
	}
	base.Technologies = mergeTechnologies(base.Technologies, additional)
	if !progress.Complete || base.Error != "" || hasRequiredWebCapabilityGap(probe.CapabilityGaps) {
		base.Coverage = "partial"
		base.Outcome = "incomplete"
	}
	var rules []webevidence.RuleExecution
	if match.Active != nil {
		rules = match.Active.Rules
	}
	for _, r := range rules {
		if r.Status == "failed" || r.Status == "partial" {
			base.Coverage = "partial"
			base.Outcome = "incomplete"
		}
	}
	evidence := webEvidenceEnvelope{Probe: compactProbe(probe), Fingerprint: compactFullMatch(match), AssignedBundle: payload.FingerprintBundle, BundleSchema: payload.FingerprintBundleSchema, RequestsBudgetUsed: progress.RequestsUsed}
	storeWebEvidence(&base, &evidence, false)
	return base
}
func mergeFullIDs(old, next []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(old)+len(next))
	for _, list := range [][]string{old, next} {
		for _, id := range list {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}
func mergeFullMatches(old, next []webevidence.Match) []webevidence.Match {
	seen := map[string]bool{}
	var out []webevidence.Match
	for _, list := range [][]webevidence.Match{old, next} {
		for _, m := range list {
			key := m.Engine + "\x00" + m.Name + "\x00" + m.Version + "\x00" + strconv.FormatBool(m.Candidate) + "\x00" + m.CandidateReason + "\x00" + webevidence.SHA256(m.Evidence)
			if !seen[key] {
				seen[key] = true
				out = append(out, m)
			}
		}
	}
	return out
}

func validateFullWebResult(input webevidence.ProbeRequest, result webevidence.ProbeResult) error {
	if input.WebScanOptions != nil && (result.WebScanOptions == nil || *input.WebScanOptions != *result.WebScanOptions) {
		return fmt.Errorf("full helper did not attest selected scan options")
	}
	if result.ID != input.ID || result.Protocol != input.Protocol || result.CFFSHA256 != input.CFFSHA256 || result.ExecutionProfile != webevidence.FullProfile || result.Identity != input.Identity || result.Profile != webevidence.FullProfile {
		return fmt.Errorf("full web helper identity/profile mismatch")
	}
	if result.Requests < 1 || result.Requests > input.MaxRequests {
		return fmt.Errorf("full web helper request budget mismatch")
	}
	base, _ := url.Parse(input.URL)
	for _, r := range append(append([]webevidence.Response{result.Response}, result.Attempts...), result.Icons...) {
		u, err := parseWebURL(r.URL)
		if err != nil || r.ConnectIP != input.ConnectIP || !sameAuthority(u, base) || u.Scheme != base.Scheme && !input.AlternateScheme {
			return fmt.Errorf("full web helper response escaped assigned entry")
		}
		if r.Completeness == "full" && (len(r.Body) > webevidence.MaxBody || r.DecodedBytes != len(r.Body) || webevidence.SHA256(r.Body) != r.BodySHA256) {
			return fmt.Errorf("full response body integrity mismatch")
		}
	}
	return nil
}

func compactFullMatch(match webevidence.MatchResult) webevidence.MatchResult {
	if match.Active == nil {
		return match
	}
	active := *match.Active
	active.Responses = append([]webevidence.Response(nil), active.Responses...)
	for i := range active.Responses {
		active.Responses[i].Body = nil
		active.Responses[i].BodyStorage = "hash_only"
		active.Responses[i].RequestRaw, _ = truncateBytes([]byte(active.Responses[i].RequestRaw), 16<<10)
		active.Responses[i].HeaderRaw, _ = truncateBytes([]byte(active.Responses[i].HeaderRaw), 16<<10)
		active.Responses[i].TLS = nil
	}
	match.Active = &active
	return match
}

func hasRequiredWebCapabilityGap(gaps []string) bool {
	for _, gap := range gaps {
		switch gap {
		case "http2-probe", "unsafe", "ztls", "headless":
			continue
		default:
			return true
		}
	}
	return false
}
