package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"scanplatform/internal/webevidence"
	"scanplatform/webprobe/browserfp"
)

const browserEngine = "chromium-rod-v0.116.2/wappalyzergo-v0.2.96-js-dom"

func serveBrowser(input io.Reader, output io.Writer) error {
	defer closeBrowserRuntime()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), webevidence.MaxMessage)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		controlledBrowser.stopIdle()
		var request webevidence.BrowserRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			return err
		}
		result, err := probeBrowser(context.Background(), request)
		if err != nil {
			result.Error = err.Error()
			result.Complete = false
			if result.StopReason == "" {
				result.StopReason = "browser-error"
			}
		}
		if err := encoder.Encode(result); err != nil {
			return err
		}
		controlledBrowser.scheduleIdle(time.Minute)
	}
	return scanner.Err()
}

func probeBrowser(ctx context.Context, input webevidence.BrowserRequest) (result webevidence.BrowserResult, err error) {
	jsEnabled := input.WebScanOptions == nil || input.WebScanOptions.JSDOM
	shotEnabled := input.WebScanOptions != nil && input.WebScanOptions.Screenshot
	deadline := 5 * time.Second
	if shotEnabled {
		deadline = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	result = webevidence.BrowserResult{ID: input.ID, Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, Identity: input.Identity, Parent: input.Parent, CFFSHA256: webevidence.SHA256(input.CFF), Engine: browserEngine}
	jsRequested := jsEnabled
	result.JSDOMEnabled = &jsRequested
	result.JSDOM = &webevidence.WebStage{State: "disabled"}
	if shotEnabled {
		if jsEnabled {
			result.Engine += "+" + screenshotEngine
		} else {
			result.Engine = screenshotEngine
		}
		result.Screenshot = &webevidence.BrowserScreenshot{WebStage: webevidence.WebStage{State: "failed", Error: "browser did not reach screenshot capture"}}
	}
	if input.Protocol != webevidence.Protocol || input.Profile != webevidence.BrowserProfile {
		return result, errors.New("unsupported browser IPC protocol/profile")
	}
	if !jsEnabled && !shotEnabled {
		result.Complete = true
		result.StopReason = "not-applicable"
		return result, nil
	}
	if !jsEnabled && len(input.CFF) == 0 && input.CFFSHA256 != "" {
		result.CFFSHA256 = input.CFFSHA256
	}
	if input.CFFSHA256 != "" && input.CFFSHA256 != result.CFFSHA256 {
		return result, errors.New("browser CFF SHA256 mismatch")
	}
	if input.MaxRequests <= 0 {
		return result, errors.New("browser request budget exhausted")
	}
	var matcher *browserfp.Matcher
	collector := ""
	if jsEnabled {
		executionPlan, planErr := cachedBrowserExecutionPlan(input.CFF, result.CFFSHA256)
		err = planErr
		matcher = executionPlan.matcher
		if err != nil {
			result.JSDOM = &webevidence.WebStage{State: "failed", Error: err.Error()}
			if !shotEnabled {
				return result, err
			}
			jsEnabled = false
		}
		if jsEnabled {
			result.PlanSHA256 = executionPlan.planSHA256
			result.SampleWindow = "DOMContentLoaded and +400ms; later asynchronous mutations outside sampled coverage"
			if !executionPlan.hasRules {
				jsEnabled = false
				result.JSDOM = &webevidence.WebStage{State: "not_applicable"}
				if !shotEnabled {
					result.Complete = true
					result.StopReason = "not-applicable"
					return result, nil
				}
			}
			if jsEnabled {
				collector = executionPlan.collector
			}
		}
	}
	runtimeInput := browserRunInput{Request: input.ProbeRequest, Eval: collector, Screenshot: shotEnabled}
	if input.Seed != nil {
		runtimeInput.Seed = *input.Seed
	}
	observed, runErr := runBrowser(ctx, runtimeInput)
	result.BrowserVersion = observed.BrowserVersion
	result.BlockedCount = observed.BlockedCount
	if shotEnabled && observed.Screenshot != nil {
		result.Screenshot = observed.Screenshot
	}
	if shotEnabled && runErr != nil && result.Screenshot.State == "failed" {
		result.Screenshot.Error = runErr.Error()
		result.Screenshot.StopReason = "browser-error"
	}
	for _, attempt := range observed.Attempts {
		// Body bytes were consumed and bounded by fullCapture. Browser evidence
		// needs accounting/hash metadata; the immutable parent keeps HTTP evidence.
		attempt.Body = nil
		attempt.Headers = nil
		attempt.RequestRaw = ""
		attempt.HeaderRaw = ""
		attempt.TLS = nil
		result.Attempts = append(result.Attempts, attempt)
	}
	result.Requests = len(observed.Attempts)
	for _, blocked := range observed.Blocked {
		result.Blocked = append(result.Blocked, webevidence.BrowserBlockedRequest{URL: blocked.URL, Method: blocked.Method, Reason: blocked.Reason})
	}
	if !jsEnabled {
		result.Complete = runErr == nil && result.JSDOM.State != "failed" && (!shotEnabled || result.Screenshot.State == "complete")
		result.StopReason = "sample-window-complete"
		if !result.Complete {
			result.StopReason = "screenshot-partial"
		}
		compactBrowserResult(&result)
		return result, runErr
	}
	// Each sample retains official matcher confidence/version/evidence independently.
	// A technology discovered at either time is kept; a later disappearance does not
	// erase positive evidence. Coverage requires valid observations at both times.
	samples := make([]browserfp.Result, 0, len(observed.Samples))
	complete := !observed.Partial && runErr == nil && observed.JSDOMError == "" && len(observed.Samples) == 2
	for _, raw := range observed.Samples {
		var values browserfp.Observations
		if decodeErr := json.Unmarshal(raw, &values); decodeErr != nil {
			complete = false
			continue
		}
		sample := matcher.MatchContext(ctx, values)
		samples = append(samples, sample)
		complete = complete && sample.Complete
	}
	if len(samples) == 0 {
		samples = append(samples, matcher.MatchContext(ctx, browserfp.Observations{}))
		complete = false
	}
	byName := map[string][]browserfp.Match{}
	rules := map[int]browserfp.RuleStatus{}
	for _, sample := range samples {
		for _, match := range sample.Matches {
			byName[match.Name] = append(byName[match.Name], match)
		}
		for _, rule := range sample.Rules {
			previous, exists := rules[rule.ID]
			if !exists || rule.Status == "incomplete" || rule.Status == "unsupported" || (rule.Status == "matched" && previous.Status == "not_matched") {
				rules[rule.ID] = rule
			}
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	evidenceBytes := 0
	for _, name := range names {
		matches := byName[name]
		merged := matches[0]
		merged.Evidence = nil
		seen := map[int]bool{}
		confidence := 0
		for _, match := range matches {
			if merged.Version == "" {
				merged.Version = match.Version
			}
			merged.Confidence = max(merged.Confidence, match.Confidence)
			for _, evidence := range match.Evidence {
				if !seen[evidence.RuleID] {
					seen[evidence.RuleID] = true
					merged.Evidence = append(merged.Evidence, evidence)
					confidence += evidence.Confidence
				}
			}
		}
		if len(merged.Evidence) > 0 {
			merged.Confidence = min(100, confidence)
		}
		evidence, _ := json.Marshal(map[string]any{"source": "wappalyzer-js-dom", "sample_window": "DOMContentLoaded and +400ms; later changes outside sampled coverage", "match": merged})
		match := webevidence.Match{Name: name, Version: merged.Version, Engine: result.Engine, Evidence: evidence}
		raw, _ := json.Marshal(match)
		if evidenceBytes+len(raw) > 384<<10 {
			complete = false
			result.Error = "browser evidence truncated at output budget"
			compact, _ := json.Marshal(map[string]any{"compacted": true, "sha256": webevidence.SHA256(match.Evidence), "confidence": merged.Confidence})
			match.Evidence = compact
			raw, _ = json.Marshal(match)
		}
		evidenceBytes += len(raw)
		result.Matches = append(result.Matches, match)
	}
	ids := make([]int, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	negative := []int{}
	evaluated, unsupported, incomplete := 0, 0, 0
	for _, id := range ids {
		rule := rules[id]
		if rule.Status == "unsupported" {
			unsupported++
		}
		if rule.Status == "incomplete" {
			incomplete++
		}
		if rule.Status == "matched" || rule.Status == "not_matched" {
			evaluated++
		}
		if rule.Status == "not_matched" {
			negative = append(negative, id)
			continue
		}
		status := rule.Status
		if status == "incomplete" || status == "unsupported" {
			status = "partial"
		}
		reason := rule.Reason
		if status == "partial" {
			reason = fmt.Sprintf("%s %s selector/path=%q operation=%s field=%q: %s", rule.Name, rule.Source, rule.Key, rule.Operation, rule.Field, reason)
		}
		execution := webevidence.RuleExecution{RuleID: fmt.Sprintf("wapp-browser:%d", id), Status: status, Error: reason}
		raw, _ := json.Marshal(execution)
		if evidenceBytes+len(raw) > 480<<10 {
			complete = false
			result.Error = "browser rule outcomes truncated at output budget"
			continue
		}
		evidenceBytes += len(raw)
		result.Rules = append(result.Rules, execution)
	}
	negativeRaw, _ := json.Marshal(negative)
	result.TotalRules = len(rules)
	result.EvaluatedRules = evaluated
	result.UnsupportedRules = unsupported
	result.IncompleteRules = incomplete
	result.OmittedNegativeRules = len(negative)
	result.NegativeOutcomesSHA256 = webevidence.SHA256(negativeRaw)
	result.JSDOM = &webevidence.WebStage{State: "complete"}
	if !complete {
		result.JSDOM.State = "partial"
		result.JSDOM.Error = observed.JSDOMError
		if runErr != nil {
			result.JSDOM.State = "failed"
			result.JSDOM.Error = runErr.Error()
		}
		if result.JSDOM.Error == "" {
			result.JSDOM.Error = "some selected rules or page resources were incomplete"
		}
	}
	result.Complete = complete && (!shotEnabled || result.Screenshot.State == "complete")
	switch {
	case runErr != nil:
		result.StopReason = "browser-error"
		if strings.Contains(runErr.Error(), "unavailable") || strings.Contains(runErr.Error(), "sandbox") {
			result.StopReason = "browser-unavailable"
		}
	case observed.Partial:
		result.StopReason = "browser-network-partial"
	case !complete:
		result.StopReason = "browser-rules-partial"
	case shotEnabled && result.Screenshot.State != "complete":
		result.StopReason = "screenshot-partial"
	default:
		result.StopReason = "sample-window-complete"
	}
	compactBrowserResult(&result)
	return result, runErr
}

func compactBrowserResult(result *webevidence.BrowserResult) {
	// PNG has its own768KiB limit and is persisted separately from indexed JSON.
	// It must never consume the JS metadata budget or discard valid JS matches.
	if result.Screenshot != nil {
		data := result.Screenshot.PNG
		result.Screenshot.PNG = nil
		defer func() { result.Screenshot.PNG = data }()
	}
	if raw, _ := json.Marshal(result); len(raw) > 512<<10 {
		result.Complete = false
		result.Error = "browser evidence exceeds 512KiB result budget"
		result.StopReason = "browser-output-partial"
		originalMatches, _ := json.Marshal(result.Matches)
		result.EvidenceSHA256 = webevidence.SHA256(originalMatches)
		for i := range result.Matches {
			original := result.Matches[i].Evidence
			result.Matches[i].Evidence, _ = json.Marshal(map[string]any{"compacted": true, "sha256": webevidence.SHA256(original)})
		}
		// Preserve all positive names/versions; remove noisy denied URLs first.
		result.Blocked = nil
		if raw, _ := json.Marshal(result); len(raw) > 512<<10 {
			for i := range result.Matches {
				result.Matches[i].Evidence = nil
			}
			result.Rules = nil
			for i := range result.Attempts {
				result.Attempts[i].Error = ""
			}
		}
	}
}
