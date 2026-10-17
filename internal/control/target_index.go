package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"scanplatform/internal/rulelib"
)

var verificationTitlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func canonicalTarget(value string) string {
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		value = u.Hostname()
	}
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.String()
	}
	return value
}

func taskTargetKeys(payload []byte) []string {
	var p struct {
		Targets   []string                         `json:"targets"`
		Endpoints []struct{ IP, Host, URL string } `json:"endpoints"`
		Endpoint  *struct{ IP, Host, URL string }  `json:"endpoint"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return nil
	}
	keys := make(map[string]bool)
	for _, value := range p.Targets {
		if key := canonicalTarget(value); key != "" {
			keys[key] = true
		}
	}
	for _, ep := range p.Endpoints {
		value := ep.Host
		if value == "" {
			value = ep.URL
		}
		if value == "" {
			value = ep.IP
		}
		if key := canonicalTarget(value); key != "" {
			keys[key] = true
		}
	}
	if p.Endpoint != nil {
		value := p.Endpoint.Host
		if value == "" {
			value = p.Endpoint.URL
		}
		if value == "" {
			value = p.Endpoint.IP
		}
		if key := canonicalTarget(value); key != "" {
			keys[key] = true
		}
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func insertTaskTargets(ctx context.Context, tx pgx.Tx, taskID string, payload []byte) error {
	keys := taskTargetKeys(payload)
	if len(keys) == 0 {
		return errors.New("task has no source targets")
	}
	rows := make([][]any, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, []any{taskID, key})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"task_targets"}, []string{"task_id", "target_key"}, pgx.CopyFromRows(rows))
	return err
}

func observationTarget(typeName string, payload []byte, source string, item *Observation) (string, error) {
	if item == nil || item.Kind != typeName {
		return "", errors.New("observation kind does not match task type")
	}
	if typeName == "poc" {
		if err := validatePOCObservation(payload, item); err != nil {
			return "", err
		}
		if source == "" {
			return "", errors.New("PoC task has no source target")
		}
		return source, nil
	}
	keys := taskTargetKeys(payload)
	if len(keys) == 0 {
		return "", errors.New("task has no source target")
	}
	if typeName == "http" {
		if source == "" {
			source = keys[0]
		}
		if item.Target != "" && !contains(keys, canonicalTarget(item.Target)) {
			return "", errors.New("HTTP observation belongs to a different source target")
		}
		var p struct {
			Endpoints []taskEndpoint `json:"endpoints"`
		}
		if json.Unmarshal(payload, &p) != nil {
			return "", errors.New("invalid HTTP task payload")
		}
		if item.URL != "" {
			inside := false
			for _, ep := range p.Endpoints {
				if _, ok := observedEndpoint(ep, item.URL); ok {
					if item.WorkKey != "" && ep.WorkKey != "" && item.WorkKey != ep.WorkKey {
						return "", errors.New("HTTP work binding does not match assigned entry")
					}
					if ep.WorkKey != "" {
						item.WorkKey = ep.WorkKey
					}
					inside = true
					break
				}
			}
			if !inside {
				return "", errors.New("HTTP observation URL is outside assigned entry")
			}
		} else if item.Error == "" {
			return "", errors.New("HTTP observation must include URL or an explicit error")
		}
		return source, nil
	}
	value := item.IP
	if value == "" {
		value = item.Target
	}
	key := canonicalTarget(value)
	if !contains(keys, key) {
		return "", errors.New("observation IP is outside the task targets")
	}
	if item.Port < 1 || item.Port > 65535 {
		return "", errors.New("observation port is outside TCP 1–65535")
	}
	if typeName == "port" {
		var p struct {
			Ports string `json:"ports"`
		}
		if json.Unmarshal(payload, &p) != nil {
			return "", errors.New("invalid port range payload")
		}
		lo, hi, err := parsePortInterval(p.Ports)
		if err != nil || item.Port < lo || item.Port > hi {
			return "", errors.New("observation port is outside the assigned range")
		}
	}
	if typeName == "service" {
		var p struct {
			Endpoints []struct {
				IP      string
				Port    int
				WorkKey string `json:"work_key"`
			} `json:"endpoints"`
		}
		if json.Unmarshal(payload, &p) != nil {
			return "", errors.New("invalid endpoint payload")
		}
		found := false
		for _, ep := range p.Endpoints {
			if canonicalTarget(ep.IP) == key && ep.Port == item.Port {
				if item.WorkKey != "" && ep.WorkKey != "" && item.WorkKey != ep.WorkKey {
					return "", errors.New("service work binding does not match assigned endpoint")
				}
				if ep.WorkKey != "" {
					item.WorkKey = ep.WorkKey
				}
				found = true
				break
			}
		}
		if !found {
			return "", errors.New("service observation is outside assigned endpoints")
		}
	}
	return key, nil
}

func validatePOCObservation(payload []byte, item *Observation) error {
	var assignment struct {
		Endpoint taskEndpoint   `json:"endpoint"`
		Rules    []rulelib.Rule `json:"rules"`
	}
	if json.Unmarshal(payload, &assignment) != nil || len(assignment.Rules) != 1 {
		return errors.New("invalid PoC task payload")
	}
	rule := assignment.Rules[0]
	if item.RuleID != rule.ID || item.RuleRevision != rule.Revision || item.Engine != rule.Engine {
		return errors.New("PoC observation rule identity does not match assigned rule")
	}
	if item.RuleName != rule.Name || item.Severity != rule.Severity {
		return errors.New("PoC observation rule metadata does not match assigned rule")
	}
	item.Purpose = rulelib.VerificationPurpose(rule)
	item.Verification = nil
	if item.Purpose == "verification" {
		item.Verification = rule.Verification
	}
	if item.FindingStatus != "matched" && item.FindingStatus != "not_matched" && item.FindingStatus != "error" && item.FindingStatus != "incomplete" && item.FindingStatus != "unknown" && item.FindingStatus != "skipped" {
		return errors.New("PoC observation finding_status is invalid")
	}
	proofProfile := item.CanProveNoMatch && !item.Truncated && item.Error == "" && item.RequestRaw != "" && item.ResponseRaw != ""
	if item.Engine == "native" {
		proofProfile = proofProfile && item.EvidenceProfile == "native-http-matcher-v1" && len(item.Checks) == len(rule.Definition.Requests)
	} else {
		proofProfile = proofProfile && item.EngineVersion == "3.11.1" && item.EvidenceProfile == "nuclei-3.11.1-single-http-response-v1" && item.ContentSHA256 != ""
	}
	if item.FindingStatus == "not_matched" && !proofProfile {
		item.FindingStatus = "incomplete"
		item.Coverage = "partial"
		item.Outcome = "incomplete"
	}
	base, err := endpointBaseURL(assignment.Endpoint)
	if err != nil {
		return errors.New("invalid assigned PoC endpoint")
	}
	observed, ok := sameOriginURL(base, item.URL)
	if !ok {
		return errors.New("PoC observation URL is outside the assigned origin")
	}
	if observed.RawQuery != "" || observed.Fragment != "" {
		return errors.New("PoC observation URL query or fragment was not assigned")
	}
	allowedPath := observed.EscapedPath() == "" || observed.EscapedPath() == "/"
	if rule.Nuclei != nil && rule.Nuclei.ExecutionProfile == rulelib.NucleiExecutionProfileHTTPBasic {
		if item.TemplateID != rule.Nuclei.TemplateID || item.ExecutionProfile != rule.Nuclei.ExecutionProfile ||
			item.ContentSHA256 != rule.Nuclei.ContentSHA256 {
			return errors.New("original PoC observation template identity does not match assigned rule")
		}
		analysis, err := rulelib.AnalyzeNucleiOriginal([]byte(rule.Template))
		if err != nil || analysis.Plan.TemplateID != rule.Nuclei.TemplateID || analysis.Plan.ContentSHA256 != rule.Nuclei.ContentSHA256 {
			return errors.New("assigned original PoC template is invalid")
		}
		base.Path = strings.TrimRight(base.Path, "/")
		base.RawPath = strings.TrimRight(base.RawPath, "/")
		requests, err := rulelib.ResolveNucleiOriginalRequests(analysis.Plan, base)
		if err != nil {
			return errors.New("assigned original PoC request scope is invalid")
		}
		for _, request := range requests {
			if observed.EscapedPath() == request.Path {
				allowedPath = true
				break
			}
		}
	} else {
		for _, request := range rule.Definition.Requests {
			if observed.EscapedPath() == request.Path {
				allowedPath = true
				break
			}
		}
	}
	if !allowedPath {
		return errors.New("PoC observation URL path was not assigned")
	}
	if item.Purpose == "verification" && item.FindingStatus == "matched" {
		if err := validateVerificationEvidence(rule, assignment.Endpoint, item); err != nil {
			return err
		}
	}
	return nil
}

func validateVerificationEvidence(rule rulelib.Rule, endpoint taskEndpoint, item *Observation) error {
	if rule.Engine != "native" || rule.Verification == nil {
		return errors.New("verification finding requires an assigned native verification rule")
	}
	if item.Truncated || item.Error != "" || item.RequestRaw == "" || item.ResponseRaw == "" || item.Evidence == "" {
		return errors.New("verification finding has incomplete raw evidence")
	}
	if len(item.Checks) != len(rule.Definition.Requests) {
		return errors.New("verification finding checks do not match assigned requests")
	}
	base, err := endpointBaseURL(endpoint)
	if err != nil {
		return errors.New("invalid assigned verification endpoint")
	}
	inputs := make([]rulelib.Input, len(item.Checks))
	for index, check := range item.Checks {
		input, err := parseVerificationCheck(check, rule.Definition.Requests[index], base)
		if err != nil {
			return fmt.Errorf("verification check %d: %w", index+1, err)
		}
		if !rulelib.MatchRequest(rule.Definition.Requests[index], input) {
			return fmt.Errorf("verification check %d does not satisfy its assigned matcher", index+1)
		}
		inputs[index] = input
	}
	if _, matched := rulelib.NativePoCMatch(rule, inputs); !matched {
		return errors.New("verification checks do not satisfy the assigned rule")
	}
	return nil
}

func parseVerificationCheck(check rulelib.CheckEvidence, definition rulelib.Request, base *url.URL) (rulelib.Input, error) {
	if check.RequestRaw == "" || check.ResponseRaw == "" {
		return rulelib.Input{}, errors.New("request_raw and response_raw are required")
	}
	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(check.RequestRaw)))
	if err != nil {
		return rulelib.Input{}, fmt.Errorf("parse request: %w", err)
	}
	defer request.Body.Close()
	if request.Method != definition.Method || request.URL == nil {
		return rulelib.Input{}, errors.New("request method does not match assignment")
	}
	requestBody, err := io.ReadAll(io.LimitReader(request.Body, 1))
	if err != nil || len(requestBody) != 0 {
		return rulelib.Input{}, errors.New("verification request must not contain a body")
	}
	assigned, err := url.ParseRequestURI(definition.Path)
	if err != nil || assigned.IsAbs() || assigned.Host != "" || assigned.User != nil || assigned.Fragment != "" {
		return rulelib.Input{}, errors.New("assigned verification request URI is invalid")
	}
	if request.URL.Fragment != "" || request.URL.EscapedPath() != assigned.EscapedPath() ||
		request.URL.RawQuery != assigned.RawQuery || request.URL.ForceQuery != assigned.ForceQuery {
		return rulelib.Input{}, errors.New("request URL does not match assigned request URI")
	}
	host := request.Host
	if request.URL.IsAbs() {
		if request.URL.Scheme != base.Scheme {
			return rulelib.Input{}, errors.New("request scheme is outside assigned origin")
		}
		host = request.URL.Host
	}
	authority, err := url.Parse(base.Scheme + "://" + host)
	if err != nil || authority.User != nil || origin(authority) != origin(base) {
		return rulelib.Input{}, errors.New("request host is outside assigned origin")
	}
	for name, value := range definition.Headers {
		if request.Header.Get(name) != value {
			return rulelib.Input{}, fmt.Errorf("request header %q does not match assignment", name)
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(check.ResponseRaw)), request)
	if err != nil {
		return rulelib.Input{}, fmt.Errorf("parse response: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rulelib.Input{}, fmt.Errorf("read response: %w", err)
	}
	var headers bytes.Buffer
	if err := response.Header.Write(&headers); err != nil {
		return rulelib.Input{}, fmt.Errorf("read response headers: %w", err)
	}
	return rulelib.Input{Body: string(body), Header: headers.String(), Title: verificationHTMLTitle(body), Status: response.StatusCode}, nil
}

func verificationHTMLTitle(body []byte) string {
	match := verificationTitlePattern.FindSubmatch(body)
	if len(match) != 2 {
		return ""
	}
	return strings.Join(strings.Fields(string(match[1])), " ")
}
