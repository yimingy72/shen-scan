package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"scanplatform/internal/rulelib"
)

const (
	maxNativePoCExecution = 60 * time.Second
	maxNucleiPoCExecution = 90 * time.Second
)

type pocPayload struct {
	Endpoint Endpoint       `json:"endpoint"`
	Rules    []rulelib.Rule `json:"rules"`
}

func (a *Agent) runPoC(ctx context.Context, task Task, emit func(Observation) error) error {
	var payload pocPayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return &TaskError{Reason: "invalid poc payload: " + err.Error(), Retryable: false}
	}
	if len(payload.Rules) != 1 {
		return &TaskError{Reason: "poc task must contain exactly one rule", Retryable: false}
	}
	rule := payload.Rules[0]
	if rule.Kind != "poc" || !rule.Enabled {
		return &TaskError{Reason: "poc task rule must be an enabled poc rule", Retryable: false}
	}
	if err := rulelib.Validate(rule); err != nil {
		return &TaskError{Reason: "invalid poc rule: " + err.Error(), Retryable: false}
	}
	base, err := pocBaseURL(payload.Endpoint)
	if err != nil {
		return &TaskError{Reason: "invalid poc endpoint: " + err.Error(), Retryable: false}
	}
	obs := newPoCObservation(payload.Endpoint, base, rule)
	if rule.Engine == "native" {
		pocCtx, cancel := context.WithTimeout(ctx, maxNativePoCExecution)
		obs = a.runNativePoC(pocCtx, payload.Endpoint, base, rule, obs)
		cancel()
	} else {
		pocCtx, cancel := context.WithTimeout(ctx, maxNucleiPoCExecution)
		obs = a.runNucleiPoC(pocCtx, payload.Endpoint, base, rule, obs)
		cancel()
	}
	return emit(obs)
}

func pocBaseURL(ep Endpoint) (*url.URL, error) {
	raw, err := endpointURL(ep)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("endpoint must be an HTTP(S) URL without userinfo")
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "", "", "", ""
	u.Host = canonicalURLHost(u)
	return u, nil
}

func canonicalURLHost(u *url.URL) string {
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := urlPort(u)
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

func newPoCObservation(ep Endpoint, base *url.URL, rule rulelib.Rule) Observation {
	port, _ := strconv.Atoi(urlPort(base))
	return Observation{
		Kind: "poc", Target: endpointTarget(ep), IP: ep.IP, Port: port, Protocol: base.Scheme, URL: base.String(),
		RuleID: rule.ID, RuleName: rule.Name, RuleRevision: rule.Revision,
		Engine: rule.Engine, Severity: rule.Severity,
	}
}

func (a *Agent) runNativePoC(ctx context.Context, ep Endpoint, base *url.URL, rule rulelib.Rule, obs Observation) Observation {
	inputs := make([]rulelib.Input, 0, len(rule.Definition.Requests))
	var requests, responses bytes.Buffer
	for _, definition := range rule.Definition.Requests {
		input, requestRaw, responseRaw, truncated, err := a.nativePoCRequest(ctx, ep, base, definition)
		appendBounded(&requests, requestRaw, maxRawRequest)
		appendBounded(&responses, responseRaw, maxRawResponse)
		obs.Truncated = obs.Truncated || truncated || requests.Len() >= maxRawRequest || responses.Len() >= maxRawResponse
		if err != nil {
			obs.FindingStatus, obs.Error = "error", err.Error()
			obs.Evidence = fmt.Sprintf("%s %s did not produce a complete response", definition.Method, definition.Path)
			obs.RequestRaw, obs.ResponseRaw = requests.String(), responses.String()
			return obs
		}
		inputs = append(inputs, input)
	}
	obs.RequestRaw, obs.ResponseRaw = requests.String(), responses.String()
	match, ok := rulelib.NativePoCMatch(rule, inputs)
	if ok {
		obs.FindingStatus, obs.Evidence = "matched", match.Evidence
		obs.Service, obs.Product, obs.Version = match.Service, match.Product, match.Version
	} else {
		obs.FindingStatus = "not_matched"
		obs.Evidence = fmt.Sprintf("completed %d read-only request(s); matchers did not match", len(inputs))
	}
	return obs
}

func (a *Agent) nativePoCRequest(ctx context.Context, ep Endpoint, base *url.URL, definition rulelib.Request) (rulelib.Input, string, string, bool, error) {
	requestURL := *base
	requestURL.Path = definition.Path
	requestCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, definition.Method, requestURL.String(), nil)
	if err != nil {
		return rulelib.Input{}, "", "", false, err
	}
	req.Header.Set("User-Agent", "scanplatform-agent/1")
	req.Header.Set("Accept-Encoding", "identity")
	for name, value := range definition.Headers {
		req.Header.Set(name, value)
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: a.safeDialer(ep.IP, base.Hostname()),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
		DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	requestRaw := string(rawHTTPRequest(req))
	resp, err := client.Do(req)
	if err != nil {
		return rulelib.Input{}, requestRaw, "", false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody+1))
	truncated := len(body) > maxHTTPBody
	if truncated {
		body = body[:maxHTTPBody]
	}
	responseRaw := string(rawHTTPResponse(resp, body))
	if truncated {
		return rulelib.Input{}, requestRaw, responseRaw, true, fmt.Errorf("response exceeded %d-byte read limit", maxHTTPBody)
	}
	if err != nil {
		return rulelib.Input{}, requestRaw, responseRaw, truncated, err
	}
	var headers bytes.Buffer
	_ = resp.Header.Write(&headers)
	return rulelib.Input{Body: string(body), Header: headers.String(), Title: htmlTitle(body), Status: resp.StatusCode}, requestRaw, responseRaw, truncated, nil
}

func appendBounded(dst *bytes.Buffer, value string, limit int) {
	if value == "" || dst.Len() >= limit {
		return
	}
	if dst.Len() > 0 {
		separator := "\n\n"
		remaining := limit - dst.Len()
		if remaining < len(separator) {
			dst.WriteString(separator[:remaining])
			return
		}
		dst.WriteString(separator)
	}
	remaining := limit - dst.Len()
	if len(value) > remaining {
		value = value[:remaining]
	}
	dst.WriteString(value)
}
