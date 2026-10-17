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
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanplatform/internal/rulelib"
)

const (
	maxHTTPBody    = 1 << 20
	maxRawRequest  = 64 << 10
	maxRawResponse = 192 << 10
	maxBodyExcerpt = 32 << 10
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type httpPayload struct {
	Endpoints      []Endpoint     `json:"endpoints"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Rules          []rulelib.Rule `json:"rules"`
	RulesRef       string         `json:"rules_ref,omitempty"`
}

type targetSlots struct {
	semaphore chan struct{}
	users     int
}

func (a *Agent) runHTTP(ctx context.Context, task Task, emit func(Observation) error) error {
	var payload httpPayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return &TaskError{Reason: "invalid http payload: " + err.Error()}
	}
	if len(payload.Endpoints) == 0 {
		return &TaskError{Reason: "http task has no endpoints"}
	}
	rules, err := a.resolveTaskRules(ctx, task, payload.RulesRef, payload.Rules, "http")
	if err != nil {
		return err
	}
	payload.Rules = rules
	timeout := minDuration(boundedTimeout(payload.TimeoutSeconds, 12*time.Second), 12*time.Second)
	return runEndpointsWithLimit(ctx, payload.Endpoints, a.endpointSlots, 2, func(ctx context.Context, ep Endpoint) Observation {
		release, err := a.acquireHTTPTarget(ctx, httpTargetKey(ep))
		if err != nil {
			return Observation{Kind: "http", Target: endpointTarget(ep), Error: context.Cause(ctx).Error()}
		}
		defer release()
		obs := a.fetchHTTP(ctx, ep, timeout)
		if payload.Rules != nil && obs.StatusCode > 0 {
			obs.Technologies = matchHTTPRules(payload.Rules, obs)
		}
		obs.httpBody, obs.httpHeader = "", ""
		return obs
	}, emit)
}

func validateTaskRules(rules []rulelib.Rule, kind string) error {
	for i, rule := range rules {
		if rule.Kind != kind || rule.Engine != "native" {
			return fmt.Errorf("rule %d must be a native %s rule", i+1, kind)
		}
		if err := rulelib.Validate(rule); err != nil {
			return fmt.Errorf("rule %q: %w", rule.ID, err)
		}
	}
	return nil
}

func matchHTTPRules(rules []rulelib.Rule, obs Observation) []Technology {
	if obs.StatusCode == 0 {
		return nil
	}
	input := rulelib.Input{Body: obs.httpBody, Header: obs.httpHeader, Title: obs.Title, Status: obs.StatusCode}
	technologies := make([]Technology, 0, len(rules))
	seen := make(map[string]int)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		incompleteNegative := false
		if obs.Truncated || obs.Error != "" {
			for _, matcher := range rule.Definition.Matchers {
				if matcher.Negative && (matcher.Part == "body" || matcher.Part == "title") {
					incompleteNegative = true
				}
			}
		}
		if incompleteNegative {
			continue
		}
		match, ok := rulelib.Match(rule, input)
		if !ok {
			continue
		}
		name := match.Product
		if name == "" {
			name = match.Service
		}
		if name == "" {
			name = rule.Name
		}
		technology := Technology{
			Name: name, Version: match.Version, Evidence: match.Evidence,
			RuleID: rule.ID, RuleRevision: rule.Revision,
		}
		key := strings.ToLower(name)
		if index, exists := seen[key]; exists {
			if technologies[index].Version == "" && technology.Version != "" {
				technologies[index] = technology
			}
		} else {
			seen[key] = len(technologies)
			technologies = append(technologies, technology)
		}
	}
	return technologies
}

func (a *Agent) acquireHTTPTarget(ctx context.Context, key string) (func(), error) {
	a.httpTargetMu.Lock()
	limit := a.httpTargetSlots[key]
	if limit == nil {
		limit = &targetSlots{semaphore: make(chan struct{}, 2)}
		a.httpTargetSlots[key] = limit
	}
	limit.users++
	a.httpTargetMu.Unlock()
	select {
	case limit.semaphore <- struct{}{}:
		return func() {
			<-limit.semaphore
			a.httpTargetMu.Lock()
			limit.users--
			if limit.users == 0 {
				delete(a.httpTargetSlots, key)
			}
			a.httpTargetMu.Unlock()
		}, nil
	case <-ctx.Done():
		a.httpTargetMu.Lock()
		limit.users--
		if limit.users == 0 {
			delete(a.httpTargetSlots, key)
		}
		a.httpTargetMu.Unlock()
		return nil, context.Cause(ctx)
	}
}

func (a *Agent) fetchHTTP(ctx context.Context, ep Endpoint, timeout time.Duration) Observation {
	endpointCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	firstTimeout := timeout
	if ep.URL == "" && timeout > time.Nanosecond {
		firstTimeout = timeout / 2
	}
	obs := a.fetchHTTPOnce(endpointCtx, ep, firstTimeout)
	if ep.URL != "" || obs.Error == "" || obs.StatusCode != 0 {
		return obs
	}
	firstError := obs.Error
	alternate := ep
	scheme := "https"
	if strings.HasPrefix(obs.URL, "https://") {
		scheme = "http"
	}
	alternate.URL, _ = endpointURLWithScheme(ep, scheme)
	alt := a.fetchHTTPOnce(endpointCtx, alternate, timeout)
	if alt.Error == "" || alt.StatusCode != 0 {
		return alt
	}
	obs.Error = firstError + "; alternate protocol: " + alt.Error
	return obs
}

func (a *Agent) fetchHTTPOnce(ctx context.Context, ep Endpoint, timeout time.Duration) Observation {
	targetURL, err := endpointURL(ep)
	obs := Observation{Kind: "http", Target: endpointTarget(ep)}
	if err != nil {
		obs.Error = err.Error()
		return obs
	}
	u, err := url.Parse(targetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		obs.Error = "invalid HTTP endpoint URL"
		return obs
	}
	setObservationURL(&obs, u)

	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var remoteMu sync.Mutex
	remoteIP := ""
	requestCtx = httptrace.WithClientTrace(requestCtx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if host := remoteHost(info.Conn.RemoteAddr()); host != "" {
			remoteMu.Lock()
			remoteIP = host
			remoteMu.Unlock()
		}
	}})
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		obs.Error = err.Error()
		return obs
	}
	req.Header.Set("User-Agent", "scanplatform-agent/1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "identity")

	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            a.safeDialer(ep.IP, u.Hostname()),
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, // scanner records self-signed and legacy endpoints
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  minDuration(timeout, 20*time.Second),
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 32 << 10,
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		_, err := a.httpDialHost(next.Context(), next.URL.Hostname(), urlPort(next.URL), ep.IP, u.Hostname())
		return err
	}
	resp, err := client.Do(req)
	remoteMu.Lock()
	obs.IP = remoteIP
	remoteMu.Unlock()
	if err != nil {
		reqRaw := rawHTTPRequest(req)
		obs.RequestRaw, obs.Truncated = truncateBytes(reqRaw, maxRawRequest)
		obs.Error = err.Error()
		return obs
	}
	defer resp.Body.Close()
	setObservationURL(&obs, resp.Request.URL)
	reqRaw := rawHTTPRequest(resp.Request)
	var reqTruncated bool
	obs.RequestRaw, reqTruncated = truncateBytes(reqRaw, maxRawRequest)
	obs.Truncated = reqTruncated
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody+1))
	if len(body) > maxHTTPBody {
		body = body[:maxHTTPBody]
		obs.Truncated = true
	}
	if readErr != nil {
		obs.Error = readErr.Error()
	}
	respRaw := rawHTTPResponse(resp, body)
	obs.ResponseRaw, reqTruncated = truncateBytes(respRaw, maxRawResponse)
	obs.Truncated = obs.Truncated || reqTruncated
	obs.StatusCode = resp.StatusCode
	obs.Headers = resp.Header.Clone()
	var header bytes.Buffer
	_ = resp.Header.Write(&header)
	obs.httpBody, obs.httpHeader = string(body), header.String()
	obs.Server = resp.Header.Get("Server")
	obs.BodyExcerpt, _ = truncateBytes(body, maxBodyExcerpt)
	obs.Title = htmlTitle(body)
	obs.Technologies = detectTechnologies(resp.Header, body)
	return obs
}

func (a *Agent) safeDialer(fixedIP string, fixedHost ...string) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
	boundHost := ""
	if len(fixedHost) > 0 {
		boundHost = fixedHost[0]
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		dialHost, err := a.httpDialHost(ctx, host, port, fixedIP, boundHost)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(dialHost, port))
	}
}

func (a *Agent) httpDialHost(ctx context.Context, host, port, fixedIP, fixedHost string) (string, error) {
	if err := a.policy.validateEndpoint(ctx, host, port); err != nil {
		return "", err
	}
	if fixedIP != "" && (fixedHost == "" || equalHost(host, fixedHost)) {
		if err := a.policy.validateEndpoint(ctx, fixedIP, port); err != nil {
			return "", err
		}
		if _, err := a.policy.resolve(ctx, fixedIP); err != nil {
			return "", err
		}
		return fixedIP, nil
	}
	ips, err := a.policy.resolve(ctx, host)
	if err != nil {
		return "", err
	}
	return ips[0].String(), nil
}

func equalHost(left, right string) bool {
	return strings.EqualFold(strings.TrimSuffix(left, "."), strings.TrimSuffix(right, "."))
}

func urlPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func setObservationURL(obs *Observation, u *url.URL) {
	obs.URL, obs.Protocol = u.String(), u.Scheme
	obs.Port, _ = strconv.Atoi(urlPort(u))
}

func remoteHost(address net.Addr) string {
	if address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(address.String(), "[]")
}

func rawHTTPRequest(req *http.Request) []byte {
	copy := req.Clone(context.Background())
	data, _ := httputil.DumpRequestOut(copy, true)
	return data
}

func httpTargetKey(ep Endpoint) string {
	if ep.Host != "" {
		return strings.ToLower(ep.Host)
	}
	if ep.URL != "" {
		if u, err := url.Parse(ep.URL); err == nil {
			return strings.ToLower(u.Hostname())
		}
	}
	return ep.IP
}

func endpointURL(ep Endpoint) (string, error) {
	if ep.URL != "" {
		return ep.URL, nil
	}
	scheme := "http"
	if ep.Port == 443 || ep.Port == 8443 || ep.Port == 9443 {
		scheme = "https"
	}
	return endpointURLWithScheme(ep, scheme)
}

func endpointURLWithScheme(ep Endpoint, scheme string) (string, error) {
	host := ep.Host
	if host == "" {
		host = ep.IP
	}
	if host == "" {
		return "", fmt.Errorf("endpoint has no host")
	}
	if ep.Port != 0 {
		host = net.JoinHostPort(host, strconv.Itoa(ep.Port))
	}
	return scheme + "://" + host + "/", nil
}

func endpointTarget(ep Endpoint) string {
	if ep.URL != "" {
		return ep.URL
	}
	if ep.Host != "" {
		return ep.Host
	}
	return ep.IP
}

func htmlTitle(body []byte) string {
	m := titlePattern.FindSubmatch(body)
	if len(m) != 2 {
		return ""
	}
	return strings.Join(strings.Fields(string(m[1])), " ")
}

func rawHTTPResponse(resp *http.Response, body []byte) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	_ = resp.Header.Write(&out)
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes()
}

func truncateBytes(in []byte, limit int) (string, bool) {
	if len(in) <= limit {
		return string(in), false
	}
	return string(in[:limit]), true
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func runEndpointsWithLimit(ctx context.Context, endpoints []Endpoint, slots chan struct{}, limit int, run func(context.Context, Endpoint) Observation, emit func(Observation) error) error {
	concurrency := cap(slots)
	if limit > 0 && limit < concurrency {
		concurrency = limit
	}
	if concurrency < 1 {
		concurrency = 1
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan Endpoint)
	results := make(chan Observation)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				select {
				case slots <- struct{}{}:
				case <-ctx.Done():
					return
				}
				obs := run(ctx, ep)
				<-slots
				select {
				case results <- obs:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(results)
		defer wg.Wait()
		for _, ep := range endpoints {
			select {
			case jobs <- ep:
			case <-ctx.Done():
				close(jobs)
				return
			}
		}
		close(jobs)
	}()
	for obs := range results {
		if err := emit(obs); err != nil {
			cancel()
			return err
		}
	}
	return ctx.Err()
}

func boundedTimeout(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	d := time.Duration(seconds) * time.Second
	if d > 10*time.Minute {
		return 10 * time.Minute
	}
	return d
}
