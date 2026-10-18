package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	fingers "github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/common"
	native "github.com/chainreactors/fingers/fingers"
	neutronhttp "github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/utils/encode"
	fb "scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/httpadmission"
	"scanplatform/internal/webevidence"
)

type activeUnit struct {
	independent bool
	id, name    string
	finger      *native.Finger
}

func activeUnits(engine *fingers.Engine) []activeUnit {
	var units []activeUnit
	for i, f := range engine.Fingers().HTTPFingers {
		if f.IsActive {
			units = append(units, activeUnit{id: fb.UnitKey("fingers", fmt.Sprintf("resources/fingers_http.json.gz#/%d", i), f.Name, f.SourceHash), name: f.Name, finger: f, independent: true})
		}
	}
	for _, t := range engine.FingerPrintHub().HTTPTemplates() {
		units = append(units, activeUnit{id: t.ID, name: t.Name, independent: t.Requests == 1})
	}
	return units
}

func executeActive(engine *fingers.Engine, input webevidence.MatchRequest) ([]webevidence.Match, *webevidence.ActiveResult, error) {
	a := input.Active
	out := &webevidence.ActiveResult{}
	if a == nil {
		return nil, out, nil
	}
	if input.ExecutionProfile != webevidence.FullProfile {
		return nil, out, fmt.Errorf("active execution requires %s", webevidence.FullProfile)
	}
	target, err := url.Parse(a.EntryURL)
	if err != nil || target.Host == "" || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") || net.ParseIP(a.ConnectIP) == nil {
		return nil, out, fmt.Errorf("invalid active HTTP target")
	}
	if a.Deadline.IsZero() || a.MaxRequests <= 0 || a.SegmentMaxRequests <= 0 || a.RequestsUsed < 0 {
		return nil, out, fmt.Errorf("active execution requires fixed deadline and request budgets")
	}
	deadline := a.Deadline
	segmentBoundary := !a.SegmentDeadline.IsZero() && a.SegmentDeadline.Before(deadline)
	if segmentBoundary {
		deadline = a.SegmentDeadline
	}
	deadlineReason := "deadline"
	if segmentBoundary {
		deadlineReason = "segment_deadline"
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	units := activeUnits(engine)
	known := map[string]bool{}
	for _, u := range units {
		known[u.id] = true
	}
	done := map[string]bool{}
	for _, id := range a.CompletedRuleIDs {
		if !known[id] {
			return nil, out, fmt.Errorf("unknown completed template %s", id)
		}
		done[id] = true
	}
	selected := map[string]bool{}
	for _, id := range a.RemainingRuleIDs {
		if !known[id] {
			return nil, out, fmt.Errorf("unknown remaining template %s", id)
		}
		selected[id] = true
	}
	pending := make([]activeUnit, 0, len(units))
	for _, u := range units {
		if !done[u.id] && (len(selected) == 0 || selected[u.id]) {
			pending = append(pending, u)
		}
	}
	priority := map[string]bool{}
	for _, p := range a.CandidateProducts {
		priority[strings.ToLower(p)] = true
	}
	sort.SliceStable(pending, func(i, j int) bool {
		return priority[strings.ToLower(pending[i].name)] && !priority[strings.ToLower(pending[j].name)]
	})
	transport, err := newActiveTransport(ctx, input, target)
	if err != nil {
		return nil, out, err
	}
	defer transport.base.CloseIdleConnections()
	var matches []webevidence.Match
	for _, u := range pending {
		if ctx.Err() != nil {
			out.StopReason = deadlineReason
			break
		}
		transport.lastErr = nil
		transport.cacheEnabled = u.independent
		before := transport.used
		var frame *common.Framework
		if u.finger != nil {
			frame, _, _ = u.finger.ActiveMatch(5, transport.sender(target))
		} else {
			frame, err = engine.FingerPrintHub().HTTPTemplateMatch(ctx, u.id, a.EntryURL, transport)
			if err != nil {
				transport.lastErr = err
			}
		}
		status := "not_matched"
		unitErr := ""
		if transport.lastErr != nil {
			status = "failed"
			unitErr = transport.lastErr.Error()
			out.Errors = append(out.Errors, u.id+": "+unitErr)
		} else if frame != nil {
			status = "matched"
		}
		if ctx.Err() != nil || errors.Is(transport.lastErr, errActiveBudget) || errors.Is(transport.lastErr, errActiveEvidenceBudget) {
			status = "partial"
			if ctx.Err() != nil {
				out.StopReason = deadlineReason
			} else if errors.Is(transport.lastErr, errActiveEvidenceBudget) {
				out.StopReason = "evidence_budget"
			} else {
				out.StopReason = "request_budget"
			}
		}
		if status == "not_matched" || status == "matched" {
			done[u.id] = true
			out.CompletedRuleIDs = append(out.CompletedRuleIDs, u.id)
		}
		out.Rules = append(out.Rules, webevidence.RuleExecution{RuleID: u.id, Status: status, Requests: transport.used - before, Error: unitErr})
		if frame != nil {
			frames := engine.MergeFrameworks(make(common.Frameworks), common.Frameworks{frame.Name: frame})
			for _, f := range frames {
				detail, _ := json.Marshal(f)
				name := fingers.FingerPrintEngine
				if u.finger != nil {
					name = fingers.FingersEngine
				}
				version := ""
				if f.Attributes != nil {
					version = f.Version
				}
				matches = append(matches, webevidence.Match{Name: f.Name, Version: version, Engine: name, Evidence: detail})
			}
		}
		if out.StopReason != "" {
			break
		}
	}
	for _, u := range pending {
		if !done[u.id] {
			out.RemainingRuleIDs = append(out.RemainingRuleIDs, u.id)
		}
	}
	out.Requests = transport.used
	out.Responses = transport.responses
	out.Complete = len(out.RemainingRuleIDs) == 0
	if out.StopReason == "" && !out.Complete {
		out.StopReason = "execution_errors"
	}
	return matches, out, nil
}

var errActiveBudget = errors.New("active HTTP request budget exhausted")
var errActiveEvidenceBudget = errors.New("active HTTP segment evidence budget exhausted")

type activeTransport struct {
	ctx           context.Context
	input         webevidence.MatchRequest
	target        *url.URL
	base          *http.Transport
	gate          httpadmission.Transport
	used          int
	lastErr       error
	responses     []webevidence.Response
	requestURL    *url.URL
	cacheEnabled  bool
	cache         map[string]cachedActiveResponse
	cacheBytes    int
	evidenceBytes int
}

func newActiveTransport(ctx context.Context, input webevidence.MatchRequest, target *url.URL) (*activeTransport, error) {
	a := input.Active
	endpoint, err := url.Parse(a.AdmissionURL)
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.User != nil || a.AdmissionToken == "" {
		return nil, fmt.Errorf("active HTTP requires tokenized loopback admission")
	}
	timeout := time.Duration(a.TimeoutMillis) * time.Millisecond
	if timeout <= 0 || timeout > 8*time.Second {
		timeout = 8 * time.Second
	}
	sni := a.SNI
	if sni == "" {
		sni = target.Hostname()
	}
	t := &activeTransport{ctx: ctx, input: input, target: target, cache: map[string]cachedActiveResponse{}}
	t.base = &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: sni}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	t.base.DialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, e
		}
		if !strings.EqualFold(host, target.Hostname()) || port != urlPort(target) {
			return nil, fmt.Errorf("active template left admitted HTTP origin")
		}
		dialCtx, e = httpadmission.BeforeDial(httpadmission.RequestContext(dialCtx), a.ConnectIP, host, port)
		if e != nil {
			return nil, e
		}
		conn, e := (&net.Dialer{}).DialContext(dialCtx, network, net.JoinHostPort(a.ConnectIP, port))
		return httpadmission.AfterDial(dialCtx, conn, e)
	}
	t.gate = httpadmission.Transport{Base: t.base, NetworkTimeout: timeout, Permit: func(ctx context.Context, _, _, _ string, wait bool) (time.Time, error) {
		return t.permit(ctx, endpoint, wait)
	}}
	return t, nil
}
func urlPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
func (t *activeTransport) RoundTrip(request *http.Request) (response *http.Response, err error) {
	defer func() {
		if err != nil {
			t.lastErr = err
		}
	}()
	if t.ctx.Err() != nil {
		return nil, t.ctx.Err()
	}
	a := t.input.Active

	if request.URL.User != nil || !strings.EqualFold(request.URL.Hostname(), t.target.Hostname()) || urlPort(request.URL) != urlPort(t.target) || request.URL.Scheme != t.target.Scheme {
		return nil, fmt.Errorf("active template left admitted HTTP origin")
	}
	request = request.Clone(t.ctx)
	if a.Host != "" {
		request.Host = a.Host
	}

	cacheKey := t.cacheKey(request)
	if cached, ok := t.cache[cacheKey]; cacheKey != "" && ok {
		response := cached.response
		response.Header = cached.response.Header.Clone()
		response.Request = request
		response.Body = io.NopCloser(bytes.NewReader(cached.body))
		return &response, nil
	}
	// Reserve one maximum request/response pair plus result metadata before sending.
	if t.evidenceBytes >= webevidence.MaxMessage/3 {
		return nil, errActiveEvidenceBudget
	}
	if t.used >= a.SegmentMaxRequests || a.RequestsUsed+t.used >= a.MaxRequests {
		return nil, errActiveBudget
	}
	requestRaw, e := httputil.DumpRequestOut(request, true)
	if e != nil {
		return nil, e
	}
	if len(requestRaw) > webevidence.MaxBody {
		return nil, fmt.Errorf("active request evidence exceeds profile")
	}
	t.used++
	t.requestURL = request.URL
	evidence := webevidence.Response{URL: request.URL.String(), ConnectIP: a.ConnectIP, Host: request.Host, ObservedAt: time.Now().UTC(), RequestRaw: string(requestRaw), Completeness: "failed"}
	response, err = t.gate.RoundTrip(request)
	if err != nil {
		evidence.Error = err.Error()
		t.responses = append(t.responses, evidence)
		return nil, err
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, webevidence.MaxBody+1))
	response.Body.Close()
	if e != nil {
		return nil, e
	}
	if len(body) > webevidence.MaxBody {
		return nil, fmt.Errorf("active response evidence exceeds profile")
	}
	decoded, decodeErr := neutronhttp.DecodeBoundedResponseBody(body, response.Header.Get("Content-Encoding"), webevidence.MaxBody)
	if decodeErr != nil {
		return nil, decodeErr
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	header, _ := httputil.DumpResponse(response, false)
	evidence.StatusCode = response.StatusCode
	evidence.Proto = response.Proto
	evidence.Headers = response.Header.Clone()
	evidence.HeaderRaw = string(header)
	evidence.Body = decoded
	evidence.BodySHA256 = webevidence.SHA256(decoded)
	evidence.DecodedBytes = len(decoded)
	evidence.EncodedBytes = int64(len(body))
	evidence.Completeness = "full"

	t.responses = append(t.responses, evidence)
	encodedEvidence, _ := json.Marshal(evidence)
	t.evidenceBytes += len(encodedEvidence)
	if cacheKey != "" && response.Header.Get("Set-Cookie") == "" && !strings.Contains(strings.ToLower(response.Header.Get("Cache-Control")), "no-store") && !strings.Contains(strings.ToLower(response.Header.Get("Cache-Control")), "private") && t.cacheBytes+len(body) <= webevidence.MaxMessage {
		copyResponse := *response
		copyResponse.Body = nil
		copyResponse.Header = response.Header.Clone()
		t.cache[cacheKey] = cachedActiveResponse{response: copyResponse, body: append([]byte(nil), body...)}
		t.cacheBytes += len(body)
	}
	return response, nil
}
func (t *activeTransport) permit(ctx context.Context, endpoint *url.URL, wait bool) (time.Time, error) {
	payload, _ := json.Marshal(map[string]any{"id": t.input.ID, "url": t.requestURL.String(), "request_seq": t.used, "wait": wait})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return time.Time{}, err
	}
	request.Header.Set("Authorization", "Bearer "+t.input.Active.AdmissionToken)
	base := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer base.CloseIdleConnections()
	client := &http.Client{Transport: base, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sent := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return time.Time{}, err
	}
	defer response.Body.Close()
	if !wait && response.StatusCode == http.StatusTooManyRequests {
		return time.Time{}, httpadmission.ErrPending
	}
	if response.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("active HTTP admission returned %s", response.Status)
	}
	var permission struct {
		ValidForMS int64 `json:"valid_for_ms"`
		WaitedMS   int64 `json:"waited_ms"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&permission) != nil || permission.ValidForMS <= 0 || permission.ValidForMS > 1000 || permission.WaitedMS < 0 || permission.WaitedMS > 90000 {
		return time.Time{}, fmt.Errorf("invalid active HTTP admission permit")
	}
	elapsed := time.Since(sent)
	waited := time.Duration(permission.WaitedMS) * time.Millisecond
	overhead := max(time.Duration(0), elapsed-waited)
	if waited > elapsed || overhead >= time.Duration(permission.ValidForMS)*time.Millisecond {
		return time.Time{}, fmt.Errorf("active HTTP admission permit expired")
	}
	return time.Now().Add(time.Duration(permission.ValidForMS)*time.Millisecond - overhead), nil
}
func (t *activeTransport) sender(base *url.URL) native.Sender {
	return func(payload []byte) ([]byte, bool) {
		var request *http.Request
		var err error
		if bytes.Contains(payload, []byte(" HTTP/")) {
			request, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
			if err == nil {
				request.RequestURI = ""
				request.URL.Scheme = base.Scheme
				request.URL.Host = base.Host
			}
		} else {
			var ref *url.URL
			ref, err = url.Parse(string(payload))
			if err == nil {
				request, err = http.NewRequest(http.MethodGet, base.ResolveReference(ref).String(), nil)
			}
		}
		if err != nil {
			t.lastErr = err
			return nil, false
		}
		response, err := t.RoundTrip(request)
		if err != nil {
			return nil, false
		}
		defer response.Body.Close()
		raw, err := httputil.DumpResponse(response, true)
		if err != nil {
			t.lastErr = err
			return nil, false
		}
		return raw, true
	}
}

// Associated icon evidence belongs to the page matcher event, never its body.
func (t *activeTransport) FaviconHashEvidence() string {
	var hashes []string
	for _, icon := range t.input.Icons {
		if icon.Completeness == "full" && icon.StatusCode >= 200 && icon.StatusCode < 300 && icon.BodyStorage != "hash_only" && (icon.BodySHA256 == "" || icon.BodySHA256 == webevidence.SHA256(icon.Body)) {
			hashes = append(hashes, encode.Mmh3Hash32(icon.Body), encode.Md5Hash(icon.Body))
		}
	}
	return strings.Join(hashes, " ")
}

type cachedActiveResponse struct {
	response http.Response
	body     []byte
}

func (t *activeTransport) cacheKey(r *http.Request) string {
	if !t.cacheEnabled || (r.Method != http.MethodGet && r.Method != http.MethodHead) || (r.Body != nil && r.Body != http.NoBody) || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
		return ""
	}
	// JSON map keys are sorted. Include every identity dimension even though an
	// independent unauthenticated GET has no body/cookie/session state.
	data, _ := json.Marshal(struct {
		Method, URL, ConnectIP, Host, SNI, Session string
		Headers                                    http.Header
		Body                                       string
	}{r.Method, r.URL.String(), t.input.Active.ConnectIP, r.Host, t.base.TLSClientConfig.ServerName, t.input.Identity.EntryID, r.Header, ""})
	return webevidence.SHA256(data)
}
