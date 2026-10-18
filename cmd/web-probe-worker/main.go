// web-probe-worker preserves legacy bounded profiles and runs the official
// httpx enumeration workflow for web-full-v2 through a per-request admission gate.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
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
	"os"
	"sort"
	"strings"
	"time"

	hx "github.com/projectdiscovery/httpx/common/httpx"
	wapp "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"
	"scanplatform/internal/httpadmission"
	"scanplatform/internal/webevidence"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--browser-worker" {
		if err := serveBrowser(os.Stdin, os.Stdout); err != nil {
			fatal(err)
		}
		return
	}

	if len(os.Args) == 2 && os.Args[1] == "--capabilities" {
		json.NewEncoder(os.Stdout).Encode(webProbeCapabilities(context.Background()))
		return
	}
	if err := serve(os.Stdin, os.Stdout); err != nil {
		fatal(err)
	}
}

// A malformed frame ends this process. The Agent kills and waits on any failed
// item before dispatching another, so a late reply cannot belong to a new item.
func serve(input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), 36<<20)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		var request webevidence.ProbeRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			return err
		}
		result, err := probe(context.Background(), request)
		if err != nil {
			result.Error = err.Error()
		}
		if err := encoder.Encode(result); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

const maxRedirectLocation = 4096

func probe(ctx context.Context, input webevidence.ProbeRequest) (webevidence.ProbeResult, error) {
	if input.ExecutionProfile == webevidence.FullProfile || input.Profile == webevidence.FullProfile || input.EnrichmentProfile == webevidence.FullProfile {
		return probeFull(ctx, input)
	}
	result := webevidence.ProbeResult{ID: input.ID, Protocol: webevidence.Protocol, Profile: webevidence.Profile, EnrichmentProfile: input.EnrichmentProfile, InputURL: input.URL, Engine: "httpx-sdk-v1.12.0/bounded-transport+wappalyzergo-v0.2.96"}
	target, err := url.Parse(input.URL)
	if err != nil || target.Hostname() == "" || target.User != nil || target.Fragment != "" || (target.Scheme != "http" && target.Scheme != "https") || net.ParseIP(input.ConnectIP) == nil {
		return result, errors.New("invalid fixed HTTP target")
	}
	if input.Protocol != webevidence.Protocol {
		return result, errors.New("unsupported IPC protocol")
	}
	enriched := input.EnrichmentProfile != ""
	if enriched && input.EnrichmentProfile != webevidence.EnrichmentProfile {
		return result, errors.New("unsupported enrichment profile")
	}
	if input.Step != "" && input.Step != "entry" && input.Step != "supplement" {
		return result, errors.New("unsupported probe step")
	}
	supplement := input.Step == "supplement"
	if supplement && !enriched {
		return result, errors.New("supplement requires enrichment profile")
	}
	budget := 8
	if enriched {
		if len(input.URL) > maxRedirectLocation || len(target.String()) > maxRedirectLocation {
			return result, errors.New("entry URL exceeds enrichment limit")
		}
		if input.MaxRequests < 0 || input.MaxRequests > 8 {
			return result, errors.New("invalid enrichment request budget")
		}
		if input.MaxRequests > 0 {
			budget = input.MaxRequests
		}
		if supplement {
			if input.MaxRequests > 1 {
				return result, errors.New("supplement request budget must be 1")
			}
			budget = 1
		}
	}
	if len(input.CFF) > 32<<20 {
		return result, errors.New("fingerprint snapshot exceeds limit")
	}
	if input.CFFSHA256 != "" && webevidence.SHA256(input.CFF) != input.CFFSHA256 {
		return result, errors.New("fingerprint snapshot digest mismatch")
	}
	result.CFFSHA256 = webevidence.SHA256(input.CFF)
	timeout := time.Duration(input.TimeoutMillis) * time.Millisecond
	if timeout <= 0 || timeout > 8*time.Second {
		timeout = 8 * time.Second
	}
	entryTimeout := time.Duration(input.EntryTimeoutMillis) * time.Millisecond
	if entryTimeout <= 0 || entryTimeout > 90*time.Second {
		entryTimeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, entryTimeout)
	defer cancel()
	// Count actual collect calls, including failed attempts; never count a skipped plan.
	fetch := func(u *url.URL, limit int, icon bool) (webevidence.Response, bool) {
		response := webevidence.Response{URL: u.String(), Host: u.Host, ConnectIP: input.ConnectIP, Completeness: "missing"}
		if ctx.Err() != nil {
			response.Error = context.Cause(ctx).Error()
			return response, false
		}
		if result.Requests >= budget {
			response.Error = "request budget exhausted"
			return response, false
		}
		result.Requests++
		sequence := result.Requests
		response = collect(ctx, u, input.ConnectIP, timeout, limit, func(ctx context.Context, ip, host, port string, wait bool) (time.Time, error) {
			return localHTTPPermit(ctx, input, u, wait, sequence)
		})
		if enriched || !icon {
			result.Attempts = append(result.Attempts, metadata(response))
		}
		return response, true
	}
	result.Response, _ = fetch(target, webevidence.MaxBody, false)
	if supplement {
		return result, nil
	}
	if result.Response.StatusCode == 0 && input.AlternateScheme && ctx.Err() == nil && result.Requests < budget {
		alternate := *target
		if alternate.Port() == "" {
			alternate.Host = net.JoinHostPort(target.Hostname(), portOf(target))
		}
		if alternate.Scheme == "http" {
			alternate.Scheme = "https"
		} else {
			alternate.Scheme = "http"
		}
		result.Response, _ = fetch(&alternate, webevidence.MaxBody, false)
		target = &alternate
	}
	if enriched && result.Response.StatusCode > 0 {
		visited := map[string]bool{redirectIdentity(target): true}
		followed := 0
		for redirectStatus(result.Response.StatusCode) {
			source := result.Response
			step := webevidence.RedirectStep{FromURL: source.URL, StatusCode: source.StatusCode, AttemptIndex: len(result.Attempts) - 1}
			next, outcome := redirectDestination(target, source.Headers.Get("Location"))
			step.Outcome = outcome
			if next != nil {
				step.ToURL = next.String()
			}
			if step.Outcome == "" {
				switch {
				case ctx.Err() != nil:
					step.Outcome = "canceled"
				case visited[redirectIdentity(next)]:
					step.Outcome = "loop"
				case followed >= 3:
					step.Outcome = "hop_limit"
				case result.Requests >= budget:
					step.Outcome = "skipped_budget"
				default:
					response, attempted := fetch(next, webevidence.MaxBody, false)
					if !attempted {
						if ctx.Err() != nil {
							step.Outcome = "canceled"
						} else {
							step.Outcome = "skipped_budget"
						}
					} else if response.StatusCode == 0 {
						if ctx.Err() != nil {
							step.Outcome = "canceled"
						} else {
							step.Outcome = "fetch_failed"
						}
					} else {
						step.Outcome = "followed"
						result.Response = response
						target = next
						visited[redirectIdentity(next)] = true
						followed++
					}
				}
			}
			result.Redirects = append(result.Redirects, step)
			if step.Outcome != "followed" {
				break
			}
		}
	}
	if result.Response.StatusCode > 0 {
		result.Title = hx.ExtractTitle(&hx.Response{Data: result.Response.Body, Raw: result.Response.HeaderRaw + string(result.Response.Body)})
		// Match only the final complete primary response, never splice different pages.
		if result.Response.Completeness == "full" && len(input.CFF) > 0 {
			matcher, err := cachedMatcher(input.CFF, result.CFFSHA256)
			if err != nil {
				return result, err
			}
			for name := range matcher.Fingerprint(result.Response.Headers, result.Response.Body) {
				result.Technologies = append(result.Technologies, name)
			}
			sort.Strings(result.Technologies)
		}
		for _, icon := range iconURLs(target, result.Response.Body) {
			if ctx.Err() != nil || result.Requests >= budget {
				break
			}
			if response, attempted := fetch(icon, webevidence.MaxIcon, true); attempted {
				result.Icons = append(result.Icons, response)
			}
		}
	}
	return result, nil
}
func redirectStatus(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}
func redirectIdentity(value *url.URL) string {
	path := value.EscapedPath()
	if path == "" {
		path = "/"
	}
	if value.RawQuery != "" || value.ForceQuery {
		path += "?" + value.RawQuery
	}
	return value.Scheme + "://" + net.JoinHostPort(strings.ToLower(value.Hostname()), portOf(value)) + path
}
func redirectDestination(base *url.URL, location string) (*url.URL, string) {
	if len(location) > maxRedirectLocation {
		return nil, "location_too_long"
	}
	location = strings.TrimSpace(location)
	if location == "" {
		return nil, "missing_location"
	}
	reference, err := url.Parse(location)
	if err != nil {
		return nil, "invalid_location"
	}
	next := base.ResolveReference(reference)
	next.Scheme = strings.ToLower(next.Scheme)
	next.Fragment, next.RawFragment = "", ""
	if next.User != nil || next.Opaque != "" || next.Hostname() == "" || (next.Scheme != "http" && next.Scheme != "https") {
		return nil, "invalid_location"
	}
	if len(next.String()) > maxRedirectLocation {
		return nil, "location_too_long"
	}
	if next.Scheme != base.Scheme || !strings.EqualFold(next.Hostname(), base.Hostname()) || portOf(next) != portOf(base) {
		return next, "blocked_cross_origin"
	}
	return next, ""
}

func metadata(response webevidence.Response) webevidence.Response {
	response.Body = nil
	return response
}

func collect(ctx context.Context, target *url.URL, ip string, timeout time.Duration, limit int, permits ...httpadmission.Permit) webevidence.Response {
	result := webevidence.Response{URL: target.String(), Host: target.Host, ConnectIP: ip, ObservedAt: time.Now().UTC(), Completeness: "missing"}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	sdk := &hx.HTTPX{Options: &hx.Options{DefaultUserAgent: "shen-scan/2"}}

	request, err := sdk.NewRequestWithContext(ctx, http.MethodGet, target.String())
	if err != nil {
		result.Error = err.Error()
		return result
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	request.Header.Set("Accept-Encoding", "identity")
	raw, _ := httputil.DumpRequestOut(request.Request.Clone(context.Background()), false)
	result.RequestRaw = string(raw)
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: target.Hostname(), MinVersion: tls.VersionTLS10},
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx = httpadmission.RequestContext(ctx)
			host, port, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(host, target.Hostname()) || port != portOf(target) {
				return nil, errors.New("dial outside fixed entry")
			}
			ctx, err = httpadmission.BeforeDial(ctx, ip, host, port)
			if err != nil {
				return nil, err
			}
			conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort(ip, port))
			return httpadmission.AfterDial(ctx, conn, err)
		},
	}
	defer transport.CloseIdleConnections()
	permit := httpadmission.Permit(func(context.Context, string, string, string, bool) (time.Time, error) {
		return time.Now().Add(500 * time.Millisecond), nil
	})
	if len(permits) > 0 {
		permit = permits[0]
	}
	// RoundTrip never parses/follows Location. Even a malformed Location must
	// preserve the received 3xx response for the explicit redirect trace.
	gate := httpadmission.Transport{Base: transport, NetworkTimeout: timeout, Permit: permit}
	response, err := gate.RoundTrip(request.Request)

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	result.Headers = response.Header.Clone()
	result.Proto = response.Proto
	headers, _ := httputil.DumpResponse(response, false)
	result.HeaderRaw = string(headers)
	if response.TLS != nil {
		result.TLS = &webevidence.TLS{Source: "same_http_connection", ServerName: response.TLS.ServerName, Version: response.TLS.Version}
		certBytes := 0
		for _, cert := range response.TLS.PeerCertificates {
			certBytes += len(cert.Raw)
			if certBytes > 128<<10 {
				break
			}
			result.TLS.PeerCertificates = append(result.TLS.PeerCertificates, cert.Raw)
		}
	}
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	result.EncodedBytes = int64(len(encoded))
	result.Completeness = "full"
	if len(encoded) > limit {
		encoded = encoded[:limit]
		result.Completeness = "partial"
	}
	if readErr != nil {
		result.Error = readErr.Error()
		result.Completeness = "partial"
	}
	body, decodeErr := decodeBody(encoded, response.Header.Get("Content-Encoding"), limit)
	if len(body) > limit {
		body = body[:limit]
		result.Completeness = "partial"
	}
	if decodeErr != nil {
		result.Error = decodeErr.Error()
		result.Completeness = "partial"
	}
	result.Body = body
	result.DecodedBytes = len(body)
	result.BodySHA256 = webevidence.SHA256(body)
	return result
}
func decodeBody(encoded []byte, encoding string, limit int) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(encoded)
	var closer io.Closer
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return encoded, nil
	case "gzip":
		r, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		reader = r
		closer = r
	case "deflate":
		r, err := zlib.NewReader(reader)
		if err != nil {
			return nil, err
		}
		reader = r
		closer = r
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
	defer closer.Close()
	return io.ReadAll(io.LimitReader(reader, int64(limit)+1))
}
func portOf(target *url.URL) string {
	if port := target.Port(); port != "" {
		return port
	}
	if target.Scheme == "https" {
		return "443"
	}
	return "80"
}
func iconURLs(base *url.URL, body []byte) []*url.URL {
	var icons []*url.URL
	seen := map[string]bool{}
	add := func(raw string) {
		if len(icons) >= 2 {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		u := base.ResolveReference(ref)
		if u.User != nil || u.Scheme != base.Scheme || !strings.EqualFold(u.Hostname(), base.Hostname()) || portOf(u) != portOf(base) {
			return
		}
		u.Fragment = ""
		if seen[u.String()] {
			return
		}
		seen[u.String()] = true
		icons = append(icons, u)
	}
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			break
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if token.Data != "link" {
			continue
		}
		rel, href := "", ""
		for _, attr := range token.Attr {
			if attr.Key == "rel" {
				rel = strings.ToLower(attr.Val)
			}
			if attr.Key == "href" {
				href = attr.Val
			}
		}
		if strings.Contains(" "+rel+" ", " icon ") && href != "" {
			add(href)
		}
	}
	add("/favicon.ico")
	return icons
}

// ponytail: one parsed snapshot retained (at most 32 MiB source); sequential IPC
// makes an LRU or lock unnecessary. Replace it only when a different task digest arrives.
var cffCache struct {
	digest  string
	matcher *wapp.Wappalyze
}

func cachedMatcher(cff []byte, digest string) (*wapp.Wappalyze, error) {
	if len(cff) > 32<<20 {
		return nil, errors.New("fingerprint snapshot exceeds limit")
	}
	if cffCache.matcher != nil && cffCache.digest == digest {
		return cffCache.matcher, nil
	}
	f, err := os.CreateTemp("", "shen-cff-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(cff); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	matcher, err := wapp.NewFromFile(f.Name(), false, true)
	if err != nil {
		return nil, fmt.Errorf("load Wappalyzer snapshot: %w", err)
	}
	cffCache.digest, cffCache.matcher = digest, matcher
	return matcher, nil
}

func admit(ctx context.Context, input webevidence.ProbeRequest, target *url.URL) error {
	_, err := localHTTPPermit(ctx, input, target, true)
	return err
}
func localHTTPPermit(ctx context.Context, input webevidence.ProbeRequest, target *url.URL, wait bool, requestSeq ...int) (time.Time, error) {
	if input.AdmissionURL == "" && input.AdmissionToken == "" {
		return time.Now().Add(500 * time.Millisecond), nil
	}
	endpoint, err := url.Parse(input.AdmissionURL)
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.User != nil || input.AdmissionToken == "" {
		return time.Time{}, errors.New("invalid local admission endpoint")
	}
	body := map[string]any{"id": input.ID, "url": target.String(), "wait": wait}
	if (input.EnrichmentProfile == webevidence.EnrichmentProfile || input.ExecutionProfile == webevidence.FullProfile || input.Profile == webevidence.FullProfile || input.EnrichmentProfile == webevidence.FullProfile || input.Profile == webevidence.BrowserProfile) && len(requestSeq) > 0 {
		body["request_seq"] = requestSeq[0]
	}
	payload, _ := json.Marshal(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return time.Time{}, err
	}
	request.Header.Set("Authorization", "Bearer "+input.AdmissionToken)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sentAt := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return time.Time{}, err
	}
	defer response.Body.Close()
	if !wait && response.StatusCode == http.StatusTooManyRequests {
		return time.Time{}, httpadmission.ErrPending
	}
	if response.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("local admission returned %s", response.Status)
	}
	var permission struct {
		ValidForMS int64 `json:"valid_for_ms"`
		WaitedMS   int64 `json:"waited_ms"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&permission) != nil || permission.ValidForMS <= 0 || permission.ValidForMS > 1000 || permission.WaitedMS < 0 || permission.WaitedMS > 90000 {
		return time.Time{}, errors.New("invalid local HTTP permit")
	}
	received := time.Now()
	elapsed := received.Sub(sentAt)
	waited := time.Duration(permission.WaitedMS) * time.Millisecond
	// The Agent reports a fresh remaining TTL after queueing. Deduct only
	// delivery/IPC overhead; charging its monotonic handler time twice rejects
	// valid grants when the shared queue takes longer than the permit lifetime.
	if waited > elapsed || max(time.Duration(0), elapsed-waited) >= time.Duration(permission.ValidForMS)*time.Millisecond {
		return time.Time{}, errors.New("local HTTP permit expired")
	}
	if ctx.Err() != nil {
		return time.Time{}, context.Cause(ctx)
	}
	return received.Add(time.Duration(permission.ValidForMS)*time.Millisecond - max(time.Duration(0), elapsed-waited)), nil
}
