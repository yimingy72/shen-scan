package main

import (
	"bytes"
	"context"
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
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/httpx/runner"
	"scanplatform/internal/httpadmission"
	"scanplatform/internal/webevidence"
)

const fullEngine = "httpx-runner-v1.12.0/wappalyzergo-v0.2.96"

func probeFull(ctx context.Context, input webevidence.ProbeRequest) (webevidence.ProbeResult, error) {
	result := webevidence.ProbeResult{ID: input.ID, Protocol: webevidence.Protocol, Profile: webevidence.FullProfile, ExecutionProfile: webevidence.FullProfile, Identity: input.Identity, EnrichmentProfile: input.EnrichmentProfile, InputURL: input.URL, Engine: fullEngine, CFFSHA256: webevidence.SHA256(input.CFF)}
	target, err := url.Parse(input.URL)
	if err != nil || target.Hostname() == "" || target.User != nil || target.Fragment != "" || (target.Scheme != "http" && target.Scheme != "https") || net.ParseIP(input.ConnectIP) == nil {
		return result, errors.New("invalid fixed HTTP target")
	}
	if input.Protocol != webevidence.Protocol {
		return result, errors.New("unsupported IPC protocol")
	}
	if input.MaxRequests < 0 {
		return result, errors.New("negative request budget")
	}
	if len(input.CFF) == 0 || len(input.CFF) > 32<<20 || (input.CFFSHA256 != "" && input.CFFSHA256 != result.CFFSHA256) {
		return result, errors.New("invalid full Wappalyzer snapshot")
	}
	matcher, err := cachedMatcher(input.CFF, result.CFFSHA256)
	if err != nil {
		return result, err
	}
	for _, fingerprint := range matcher.GetFingerprints().Apps {
		if len(fingerprint.JS) > 0 || len(fingerprint.Dom) > 0 {
			result.CapabilityGaps = []string{"wappalyzer-browser-js-dom"}
			break
		}
	}
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
	host, sni := input.Host, input.SNI
	if host == "" {
		host = input.HTTPHost
	}
	if sni == "" {
		sni = input.TLSSNI
	}
	if host == "" {
		host = target.Host
	}
	if sni == "" {
		sni = target.Hostname()
	}
	if strings.ContainsAny(host, "\r\n/\t ") || (strings.ContainsAny(sni, "\r\n/:\t ") && net.ParseIP(sni) == nil) {
		return result, errors.New("invalid fixed Host/SNI identity")
	}
	capture := &fullCapture{ctx: ctx, input: input, target: target, timeout: timeout, host: host}
	var native *runner.Result
	options := &runner.Options{
		Context: ctx, FixedIP: input.ConnectIP, WrapTransport: capture.wrap,
		InputTargetHost: []string{input.URL}, Threads: 1, Timeout: 90, Retries: 1, Delay: -1,
		NoFallbackScheme: !input.AlternateScheme, DisableStdin: true, DisableStdout: true,
		Silent: true, NoColor: true, HostMaxErrors: -1, OutputCDN: "false",
		ExtractTitle: true, TechDetect: true, Wappalyzer: matcher, Favicon: true,
		TLSGrab: true, FollowHostRedirects: true, MaxRedirects: 10, ChainInStdout: true, CPEDetect: true, WordPress: true,
		StatusCode: true, ContentLength: true, OutputServerHeader: true,
		OutputContentType: true, OutputResponseTime: true, OutputIP: true,
		OutputLinesCount: true, OutputWordsCount: true, Hashes: "md5,mmh3,sha256,simhash",
		MaxResponseBodySizeToRead: webevidence.MaxBody, MaxResponseBodySizeToSave: webevidence.MaxBody,
		Protocol: "http11", SniName: sni,
		CustomHeaders: []string{"User-Agent: shen-scan/3", "Accept-Encoding: identity", "Host: " + host},
		OnResult:      func(value runner.Result) { native = &value },
	}
	instance, err := runner.New(options)
	if err != nil {
		return result, fmt.Errorf("httpx runner initialization: %w", err)
	}
	defer instance.Close()
	instance.RunEnumeration()
	result.Attempts = capture.attempts
	result.Requests = len(result.Attempts)
	if native == nil {
		return result, errors.New("httpx runner completed without OnResult")
	}
	result.Title = native.Title
	result.Technologies = append([]string(nil), native.Technologies...)
	sort.Strings(result.Technologies)
	// Copy the native json:"-" bytes before any SDK JSON serialization.
	if native.Response != nil {
		finalURL := native.FinalURL
		if finalURL == "" {
			finalURL = native.URL
		}
		for _, attempt := range result.Attempts {
			if attempt.URL == finalURL && attempt.StatusCode == native.Response.StatusCode {
				result.Response = attempt
			}
		}
		if result.Response.StatusCode == 0 {
			result.Response = webevidence.Response{URL: finalURL, Host: target.Host, ConnectIP: input.ConnectIP, Completeness: "partial", Error: "SDK response lacks observed transport evidence"}
		}
		if result.Response.Completeness == "full" {
			result.Response.Body = append([]byte(nil), native.Response.Data...)
			result.Response.BodySHA256 = webevidence.SHA256(result.Response.Body)
			result.Response.DecodedBytes = len(result.Response.Body)
		}
		if len(native.RequestRaw) > 0 && result.Response.RequestRaw == "" {
			result.Response.RequestRaw = string(native.RequestRaw)
		}
	}
	if len(native.FaviconData) > 0 {
		found := false
		for _, attempt := range result.Attempts {
			if attempt.URL == native.FaviconURL {
				icon := attempt
				if icon.Completeness == "full" {
					icon.Body = append([]byte(nil), native.FaviconData...)
					icon.BodySHA256 = webevidence.SHA256(icon.Body)
					icon.DecodedBytes = len(icon.Body)
				}
				result.Icons = append(result.Icons, icon)
				found = true
			}
		}
		if !found && native.FaviconPath == "data:" {
			result.Icons = append(result.Icons, webevidence.Response{URL: input.URL, Host: host, ConnectIP: input.ConnectIP, BodyStorage: "inline-favicon-data-url", Body: append([]byte(nil), native.FaviconData...), DecodedBytes: len(native.FaviconData), BodySHA256: webevidence.SHA256(native.FaviconData), Completeness: "full"})
		}
	}
	for i, attempt := range result.Attempts {
		if !redirectStatus(attempt.StatusCode) {
			continue
		}
		step := webevidence.RedirectStep{FromURL: attempt.URL, StatusCode: attempt.StatusCode, AttemptIndex: i}
		source, _ := url.Parse(attempt.URL)
		next, outcome := redirectDestination(source, attempt.Headers.Get("Location"))
		if next != nil {
			step.ToURL = next.String()
		}
		step.Outcome = outcome
		if step.Outcome == "" {
			step.Outcome = "not_followed"
			for _, following := range result.Attempts[i+1:] {
				if following.URL == step.ToURL {
					step.Outcome = "followed"
					break
				}
			}
		}
		result.Redirects = append(result.Redirects, step)
	}
	result.SDKResult, err = json.Marshal(native)
	if err != nil {
		return result, fmt.Errorf("httpx SDK metadata: %w", err)
	}
	if native.Err != nil {
		return result, fmt.Errorf("httpx runner: %w", native.Err)
	}
	if native.Failed || result.Response.StatusCode == 0 {
		return result, errors.New("httpx runner returned no successful HTTP response")
	}
	return result, nil
}

type fullCapture struct {
	ctx             context.Context
	input           webevidence.ProbeRequest
	target          *url.URL
	timeout         time.Duration
	host            string
	nativeTransport *http.Transport
	mu              sync.Mutex
	attempts        []webevidence.Response
}

func (capture *fullCapture) wrap(base http.RoundTripper) http.RoundTripper {
	if capture.nativeTransport != nil {
		return fullRoundTripper(func(request *http.Request) (*http.Response, error) {
			return capture.roundTrip(capture.nativeTransport, request)
		})
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return fullRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("unsupported SDK transport") })
	}
	capture.nativeTransport = transport
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.DisableKeepAlives = true
	transport.MaxResponseHeaderBytes = 32 << 10
	dial, dialTLS := transport.DialContext, transport.DialTLSContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	wrapDial := func(original func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx = httpadmission.RequestContext(ctx)
			host, port, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(host, capture.target.Hostname()) || port != portOf(capture.target) {
				return nil, errors.New("dial outside fixed HTTP entry")
			}
			ctx, err = httpadmission.BeforeDial(ctx, capture.input.ConnectIP, host, port)
			if err != nil {
				return nil, err
			}
			ctx = context.WithValue(ctx, fastdialer.IP, capture.input.ConnectIP)
			conn, err := original(ctx, network, address)
			return httpadmission.AfterDial(ctx, conn, err)
		}
	}
	transport.DialContext = wrapDial(dial)
	if dialTLS != nil {
		transport.DialTLSContext = wrapDial(dialTLS)
	}
	return fullRoundTripper(func(request *http.Request) (*http.Response, error) { return capture.roundTrip(transport, request) })
}

type fullRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip fullRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func (capture *fullCapture) roundTrip(base *http.Transport, request *http.Request) (*http.Response, error) {
	if capture.ctx.Err() != nil {
		return nil, context.Cause(capture.ctx)
	}
	if request.URL.User != nil || !strings.EqualFold(request.URL.Hostname(), capture.target.Hostname()) || portOf(request.URL) != portOf(capture.target) || (request.URL.Scheme != capture.target.Scheme && !capture.input.AlternateScheme) {
		return nil, errors.New("request outside fixed HTTP origin")
	}
	capture.mu.Lock()
	if capture.input.MaxRequests > 0 && len(capture.attempts) >= capture.input.MaxRequests {
		capture.mu.Unlock()
		return nil, errors.New("explicit HTTP request budget exhausted")
	}
	sequence := len(capture.attempts) + 1
	attempt := webevidence.Response{URL: request.URL.String(), Host: request.Host, ConnectIP: capture.input.ConnectIP, ObservedAt: time.Now().UTC(), Completeness: "missing"}
	capture.attempts = append(capture.attempts, attempt)
	capture.mu.Unlock()
	request = request.Clone(capture.ctx)
	request.Host = capture.host
	request.Close = true
	request = request.WithContext(context.WithValue(request.Context(), fastdialer.IP, capture.input.ConnectIP))
	raw, _ := httputil.DumpRequestOut(request, true)
	attempt.RequestRaw = string(raw)
	gate := httpadmission.Transport{Base: base, NetworkTimeout: capture.timeout, Permit: func(ctx context.Context, _, _, _ string, wait bool) (time.Time, error) {
		return localHTTPPermit(ctx, capture.input, request.URL, wait, sequence)
	}}
	response, err := gate.RoundTrip(request)
	if err != nil {
		attempt.Error = err.Error()
	} else {
		attempt.StatusCode, attempt.Proto, attempt.Headers = response.StatusCode, response.Proto, response.Header.Clone()
		header, _ := httputil.DumpResponse(response, false)
		attempt.HeaderRaw = string(header)
		if response.TLS != nil {
			attempt.TLS = &webevidence.TLS{Source: "same_http_connection", ServerName: response.TLS.ServerName, Version: response.TLS.Version}
			for _, certificate := range response.TLS.PeerCertificates {
				attempt.TLS.PeerCertificates = append(attempt.TLS.PeerCertificates, append([]byte(nil), certificate.Raw...))
			}
		}
		encoded, readErr := io.ReadAll(io.LimitReader(response.Body, int64(webevidence.MaxBody)+1))
		response.Body.Close()
		attempt.Completeness = "full"
		attempt.EncodedBytes = int64(len(encoded))
		if len(encoded) > webevidence.MaxBody {
			encoded = encoded[:webevidence.MaxBody]
			attempt.Completeness = "partial"
			attempt.Error = "encoded response exceeds limit"
		}
		body, decodeErr := decodeFullBody(encoded, response.Header.Get("Content-Encoding"), webevidence.MaxBody)
		if len(body) > webevidence.MaxBody {
			body = body[:webevidence.MaxBody]
			attempt.Completeness = "partial"
			attempt.Error = "decoded response exceeds limit"
		}
		if readErr != nil {
			attempt.Completeness = "partial"
			attempt.Error = readErr.Error()
		}
		if decodeErr != nil {
			attempt.Completeness = "partial"
			attempt.Error = decodeErr.Error()
		}
		attempt.Body, attempt.DecodedBytes, attempt.BodySHA256 = body, len(body), webevidence.SHA256(body)
		response.Body = io.NopCloser(bytes.NewReader(body))
		response.ContentLength = int64(len(body))
		response.Header.Del("Content-Encoding")
		response.Header.Set("Content-Length", fmt.Sprint(len(body)))
	}
	capture.mu.Lock()
	capture.attempts[sequence-1] = attempt
	capture.mu.Unlock()
	return response, err
}

// Keep decompression bounded independently of the encoded response limit.
func decodeFullBody(data []byte, encoding string, limit int) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "br":
		return io.ReadAll(io.LimitReader(brotli.NewReader(bytes.NewReader(data)), int64(limit)+1))
	case "zstd":
		reader, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderMaxMemory(16<<20), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	default:
		return decodeBody(data, encoding, limit)
	}
}
