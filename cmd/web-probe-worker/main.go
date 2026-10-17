// web-probe-worker uses httpx's request/title SDK and WappalyzerGo over a bounded
// transport. httpx.Do is intentionally not used: v1.12 does not expose a transport
// hook and its decoding cannot enforce our independent encoded/decoded limits.
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
	if len(os.Args) == 2 && os.Args[1] == "--capabilities" {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"protocol": webevidence.Protocol, "profile": webevidence.Profile, "engine": "httpx-sdk-v1.12.0/bounded-transport+wappalyzergo-v0.2.96", "request_admission": "loopback-v2", "stream_protocol": "jsonl-item-v1"})
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

func probe(ctx context.Context, input webevidence.ProbeRequest) (webevidence.ProbeResult, error) {
	result := webevidence.ProbeResult{ID: input.ID, Protocol: webevidence.Protocol, Profile: webevidence.Profile, Engine: "httpx-sdk-v1.12.0/bounded-transport+wappalyzergo-v0.2.96"}
	target, err := url.Parse(input.URL)
	if err != nil || target.Hostname() == "" || target.User != nil || target.Fragment != "" || (target.Scheme != "http" && target.Scheme != "https") || net.ParseIP(input.ConnectIP) == nil {
		return result, errors.New("invalid fixed HTTP target")
	}
	if input.Protocol != webevidence.Protocol {
		return result, errors.New("unsupported IPC protocol")
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
	count := 0
	fetch := func(u *url.URL, limit int) webevidence.Response {
		count++
		if count > 8 {
			return webevidence.Response{URL: u.String(), Completeness: "missing", Error: "request budget exhausted"}
		}
		return collect(ctx, u, input.ConnectIP, timeout, limit, func(ctx context.Context, ip, host, port string, wait bool) (time.Time, error) {
			return localHTTPPermit(ctx, input, u, wait)
		})
	}
	result.Response = fetch(target, webevidence.MaxBody)
	result.Attempts = append(result.Attempts, metadata(result.Response))
	if result.Response.StatusCode == 0 && input.AlternateScheme && ctx.Err() == nil {
		alternate := *target
		if alternate.Port() == "" {
			alternate.Host = net.JoinHostPort(target.Hostname(), portOf(target))
		}
		if alternate.Scheme == "http" {
			alternate.Scheme = "https"
		} else {
			alternate.Scheme = "http"
		}
		// Keep the same port when switching a port-derived endpoint's protocol.
		result.Response = fetch(&alternate, webevidence.MaxBody)
		result.Attempts = append(result.Attempts, metadata(result.Response))
		target = &alternate
	}
	if result.Response.StatusCode > 0 {
		result.Title = hx.ExtractTitle(&hx.Response{Data: result.Response.Body, Raw: result.Response.HeaderRaw + string(result.Response.Body)})
		// Opaque rule engines cannot prove negative/body-hash matches on a prefix.
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
			if ctx.Err() != nil {
				break
			}
			result.Icons = append(result.Icons, fetch(icon, webevidence.MaxIcon))
		}
	}
	result.Requests = count
	return result, nil
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
	client := &http.Client{Transport: httpadmission.Transport{Base: transport, NetworkTimeout: timeout, Permit: permit}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request.Request)

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
func localHTTPPermit(ctx context.Context, input webevidence.ProbeRequest, target *url.URL, wait bool) (time.Time, error) {
	if input.AdmissionURL == "" && input.AdmissionToken == "" {
		return time.Now().Add(500 * time.Millisecond), nil
	}
	endpoint, err := url.Parse(input.AdmissionURL)
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.User != nil || input.AdmissionToken == "" {
		return time.Time{}, errors.New("invalid local admission endpoint")
	}
	payload, _ := json.Marshal(map[string]any{"id": input.ID, "url": target.String(), "wait": wait})
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
