// web-probe-worker uses httpx's request/title SDK and WappalyzerGo over a bounded
// transport. httpx.Do is intentionally not used: v1.12 does not expose a transport
// hook and its decoding cannot enforce our independent encoded/decoded limits.
package main

import (
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
	"scanplatform/internal/webevidence"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--capabilities" {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"protocol": webevidence.Protocol, "profile": webevidence.Profile, "engine": "httpx-sdk-v1.12.0/bounded-transport+wappalyzergo-v0.2.96"})
		return
	}
	var input webevidence.ProbeRequest
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 36<<20)).Decode(&input); err != nil {
		fatal(err)
	}
	result, err := probe(context.Background(), input)
	if err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fatal(err)
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

func probe(ctx context.Context, input webevidence.ProbeRequest) (webevidence.ProbeResult, error) {
	result := webevidence.ProbeResult{Protocol: webevidence.Protocol, Profile: webevidence.Profile, Engine: "httpx-sdk-v1.12.0/bounded-transport+wappalyzergo-v0.2.96"}
	target, err := url.Parse(input.URL)
	if err != nil || target.Hostname() == "" || target.User != nil || target.Fragment != "" || (target.Scheme != "http" && target.Scheme != "https") || net.ParseIP(input.ConnectIP) == nil {
		return result, errors.New("invalid fixed HTTP target")
	}
	if input.Protocol != webevidence.Protocol {
		return result, errors.New("unsupported IPC protocol")
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
		return collect(ctx, u, input.ConnectIP, timeout, limit)
	}
	result.Response = fetch(target, webevidence.MaxBody)
	result.Attempts = append(result.Attempts, metadata(result.Response))
	if result.Response.StatusCode == 0 && input.AlternateScheme && ctx.Err() == nil {
		alternate := *target
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
			f, err := os.CreateTemp("", "shen-cff-*.json")
			if err != nil {
				return result, err
			}
			defer os.Remove(f.Name())
			if _, err = f.Write(input.CFF); err != nil {
				f.Close()
				return result, err
			}
			f.Close()
			matcher, err := wapp.NewFromFile(f.Name(), false, true)
			if err != nil {
				return result, fmt.Errorf("load Wappalyzer snapshot: %w", err)
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

func collect(ctx context.Context, target *url.URL, ip string, timeout time.Duration, limit int) webevidence.Response {
	result := webevidence.Response{URL: target.String(), Host: target.Host, ConnectIP: ip, ObservedAt: time.Now().UTC(), Completeness: "missing"}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sdk := &hx.HTTPX{Options: &hx.Options{DefaultUserAgent: "shen-scan/2"}}
	request, err := sdk.NewRequestWithContext(ctx, http.MethodGet, target.String())
	if err != nil {
		result.Error = err.Error()
		return result
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	request.Header.Set("Accept-Encoding", "identity")
	raw, _ := httputil.DumpRequestOut(request.Request, false)
	result.RequestRaw = string(raw)
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: target.Hostname(), MinVersion: tls.VersionTLS10},
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(host, target.Hostname()) || port != portOf(target) {
				return nil, errors.New("dial outside fixed entry")
			}
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
