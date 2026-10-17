package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"scanplatform/internal/rulelib"
)

type scopeProxy struct {
	server       *http.Server
	listener     net.Listener
	transport    *http.Transport
	agent        *Agent
	endpoint     Endpoint
	base         *url.URL
	allowed      map[string]bool
	allowedPaths map[string]bool

	mu           sync.Mutex
	requestCount int
	firstErr     error
	truncated    bool
	requestRaw   bytes.Buffer
	responseRaw  bytes.Buffer
	connections  map[net.Conn]struct{}
}

func (a *Agent) startScopeProxy(ctx context.Context, ep Endpoint, rawBase string, requests []rulelib.Request) (*scopeProxy, error) {
	base, err := url.Parse(rawBase)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" {
		return nil, fmt.Errorf("invalid proxy scope origin")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	proxy := &scopeProxy{
		listener: listener, agent: a, endpoint: ep, base: base,
		allowed: make(map[string]bool, len(requests)), allowedPaths: make(map[string]bool, len(requests)), connections: make(map[net.Conn]struct{}),
	}
	for _, request := range requests {
		proxy.allowed[request.Method+" "+request.Path] = true
		proxy.allowedPaths[request.Path] = true
	}
	proxy.transport = &http.Transport{
		Proxy: nil, DialContext: a.safeDialer(ep.IP, base.Hostname()),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
		DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10,
	}
	proxy.server = &http.Server{
		Handler: proxy, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() {
		if err := proxy.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			proxy.recordError(err)
		}
	}()
	go func() {
		<-ctx.Done()
		proxy.Close()
	}()
	return proxy, nil
}

func (proxy *scopeProxy) URL() string { return "http://" + proxy.listener.Addr().String() }

func (proxy *scopeProxy) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect {
		proxy.connect(w, request)
		return
	}
	if !proxy.httpRequestAllowed(request) {
		proxy.reject(w, fmt.Errorf("request outside validated HTTP scope: %s %s", request.Method, request.URL.String()))
		return
	}
	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	removeHopHeaders(outbound.Header)
	outbound.Header.Del("Proxy-Authorization")
	requestRaw := string(rawHTTPRequest(outbound))
	response, err := proxy.transport.RoundTrip(outbound)
	if err != nil {
		proxy.reject(w, err)
		return
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody+1))
	truncated := len(body) > maxHTTPBody
	if truncated {
		body = body[:maxHTTPBody]
	}
	if readErr != nil {
		proxy.reject(w, readErr)
		return
	}
	responseRaw := string(rawHTTPResponse(response, body))
	proxy.recordExchange(requestRaw, responseRaw, truncated)
	if truncated {
		proxy.reject(w, fmt.Errorf("response exceeded %d-byte proxy read limit", maxHTTPBody))
		return
	}
	removeHopHeaders(response.Header)
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	if request.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (proxy *scopeProxy) httpRequestAllowed(request *http.Request) bool {
	if request.URL == nil || request.URL.User != nil || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		return false
	}
	if request.URL.Scheme != proxy.base.Scheme || !sameAuthority(request.URL, proxy.base) {
		return false
	}
	hostURL, err := url.Parse(proxy.base.Scheme + "://" + request.Host)
	if err != nil || hostURL.User != nil || hostURL.Path != "" || !sameAuthority(hostURL, proxy.base) {
		return false
	}
	return proxy.allowed[request.Method+" "+scopedURLPath(request.URL)]
}

func sameAuthority(left, right *url.URL) bool {
	return equalHost(left.Hostname(), right.Hostname()) && urlPort(left) == urlPort(right)
}

func (proxy *scopeProxy) connect(w http.ResponseWriter, request *http.Request) {
	host, port, err := net.SplitHostPort(request.Host)
	if err != nil || !equalHost(host, proxy.base.Hostname()) || port != urlPort(proxy.base) || proxy.base.Scheme != "https" {
		proxy.reject(w, fmt.Errorf("CONNECT target outside validated HTTPS scope: %s", request.Host))
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		proxy.reject(w, fmt.Errorf("HTTP proxy does not support CONNECT hijacking"))
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		proxy.recordError(err)
		return
	}
	upstream, err := proxy.agent.safeDialer(proxy.endpoint.IP, proxy.base.Hostname())(request.Context(), "tcp", request.Host)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		_ = client.Close()
		proxy.recordError(err)
		return
	}
	proxy.trackConnection(client, true)
	proxy.trackConnection(upstream, true)
	proxy.mu.Lock()
	proxy.requestCount++
	proxy.mu.Unlock()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		proxy.recordError(err)
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	done := make(chan struct{}, 2)
	copyConnection := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyConnection(upstream, client)
	go copyConnection(client, upstream)
	<-done
	_ = client.Close()
	_ = upstream.Close()
	proxy.trackConnection(client, false)
	proxy.trackConnection(upstream, false)
}

func (proxy *scopeProxy) reject(w http.ResponseWriter, err error) {
	proxy.recordError(err)
	http.Error(w, "blocked by scan scope", http.StatusBadGateway)
}

func (proxy *scopeProxy) recordExchange(requestRaw, responseRaw string, truncated bool) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	proxy.requestCount++
	separator := 0
	if proxy.requestRaw.Len() > 0 {
		separator = 2
	}
	requestTruncated := proxy.requestRaw.Len()+separator+len(requestRaw) > maxRawRequest
	separator = 0
	if proxy.responseRaw.Len() > 0 {
		separator = 2
	}
	responseTruncated := proxy.responseRaw.Len()+separator+len(responseRaw) > maxRawResponse
	proxy.truncated = proxy.truncated || truncated || requestTruncated || responseTruncated
	appendBounded(&proxy.requestRaw, requestRaw, maxRawRequest)
	appendBounded(&proxy.responseRaw, responseRaw, maxRawResponse)
}

func (proxy *scopeProxy) recordError(err error) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.firstErr == nil {
		proxy.firstErr = err
	}
}

func (proxy *scopeProxy) trackConnection(conn net.Conn, add bool) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if add {
		proxy.connections[conn] = struct{}{}
	} else {
		delete(proxy.connections, conn)
	}
}

func (proxy *scopeProxy) RequestCount() int {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return proxy.requestCount
}

func (proxy *scopeProxy) Err() error {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return proxy.firstErr
}

func (proxy *scopeProxy) Evidence() (string, string) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return proxy.requestRaw.String(), proxy.responseRaw.String()
}

func (proxy *scopeProxy) Truncated() bool {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return proxy.truncated
}

func (proxy *scopeProxy) ResultAllowed(rawURL, rawRequest string) bool {
	if rawURL != "" {
		u, err := url.Parse(rawURL)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != proxy.base.Scheme || !sameAuthority(u, proxy.base) {
			return false
		}
		return proxy.allowedPaths[scopedURLPath(u)]
	}
	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))
	if err != nil || request.URL == nil || request.URL.User != nil || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		return false
	}
	if request.URL.IsAbs() && (request.URL.Scheme != proxy.base.Scheme || !sameAuthority(request.URL, proxy.base)) {
		return false
	}
	hostURL, err := url.Parse(proxy.base.Scheme + "://" + request.Host)
	if err != nil || hostURL.User != nil || hostURL.Path != "" || !sameAuthority(hostURL, proxy.base) {
		return false
	}
	return proxy.allowed[request.Method+" "+scopedURLPath(request.URL)]
}

func scopedURLPath(value *url.URL) string {
	if value == nil || value.EscapedPath() == "" {
		return "/"
	}
	return value.EscapedPath()
}

func (proxy *scopeProxy) Close() {
	if proxy == nil || proxy.server == nil {
		return
	}
	_ = proxy.server.Close()
	proxy.transport.CloseIdleConnections()
	proxy.mu.Lock()
	for conn := range proxy.connections {
		_ = conn.Close()
	}
	proxy.connections = make(map[net.Conn]struct{})
	proxy.mu.Unlock()
}

func removeHopHeaders(headers http.Header) {
	connection := headers.Get("Connection")
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		headers.Del(name)
	}
	if connection != "" {
		for _, name := range strings.Split(connection, ",") {
			headers.Del(strings.TrimSpace(name))
		}
	}
}
