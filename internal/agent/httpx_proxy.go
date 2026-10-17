package agent

import (
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
)

type httpxScopeTarget struct {
	endpoint Endpoint
	url      *url.URL
	origin   string
}

type httpxScopeProxy struct {
	ctx       context.Context
	server    *http.Server
	listener  net.Listener
	transport *http.Transport
	agent     *Agent
	targets   map[string]httpxScopeTarget
	inputs    map[string]httpxScopeTarget
	dial      map[string]httpxScopeTarget
	maxCount  int

	mu           sync.Mutex
	requestCount int
	firstErr     error
	connections  map[net.Conn]struct{}
	connectedIPs map[string]string
}

func prepareHTTPXTargets(ctx context.Context, agent *Agent, endpoints []Endpoint) ([]httpxScopeTarget, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	targets := make([]httpxScopeTarget, 0, len(endpoints))
	seen := make(map[string]httpxScopeTarget)
	for _, endpoint := range endpoints {
		raw, err := endpointURL(endpoint)
		if err != nil {
			return nil, err
		}
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("endpoint %q is not an HTTP(S) URL without userinfo or fragment", raw)
		}
		parsed.Host = canonicalURLHost(parsed)
		if parsed.Path == "" {
			parsed.Path = "/"
		}
		if err := agent.policy.validateEndpoint(ctx, parsed.Hostname(), urlPort(parsed)); err != nil {
			return nil, err
		}
		if endpoint.IP != "" {
			if err := agent.policy.validateEndpoint(ctx, endpoint.IP, urlPort(parsed)); err != nil {
				return nil, err
			}
		}
		origin := httpxOrigin(parsed)
		target := httpxScopeTarget{endpoint: endpoint, url: parsed, origin: origin}
		if previous, exists := seen[origin]; exists {
			if previous.endpoint.IP != endpoint.IP {
				return nil, fmt.Errorf("origin %q has conflicting fixed IPs", origin)
			}
		} else {
			seen[origin] = target
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func (a *Agent) startHTTPXScopeProxy(ctx context.Context, targets []httpxScopeTarget) (*httpxScopeProxy, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	proxy := &httpxScopeProxy{
		ctx: ctx, listener: listener, agent: a, targets: make(map[string]httpxScopeTarget), inputs: make(map[string]httpxScopeTarget), dial: make(map[string]httpxScopeTarget),
		maxCount: max(4, len(targets)*2), connections: make(map[net.Conn]struct{}), connectedIPs: make(map[string]string),
	}
	for _, target := range targets {
		proxy.targets[target.origin] = target
		proxy.inputs[httpxInputKey(target.url)] = target
		authority := strings.ToLower(net.JoinHostPort(target.url.Hostname(), urlPort(target.url)))
		if previous, ok := proxy.dial[authority]; ok && previous.endpoint.IP != target.endpoint.IP {
			_ = listener.Close()
			return nil, fmt.Errorf("authority %q has conflicting fixed IPs", authority)
		}
		proxy.dial[authority] = target
	}
	proxy.transport = &http.Transport{
		Proxy:               nil,
		DialContext:         proxy.dialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
		DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10,
	}
	proxy.server = &http.Server{Handler: proxy, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
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

func (proxy *httpxScopeProxy) URL() string { return "http://" + proxy.listener.Addr().String() }

func (proxy *httpxScopeProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect {
		proxy.connect(response, request)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		proxy.reject(response, fmt.Errorf("httpx method outside discovery scope: %s", request.Method))
		return
	}
	if request.URL == nil || request.URL.User != nil || request.URL.Fragment != "" {
		proxy.reject(response, fmt.Errorf("invalid httpx proxy request URL"))
		return
	}
	target, ok := proxy.targets[httpxOrigin(request.URL)]
	if !ok || target.url.Scheme != request.URL.Scheme {
		proxy.reject(response, fmt.Errorf("httpx request outside assigned origins: %s", request.URL.String()))
		return
	}
	hostURL, err := url.Parse("http://" + request.Host)
	if err != nil || !sameAuthority(hostURL, target.url) {
		proxy.reject(response, fmt.Errorf("httpx Host header outside assigned origin: %s", request.Host))
		return
	}
	if !proxy.takeRequest() {
		proxy.reject(response, fmt.Errorf("httpx request count exceeded %d", proxy.maxCount))
		return
	}
	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	removeHopHeaders(outbound.Header)
	outbound.Header.Del("Proxy-Authorization")
	upstream, err := (budgetHTTPTransport{transport: proxy.transport, timeout: 8 * time.Second}).RoundTrip(outbound)
	if err != nil {
		http.Error(response, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer upstream.Body.Close()
	removeHopHeaders(upstream.Header)
	for name, values := range upstream.Header {
		for _, value := range values {
			response.Header().Add(name, value)
		}
	}
	response.WriteHeader(upstream.StatusCode)
	if request.Method != http.MethodHead {
		_, _ = io.Copy(response, upstream.Body)
	}
}

func (proxy *httpxScopeProxy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	target, ok := proxy.dial[strings.ToLower(net.JoinHostPort(strings.TrimSuffix(host, "."), port))]
	if !ok {
		return nil, fmt.Errorf("dial outside assigned httpx origins: %s", address)
	}
	connection, err := proxy.agent.safeDialer(target.endpoint.IP, target.url.Hostname())(ctx, network, address)
	if err == nil {
		proxy.recordConnectedIP(target.origin, connection)
	}
	return connection, err
}

func (proxy *httpxScopeProxy) connect(response http.ResponseWriter, request *http.Request) {
	host, port, err := net.SplitHostPort(request.Host)
	if err != nil {
		proxy.reject(response, fmt.Errorf("invalid httpx CONNECT target: %s", request.Host))
		return
	}
	authority := strings.ToLower(net.JoinHostPort(strings.TrimSuffix(host, "."), port))
	target, ok := proxy.dial[authority]
	if !ok || target.url.Scheme != "https" {
		proxy.reject(response, fmt.Errorf("httpx CONNECT outside assigned origins: %s", request.Host))
		return
	}
	err = serveProxyTLS(proxy.ctx, response, request, target.url.Hostname(), http.HandlerFunc(func(w http.ResponseWriter, inner *http.Request) {
		if inner.Method == http.MethodConnect || inner.URL == nil || inner.URL.IsAbs() {
			proxy.reject(w, fmt.Errorf("nested/absolute HTTPS proxy request"))
			return
		}
		inner.URL.Scheme = "https"
		inner.URL.Host = inner.Host
		proxy.ServeHTTP(w, inner)
	}), proxy.track)
	if err != nil {
		proxy.recordError(err)
	}
}

func (proxy *httpxScopeProxy) takeRequest() bool {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	proxy.requestCount++
	return proxy.requestCount <= proxy.maxCount
}

func (proxy *httpxScopeProxy) reject(response http.ResponseWriter, err error) {
	proxy.recordError(err)
	http.Error(response, "blocked by scan scope", http.StatusBadGateway)
}

func (proxy *httpxScopeProxy) Target(raw string) (httpxScopeTarget, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Fragment != "" {
		return httpxScopeTarget{}, false
	}
	target, ok := proxy.inputs[httpxInputKey(parsed)]
	return target, ok
}

func httpxInputKey(value *url.URL) string {
	copy := *value
	copy.Host = canonicalURLHost(&copy)
	if copy.Path == "" {
		copy.Path = "/"
	}
	return copy.String()
}

func (proxy *httpxScopeProxy) Err() error {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return proxy.firstErr
}

func (proxy *httpxScopeProxy) recordConnectedIP(origin string, connection net.Conn) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	proxy.connectedIPs[origin] = remoteHost(connection.RemoteAddr())
}

func (proxy *httpxScopeProxy) connectedIP(origin string) string {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return proxy.connectedIPs[origin]
}

func (proxy *httpxScopeProxy) recordError(err error) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.firstErr == nil {
		proxy.firstErr = err
	}
}

func (proxy *httpxScopeProxy) track(connection net.Conn, add bool) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if add {
		proxy.connections[connection] = struct{}{}
	} else {
		delete(proxy.connections, connection)
	}
}

func (proxy *httpxScopeProxy) Close() {
	if proxy == nil || proxy.server == nil {
		return
	}
	_ = proxy.server.Close()
	proxy.transport.CloseIdleConnections()
	proxy.mu.Lock()
	for connection := range proxy.connections {
		_ = connection.Close()
	}
	proxy.connections = make(map[net.Conn]struct{})
	proxy.mu.Unlock()
}

func httpxOrigin(value *url.URL) string {
	if value == nil || (value.Scheme != "http" && value.Scheme != "https") || value.Hostname() == "" {
		return ""
	}
	copy := *value
	copy.Host = canonicalURLHost(&copy)
	return strings.ToLower(copy.Scheme + "://" + copy.Host)
}
