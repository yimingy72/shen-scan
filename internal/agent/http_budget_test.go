package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanplatform/internal/rulelib"
)

func allowHTTPFixture(t *testing.T, a *Agent) {
	t.Helper()
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC()
		json.NewEncoder(w).Encode(map[string]any{"granted": true, "server_time": now, "valid_until": now.Add(500 * time.Millisecond)})
	}))
	t.Cleanup(central.Close)
	a.client.baseURL = central.URL
}

func TestHTTPPermitFailureClosesBeforeHeaders(t *testing.T) {
	var seen atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen.Add(1); fmt.Fprint(w, "ok") }))
	defer target.Close()
	for _, kind := range []string{"expired", "control_error", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			a := newHTTPXTestAgent(t, "unused")
			central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "control_error" {
					http.Error(w, "unavailable", 503)
					return
				}
				now := time.Now().UTC()
				if kind == "cancelled" {
					select {
					case <-r.Context().Done():
					case <-time.After(300 * time.Millisecond):
					}
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"granted": true, "server_time": now, "valid_until": now.Add(-time.Second)})
			}))
			defer central.Close()
			a.client.baseURL = central.URL
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			ctx = a.withHTTPBudget(ctx, Task{ID: "fixture", AttemptNo: 1})
			obs := a.fetchHTTP(ctx, Endpoint{URL: target.URL}, time.Second)
			if obs.Error == "" || obs.StatusCode != 0 || obs.IP != "" || seen.Load() != 0 {
				t.Fatalf("unauthorized request emitted: %+v, target requests=%d", obs, seen.Load())
			}
		})
	}
}

func TestHTTPSProxyCountsInnerRequestsAndScopesBeforePermit(t *testing.T) {
	var seen, permits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen.Add(1); fmt.Fprint(w, r.URL.Path) }))
	defer target.Close()
	a := newHTTPXTestAgent(t, "unused")
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		seq := permits.Add(1)
		if in["request_id"] != fmt.Sprint(seq) || in["connect_ip"] != "127.0.0.1" {
			t.Errorf("bad permit binding: %+v", in)
		}
		now := time.Now().UTC()
		json.NewEncoder(w).Encode(map[string]any{"granted": true, "server_time": now, "valid_until": now.Add(500 * time.Millisecond)})
	}))
	defer central.Close()
	a.client.baseURL = central.URL
	ctx, cancel := context.WithCancel(a.withHTTPBudget(context.Background(), Task{ID: "fixture", AttemptNo: 1}))
	defer cancel()
	proxy, err := a.startScopeProxy(ctx, Endpoint{URL: target.URL}, target.URL, []rulelib.Request{{Method: "GET", Path: "/ok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	// Keep both requests in one TLS CONNECT tunnel; CONNECT itself has no permit.
	connection, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	u, _ := url.Parse(target.URL)
	fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", u.Host, u.Host)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %+v", err, response)
	}
	secure := tls.Client(connection, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err := secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	reader = bufio.NewReader(secure)
	for _, path := range []string{"/ok", "/ok", "/outside"} {
		fmt.Fprintf(secure, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, u.Host)
		response, err = http.ReadResponse(reader, &http.Request{Method: "GET"})
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if path == "/outside" {
			if response.StatusCode != 502 {
				t.Fatalf("scope bypass: %s", data)
			}
		} else if response.StatusCode != 200 || strings.TrimSpace(string(data)) != "/ok" {
			t.Fatalf("bad proxy response: %s %s proxy error: %v", response.Status, data, proxy.Err())
		}
	}
	if permits.Load() != 2 || seen.Load() != 2 || proxy.RequestCount() != 2 {
		t.Fatalf("CONNECT/request accounting: permits=%d actual=%d proxy=%d", permits.Load(), seen.Load(), proxy.RequestCount())
	}
}

func TestWebAdmissionReportsQueueTime(t *testing.T) {
	a := newHTTPXTestAgent(t, "unused")
	var calls atomic.Int32
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			json.NewEncoder(w).Encode(map[string]any{"granted": false, "retry_after_ms": 700})
			return
		}
		now := time.Now().UTC()
		json.NewEncoder(w).Encode(map[string]any{"granted": true, "server_time": now, "valid_until": now.Add(500 * time.Millisecond)})
	}))
	defer central.Close()
	a.client.baseURL = central.URL
	ctx, cancel := context.WithTimeout(a.withHTTPBudget(context.Background(), Task{ID: "fixture", AttemptNo: 1}), 3*time.Second)
	defer cancel()
	base, _ := url.Parse("http://127.0.0.1:18080/")
	endpoint, token, closeAdmission, err := startWebAdmission(ctx, "fixture", "127.0.0.1", base, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAdmission()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(`{"id":"fixture","url":"http://127.0.0.1:18080/"}`))
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var permission struct {
		ValidFor int64 `json:"valid_for_ms"`
		Waited   int64 `json:"waited_ms"`
	}
	if json.NewDecoder(response.Body).Decode(&permission) != nil || response.StatusCode != 200 || permission.Waited < 690 || permission.ValidFor <= 0 || permission.ValidFor > 500 {
		t.Fatalf("bad queued callback permission: %+v status=%d", permission, response.StatusCode)
	}
}

func TestHTTPAdmissionQueueBeforeNativeAndProxyConnections(t *testing.T) {
	for _, mode := range []string{"native", "nuclei-proxy", "httpx-proxy"} {
		t.Run(mode, func(t *testing.T) {
			var connected atomic.Int32
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
			target.Config.ReadHeaderTimeout = 50 * time.Millisecond
			target.Config.ConnState = func(_ net.Conn, s http.ConnState) {
				if s == http.StateNew {
					connected.Add(1)
				}
			}
			target.Start()
			defer target.Close()
			a := newHTTPXTestAgent(t, "unused")
			var calls atomic.Int32
			central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					json.NewEncoder(w).Encode(map[string]any{"granted": false, "retry_after_ms": 700})
					return
				}
				if connected.Load() != 0 {
					t.Error("target socket held during permission queue")
				}
				now := time.Now().UTC()
				json.NewEncoder(w).Encode(map[string]any{"granted": true, "server_time": now, "valid_until": now.Add(500 * time.Millisecond)})
			}))
			defer central.Close()
			a.client.baseURL = central.URL
			ctx, cancel := context.WithTimeout(a.withHTTPBudget(context.Background(), Task{ID: "fixture", AttemptNo: 1}), 3*time.Second)
			defer cancel()
			ep := Endpoint{URL: target.URL}
			if mode == "native" {
				observation := a.fetchHTTP(ctx, ep, 100*time.Millisecond)
				if observation.Error != "" || observation.StatusCode != 200 {
					t.Fatalf("native queue consumed network limit: %+v", observation)
				}
				return
			}
			var proxyURL string
			if mode == "nuclei-proxy" {
				proxy, err := a.startScopeProxy(ctx, ep, target.URL, []rulelib.Request{{Method: "GET", Path: "/"}})
				if err != nil {
					t.Fatal(err)
				}
				defer proxy.Close()
				proxyURL = proxy.URL()
			} else {
				targets, err := prepareHTTPXTargets(ctx, a, []Endpoint{ep})
				if err != nil {
					t.Fatal(err)
				}
				proxy, err := a.startHTTPXScopeProxy(ctx, targets)
				if err != nil {
					t.Fatal(err)
				}
				defer proxy.Close()
				proxyURL = proxy.URL()
			}
			parsed, _ := url.Parse(proxyURL)
			request, _ := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
			response, err := (&http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(parsed)}, Timeout: 2 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			io.Copy(io.Discard, response.Body)
			if response.StatusCode != 200 {
				t.Fatalf("proxy queue failed: %s", response.Status)
			}
		})
	}
}
