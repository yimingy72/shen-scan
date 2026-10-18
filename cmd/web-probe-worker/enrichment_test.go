package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"scanplatform/internal/webevidence"
)

type enrichmentExchange struct {
	URL      string `json:"url"`
	Request  string `json:"request"`
	Response string `json:"response"`
	Note     string `json:"note,omitempty"`
}
type enrichmentRecorder struct {
	mu        sync.Mutex
	exchanges []enrichmentExchange
	label     string
}

func (rec *enrichmentRecorder) add(exchange enrichmentExchange) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.exchanges = append(rec.exchanges, exchange)
}
func (rec *enrichmentRecorder) save(t *testing.T) {
	if dir := os.Getenv("WEB_ENRICHMENT_EVIDENCE_DIR"); dir != "" {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		data, err := json.MarshalIndent(rec.exchanges, "", "  ")
		if err != nil {
			t.Error(err)
			return
		}
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Error(err)
			return
		}
		name := "helper-" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "-" + rec.label + ".http.json"
		if err = os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0600); err != nil {
			t.Error(err)
		}
	}
}

// Record complete synthetic HTTP exchanges with the same headers/body sent on
// the wire. Failure fixtures explicitly have no response rather than inventing one.
func enrichmentFixture(t *testing.T, secure bool, handler http.HandlerFunc, delays ...time.Duration) (*httptest.Server, *enrichmentRecorder) {
	t.Helper()
	rec := &enrichmentRecorder{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := httputil.DumpRequest(r, true)
		if err != nil {
			t.Error(err)
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		exchange := enrichmentExchange{URL: scheme + "://" + r.Host + r.URL.RequestURI(), Request: string(raw)}
		if r.URL.Path == "/close" {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			exchange.Note = "synthetic peer closed before HTTP response"
			rec.add(exchange)
			return
		}
		if r.URL.Path == "/wait" {
			<-r.Context().Done()
			exchange.Note = "synthetic request canceled before response"
			rec.add(exchange)
			return
		}
		recorded := httptest.NewRecorder()
		handler(recorded, r)
		headers := recorded.Header().Clone()
		headers.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		headers.Set("Content-Length", fmt.Sprint(recorded.Body.Len()))
		headers.Set("Connection", "close")
		response := &http.Response{StatusCode: recorded.Code, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: headers, Body: io.NopCloser(bytes.NewReader(recorded.Body.Bytes())), ContentLength: int64(recorded.Body.Len())}
		packet, err := httputil.DumpResponse(response, true)
		if err != nil {
			t.Error(err)
			return
		}
		exchange.Response = string(packet)
		rec.add(exchange)
		for key, values := range headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(recorded.Code)
		w.Write(recorded.Body.Bytes())
	}))
	if secure {
		if len(delays) > 0 {
			server.Listener = enrichmentDelayedListener{Listener: server.Listener, delay: delays[0]}
		}
		server.StartTLS()
	} else {
		server.Start()
	}
	address, _ := url.Parse(server.URL)
	rec.label = address.Scheme + "-" + portOf(address)
	t.Cleanup(func() { server.Close(); rec.save(t) })
	return server, rec
}
func enrichmentInput(server *httptest.Server, path string) webevidence.ProbeRequest {
	base, _ := url.Parse(server.URL)
	return webevidence.ProbeRequest{Protocol: webevidence.Protocol, EnrichmentProfile: webevidence.EnrichmentProfile, ID: "synthetic-entry", URL: base.Scheme + "://fixture.test:" + portOf(base) + path, ConnectIP: "127.0.0.1", MaxRequests: 8}
}
func assertEnrichmentAccounting(t *testing.T, result webevidence.ProbeResult, budget int) {
	t.Helper()
	if result.Requests > budget || result.Requests != len(result.Attempts) {
		t.Fatalf("request accounting: count=%d attempts=%d budget=%d", result.Requests, len(result.Attempts), budget)
	}
	for _, step := range result.Redirects {
		if step.AttemptIndex < 0 || step.AttemptIndex >= len(result.Attempts) {
			t.Fatalf("bad source index: %+v", step)
		}
		source := result.Attempts[step.AttemptIndex]
		if step.FromURL != source.URL || step.StatusCode != source.StatusCode {
			t.Fatalf("trace/source mismatch: %+v / %+v", step, source)
		}
	}
}

func TestEnrichmentTLSChainBudgetAndFinalMatching(t *testing.T) {
	var requests, permits atomic.Int32
	target, _ := enrichmentFixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !strings.HasPrefix(r.Host, "fixture.test:") || r.TLS.ServerName != "fixture.test" {
			t.Errorf("fixed target identity lost: Host=%s SNI=%s", r.Host, r.TLS.ServerName)
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("redirect credentials forwarded")
		}
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Location", "/middle?x=1#remove")
			w.Header().Set("Set-Cookie", "synthetic_session=do-not-forward")
			w.WriteHeader(302)
			fmt.Fprint(w, "old-marker")
		case "/middle":
			w.Header().Set("Location", "./final?x=2")
			w.WriteHeader(307)
			fmt.Fprint(w, "middle-marker")
		case "/final":
			fmt.Fprint(w, `<title>final</title>final-marker<link rel="icon" href="/ico">`)
		default:
			fmt.Fprint(w, "icon")
		}
	})
	callback, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
		sequence := permits.Add(1)
		var in struct {
			RequestSeq int `json:"request_seq"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.RequestSeq != int(sequence) {
			t.Errorf("wrong per-fetch sequence: got=%d want=%d", in.RequestSeq, sequence)
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-local-token" {
			t.Error("missing local permission token")
		}
		json.NewEncoder(w).Encode(map[string]int64{"valid_for_ms": 475, "waited_ms": 0})
	})
	input := enrichmentInput(target, "/start")
	input.AdmissionURL = callback.URL
	input.AdmissionToken = "synthetic-local-token"
	input.CFF = []byte(`{"apps":{"Old":{"html":["old-marker"]},"Final":{"html":["final-marker"]}}}`)
	input.CFFSHA256 = webevidence.SHA256(input.CFF)
	result, err := probe(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	assertEnrichmentAccounting(t, result, 8)
	if result.InputURL != input.URL || result.EnrichmentProfile != input.EnrichmentProfile || result.Response.URL != strings.Replace(input.URL, "/start", "/final?x=2", 1) || result.Title != "final" {
		t.Fatalf("wrong final identity: %+v", result)
	}
	if len(result.Redirects) != 2 || result.Redirects[0].Outcome != "followed" || result.Redirects[1].Outcome != "followed" || strings.Contains(result.Redirects[0].ToURL, "#") {
		t.Fatalf("bad chain: %+v", result.Redirects)
	}
	if len(result.Technologies) != 1 || result.Technologies[0] != "Final" {
		t.Fatalf("different pages mixed for matching: %v", result.Technologies)
	}
	if result.Requests != 5 || requests.Load() != 5 || permits.Load() != 5 || len(result.Icons) != 2 {
		t.Fatalf("ungated/unbounded requests: %+v target=%d permits=%d", result, requests.Load(), permits.Load())
	}
	if result.Response.TLS == nil || result.Response.TLS.Source != "same_http_connection" || len(result.Response.TLS.PeerCertificates) == 0 {
		t.Fatal("actual connection TLS evidence lost")
	}
}

func TestEnrichmentStopsAndRetainsLastResponse(t *testing.T) {
	for _, test := range []struct {
		name, location, want string
		budget               int
		cancel               bool
	}{
		{name: "loop", location: "/start#fragment", want: "loop", budget: 1},
		{name: "missing", want: "missing_location", budget: 1},
		{name: "invalid", location: "http://%zz/", want: "invalid_location", budget: 1},
		{name: "userinfo", location: "http://user:synthetic@fixture.test/", want: "invalid_location", budget: 1},
		{name: "long", location: "/" + strings.Repeat("a", maxRedirectLocation), want: "location_too_long", budget: 1},
		{name: "budget", location: "/final", want: "skipped_budget", budget: 1},
		{name: "network_failure", location: "/close", want: "fetch_failed", budget: 2},
		{name: "canceled", location: "/wait", want: "canceled", budget: 2, cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requested atomic.Int32
			target, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
				requested.Add(1)
				if test.location != "" {
					w.Header().Set("Location", test.location)
				}
				w.WriteHeader(302)
				fmt.Fprint(w, "saved-primary-page")
			})
			input := enrichmentInput(target, "/start")
			input.MaxRequests = test.budget
			ctx := context.Background()
			if test.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 80*time.Millisecond)
				defer cancel()
			}
			result, err := probe(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			assertEnrichmentAccounting(t, result, test.budget)
			if result.Response.StatusCode != 302 || result.Response.URL != input.URL || string(result.Response.Body) != "saved-primary-page" {
				t.Fatalf("primary response discarded: %+v", result.Response)
			}
			if len(result.Redirects) != 1 || result.Redirects[0].Outcome != test.want {
				t.Fatalf("wrong terminal trace: %+v", result.Redirects)
			}
			if result.Requests != test.budget || requested.Load() != 1 {
				t.Fatalf("unexpected request plan: %d / %d", result.Requests, requested.Load())
			}
		})
	}
}

func TestEnrichmentBlocksCrossOriginAndLimitsHops(t *testing.T) {
	var outside atomic.Int32
	foreign, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) { outside.Add(1) })
	for _, kind := range []string{"port", "host", "scheme"} {
		t.Run(kind, func(t *testing.T) {
			var requested atomic.Int32
			target, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
				requested.Add(1)
				destination := foreign.URL + "/outside"
				if kind == "host" {
					destination = "http://outside.invalid:" + strings.Split(r.Host, ":")[1] + "/outside"
				}
				if kind == "scheme" {
					destination = "https://" + r.Host + "/outside"
				}
				w.Header().Set("Location", destination)
				w.WriteHeader(302)
			})
			input := enrichmentInput(target, "/start")
			input.MaxRequests = 1
			result, err := probe(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			assertEnrichmentAccounting(t, result, 1)
			if result.Requests != 1 || requested.Load() != 1 || outside.Load() != 0 || len(result.Redirects) != 1 || result.Redirects[0].Outcome != "blocked_cross_origin" {
				t.Fatalf("cross-origin request escaped: %+v outside=%d", result, outside.Load())
			}
		})
	}
	t.Run("three_hops", func(t *testing.T) {
		target, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
			var n int
			fmt.Sscanf(r.URL.Path, "/hop%d", &n)
			w.Header().Set("Location", fmt.Sprintf("/hop%d", n+1))
			w.WriteHeader(308)
			fmt.Fprintf(w, "hop%d", n)
		})
		input := enrichmentInput(target, "/hop1")
		input.MaxRequests = 4
		result, err := probe(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		assertEnrichmentAccounting(t, result, 4)
		if result.Requests != 4 || len(result.Redirects) != 4 || result.Redirects[3].Outcome != "hop_limit" || !strings.HasSuffix(result.Response.URL, "/hop4") {
			t.Fatalf("hop cap failed: %+v", result)
		}
	})
}

func TestEnrichmentLegacyOffAndSupplementSingleGET(t *testing.T) {
	for _, step := range []string{"legacy", "supplement"} {
		t.Run(step, func(t *testing.T) {
			var requested atomic.Int32
			target, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
				requested.Add(1)
				w.Header().Set("Location", "/final")
				w.WriteHeader(302)
				fmt.Fprint(w, "supplement-marker")
			})
			input := enrichmentInput(target, "/start")
			input.MaxRequests = 1
			input.AlternateScheme = true
			input.CFF = []byte(`{"apps":{"Fixture":{"html":["supplement-marker"]}}}`)
			input.CFFSHA256 = webevidence.SHA256(input.CFF)
			if step == "legacy" {
				input.EnrichmentProfile = ""
			} else {
				input.Step = "supplement"
			}
			result, err := probe(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Redirects) != 0 || result.Response.StatusCode != 302 || result.Response.URL != input.URL {
				t.Fatalf("unexpected follow: %+v", result)
			}
			if step == "supplement" {
				assertEnrichmentAccounting(t, result, 1)
				if requested.Load() != 1 || result.Requests != 1 || len(result.Icons) != 0 || len(result.Technologies) != 0 {
					t.Fatalf("supplement exceeded oneGET: %+v", result)
				}
			} else if requested.Load() != 2 || result.Requests != 2 || len(result.Attempts) != 1 || len(result.Icons) != 1 {
				t.Fatalf("legacy plan changed: %+v", result)
			}
		})
	}
}

func TestEnrichmentRejectsInvalidPlanBeforeRequests(t *testing.T) {
	target, _ := enrichmentFixture(t, false, func(http.ResponseWriter, *http.Request) { t.Error("invalid plan reached target") })
	for _, test := range []struct {
		profile, step string
		budget        int
	}{
		{webevidence.EnrichmentProfile, "entry", -1}, {webevidence.EnrichmentProfile, "entry", 9}, {webevidence.EnrichmentProfile, "supplement", 2}, {"other", "", 1}, {"", "supplement", 1}, {webevidence.EnrichmentProfile, "unknown", 1},
	} {
		input := enrichmentInput(target, "/")
		input.EnrichmentProfile = test.profile
		input.Step = test.step
		input.MaxRequests = test.budget
		result, err := probe(context.Background(), input)
		if err == nil || result.Requests != 0 || len(result.Attempts) != 0 {
			t.Fatalf("invalid plan accepted: %+v err=%v", test, err)
		}
	}
}

type enrichmentDelayedListener struct {
	net.Listener
	delay time.Duration
}

func (listener enrichmentDelayedListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &enrichmentDelayedConn{Conn: conn, delay: listener.delay}, nil
}

type enrichmentDelayedConn struct {
	net.Conn
	delay time.Duration
	read  bool
}

func (conn *enrichmentDelayedConn) Read(data []byte) (int, error) {
	if !conn.read {
		conn.read = true
		time.Sleep(conn.delay)
	}
	return conn.Conn.Read(data)
}

func TestEnrichmentSupplementSlowTLSUsesOneLogicalRequest(t *testing.T) {
	var requested atomic.Int32
	target, _ := enrichmentFixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		requested.Add(1)
		fmt.Fprint(w, "slow TLS supplementary page")
	}, 600*time.Millisecond)
	var callbacks atomic.Int32
	callback, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			RequestSeq int  `json:"request_seq"`
			Wait       bool `json:"wait"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.RequestSeq != 1 {
			t.Errorf("invalid logical fetch identity: %+v", in)
		}
		if callbacks.Add(1) == 1 && !in.Wait {
			t.Error("first permission must be off-socket wait")
		}
		json.NewEncoder(w).Encode(map[string]int64{"valid_for_ms": 475, "waited_ms": 0})
	})
	input := enrichmentInput(target, "/supplement")
	input.Step = "supplement"
	input.MaxRequests = 1
	input.AdmissionURL = callback.URL
	input.AdmissionToken = "synthetic-local-token"
	result, err := probe(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	assertEnrichmentAccounting(t, result, 1)
	if result.Response.StatusCode != 200 || requested.Load() != 1 || result.Requests != 1 || callbacks.Load() != 2 {
		t.Fatalf("permission callbacks overcharged logical budget: requests=%d callbacks=%d result=%+v", requested.Load(), callbacks.Load(), result)
	}
	if result.Response.TLS == nil || result.Response.TLS.Source != "same_http_connection" {
		t.Fatal("slow TLS actual-connection evidence lost")
	}
}
