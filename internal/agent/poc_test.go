package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"scanplatform/internal/rulelib"
)

func TestManagedFingerprintRules(t *testing.T) {
	httpRule := rulelib.Rule{
		ID: "test-http", Kind: "http", Name: "managed", Engine: "native", Severity: "info", Enabled: true, Revision: 1,
		Definition: rulelib.Definition{Product: "ManagedHTTP", Condition: "and", Matchers: []rulelib.Matcher{{
			Part: "body", Type: "word", Words: []string{"managed-marker"}, Condition: "or", CaseSensitive: true,
		}}},
	}
	obs := Observation{httpBody: "managed-marker", StatusCode: 200}
	technologies := matchHTTPRules([]rulelib.Rule{httpRule}, obs)
	if len(technologies) != 1 || technologies[0].Name != "ManagedHTTP" || technologies[0].RuleID != httpRule.ID {
		t.Fatalf("managed HTTP rule did not produce attributed technology: %#v", technologies)
	}
	if got := matchHTTPRules([]rulelib.Rule{httpRule, httpRule}, obs); len(got) != 1 {
		t.Fatal("duplicate product rules duplicated the technology")
	}
	negative := httpRule
	negative.Definition.Matchers = []rulelib.Matcher{{Part: "body", Type: "word", Words: []string{"absent-marker"}, Negative: true}}
	if got := matchHTTPRules([]rulelib.Rule{negative}, Observation{}); len(got) != 0 {
		t.Fatal("failed HTTP exchange was identified by an absence")
	}
	if got := matchHTTPRules([]rulelib.Rule{negative}, Observation{StatusCode: 200, Truncated: true}); len(got) != 0 {
		t.Fatal("truncated response was identified by an absence")
	}
	httpRule.Enabled = false
	if got := matchHTTPRules([]rulelib.Rule{httpRule}, obs); len(got) != 0 {
		t.Fatalf("disabled HTTP rule still matched: %#v", got)
	}

	portRule := findBuiltinRule(t, "port-nginx")
	service := Observation{Service: "http", Product: "nginx", Version: "1.27"}
	applyPortRules([]rulelib.Rule{portRule}, &service)
	if service.Product != "nginx" || service.Version != "1.27" || service.RuleID != portRule.ID {
		t.Fatalf("managed port rule did not retain parsed version: %#v", service)
	}
	portRule.Enabled = false
	service = Observation{Service: "http", Product: "nginx", Version: "1.27"}
	applyPortRules([]rulelib.Rule{portRule}, &service)
	if service.Service != "http" || service.Product != "" || service.Version != "" {
		t.Fatalf("disabled product rule leaked product identity: %#v", service)
	}
}

func TestNativePoCAndMissingNucleiAreDistinctOutcomes(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/.git/HEAD" {
			http.NotFound(w, request)
			return
		}
		fmt.Fprintln(w, "ref: refs/heads/main")
	}))
	defer fixture.Close()
	a, err := New(Config{
		ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test",
		AllowPrivateTargets: true, NucleiBinary: t.TempDir() + "/missing-nuclei",
	})
	if err != nil {
		t.Fatal(err)
	}
	run := func(rule rulelib.Rule) Observation {
		payload, _ := json.Marshal(pocPayload{Endpoint: Endpoint{URL: fixture.URL}, Rules: []rulelib.Rule{rule}})
		var got Observation
		if err := a.runPoC(context.Background(), Task{Payload: payload}, func(obs Observation) error { got = obs; return nil }); err != nil {
			t.Fatal(err)
		}
		return got
	}
	matched := run(findBuiltinRule(t, "poc-exposed-git-head"))
	if matched.FindingStatus != "matched" || matched.Error != "" || !strings.Contains(matched.RequestRaw, "GET /.git/HEAD") || !strings.Contains(matched.ResponseRaw, "ref: refs/heads/main") {
		t.Fatalf("unexpected native PoC outcome: %#v", matched)
	}
	nuclei := run(findBuiltinRule(t, "poc-security-txt"))
	if nuclei.FindingStatus != "error" || !strings.Contains(nuclei.Error, "was not found") {
		t.Fatalf("missing Nuclei was not reported as an execution error: %#v", nuclei)
	}
}

func TestNativePoCTruncatedResponseIsIncomplete(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxHTTPBody+1))
	}))
	defer fixture.Close()
	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(pocPayload{Endpoint: Endpoint{URL: fixture.URL}, Rules: []rulelib.Rule{findBuiltinRule(t, "poc-exposed-git-head")}})
	var got Observation
	if err := a.runPoC(context.Background(), Task{Payload: payload}, func(obs Observation) error { got = obs; return nil }); err != nil {
		t.Fatal(err)
	}
	if got.FindingStatus != "error" || !got.Truncated || !strings.Contains(got.Error, "read limit") {
		t.Fatalf("truncated response was treated as a complete negative: %#v", got)
	}
}

func TestScopeProxyRejectsUnvalidatedPath(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer fixture.Close()
	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxy, err := a.startScopeProxy(ctx, Endpoint{URL: fixture.URL}, fixture.URL, []rulelib.Request{{Method: "GET", Path: "/ok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL())
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get(fixture.URL + "/bad")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || proxy.Err() == nil {
		t.Fatalf("out-of-scope request was not rejected: status=%d error=%v", response.StatusCode, proxy.Err())
	}
}

func TestRealNucleiPoC(t *testing.T) {
	binary := os.Getenv("TEST_NUCLEI_BINARY")
	if binary == "" {
		t.Skip("set TEST_NUCLEI_BINARY to the official Nuclei executable")
	}
	for _, test := range []struct {
		name    string
		tls     bool
		contact bool
		want    string
	}{
		{name: "http matched", contact: true, want: "matched"},
		{name: "http not matched", want: "not_matched"},
		{name: "https matched", tls: true, contact: true, want: "matched"},
		{name: "https not matched", tls: true, want: "not_matched"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/.well-known/security.txt" || !test.contact {
					http.NotFound(w, request)
					return
				}
				fmt.Fprintln(w, "Contact: mailto:security@example.test")
			})
			fixture := httptest.NewServer(handler)
			if test.tls {
				fixture.Close()
				fixture = httptest.NewTLSServer(handler)
			}
			defer fixture.Close()
			a, err := New(Config{
				ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test",
				AllowPrivateTargets: true, NucleiBinary: binary,
			})
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(pocPayload{Endpoint: Endpoint{URL: fixture.URL}, Rules: []rulelib.Rule{findBuiltinRule(t, "poc-security-txt")}})
			var got Observation
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := a.runPoC(ctx, Task{Payload: payload}, func(obs Observation) error { got = obs; return nil }); err != nil {
				t.Fatal(err)
			}
			if got.FindingStatus != test.want || got.Error != "" || got.RequestRaw == "" || got.ResponseRaw == "" {
				t.Fatalf("real Nuclei outcome = %#v, want status %s with raw evidence", got, test.want)
			}
			if !strings.Contains(got.RequestRaw, "GET /.well-known/security.txt HTTP/1.1") {
				t.Fatalf("Nuclei request evidence is incomplete: %q", got.RequestRaw)
			}
			wantResponse := "HTTP/1.1 404 Not Found"
			if test.contact {
				wantResponse = "HTTP/1.1 200 OK"
			}
			if !strings.Contains(got.ResponseRaw, wantResponse) {
				t.Fatalf("Nuclei response evidence is incomplete: %q", got.ResponseRaw)
			}
		})
	}
}

func TestRealNucleiRootPoC(t *testing.T) {
	binary := os.Getenv("TEST_NUCLEI_BINARY")
	if binary == "" {
		t.Skip("set TEST_NUCLEI_BINARY to the official Nuclei executable")
	}
	rootRule := rootNucleiRule(t)
	for _, test := range []struct {
		name, want string
		tls, match bool
	}{
		{name: "http matched", match: true, want: "matched"},
		{name: "http negative", want: "not_matched"},
		{name: "https matched", tls: true, match: true, want: "matched"},
		{name: "https negative", tls: true, want: "not_matched"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/" {
					t.Errorf("Nuclei requested unexpected path %q", request.URL.Path)
				}
				if test.match {
					_, _ = io.WriteString(response, "Root Fixture Management Console")
				} else {
					_, _ = io.WriteString(response, "generic page")
				}
			})
			fixture := httptest.NewServer(handler)
			if test.tls {
				fixture.Close()
				fixture = httptest.NewTLSServer(handler)
			}
			defer fixture.Close()
			agent, err := New(Config{
				ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test",
				AllowPrivateTargets: true, NucleiBinary: binary,
			})
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(pocPayload{Endpoint: Endpoint{URL: fixture.URL}, Rules: []rulelib.Rule{rootRule}})
			var got Observation
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := agent.runPoC(ctx, Task{Payload: payload}, func(observation Observation) error { got = observation; return nil }); err != nil {
				t.Fatal(err)
			}
			if got.FindingStatus != test.want || got.Error != "" || !strings.Contains(got.RequestRaw, "GET / HTTP/1.1") || !strings.Contains(got.ResponseRaw, "HTTP/1.1 200 OK") {
				t.Fatalf("root PoC outcome = %#v, want %s with root request evidence", got, test.want)
			}
		})
	}
}

func TestNucleiTruncationRejectsNegativeBodyMatcher(t *testing.T) {
	base, _ := url.Parse("https://fixture.invalid")
	proxy := &scopeProxy{
		base: base, allowedPaths: map[string]bool{"/": true},
		requestCount: 1, truncated: true,
	}
	matched := true
	event, _ := json.Marshal(nucleiEvent{
		TemplateID: "negative-body", MatchedAt: "https://fixture.invalid", MatcherStatus: &matched,
		Request:  "GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	})
	rule := rulelib.Rule{
		ID: "negative-body",
		Definition: rulelib.Definition{Requests: []rulelib.Request{{Matchers: []rulelib.Matcher{{
			Part: "body", Type: "word", Words: []string{"error"}, Negative: true,
		}}}}},
	}
	got := nucleiOutcome(Observation{}, rule, append(event, '\n'), proxy)
	if got.FindingStatus != "error" || !strings.Contains(got.Error, "negative body matcher") {
		t.Fatalf("truncated negative-body match was trusted: %#v", got)
	}
	rule.Definition.Requests[0].Matchers[0].Negative = false
	got = nucleiOutcome(Observation{}, rule, append(event, '\n'), proxy)
	if got.FindingStatus != "matched" || got.Error != "" {
		t.Fatalf("positive match was rejected only because evidence was truncated: %#v", got)
	}
}

func rootNucleiRule(t *testing.T) rulelib.Rule {
	t.Helper()
	const template = `id: root-fixture
info:
  name: Root Fixture Panel
  author: SHEN
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}'
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words:
          - Root Fixture Management Console
`
	rule, err := rulelib.ParseNuclei(template)
	if err != nil {
		t.Fatal(err)
	}
	rule.Enabled = true
	return rule
}

func findBuiltinRule(t *testing.T, id string) rulelib.Rule {
	t.Helper()
	for _, rule := range rulelib.Builtins() {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("missing built-in rule %s", id)
	return rulelib.Rule{}
}
