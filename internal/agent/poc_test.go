package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
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
	if matched.FindingStatus != "matched" || matched.Error != "" || !strings.Contains(matched.RequestRaw, "GET /.git/HEAD") || !strings.Contains(matched.ResponseRaw, "ref: refs/heads/main") || len(matched.Checks) != 1 || !strings.Contains(matched.Checks[0].RequestRaw, "GET /.git/HEAD") {
		t.Fatalf("unexpected native PoC outcome: %#v", matched)
	}
	nuclei := run(findBuiltinRule(t, "poc-security-txt"))
	if nuclei.FindingStatus != "error" || !strings.Contains(nuclei.Error, "was not found") {
		t.Fatalf("missing Nuclei was not reported as an execution error: %#v", nuclei)
	}
}

func TestNativePoCChecksArePerRequestAndComplete(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = fmt.Fprintf(response, "marker:%s", request.URL.Path)
	}))
	defer fixture.Close()
	agent, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := pocBaseURL(Endpoint{URL: fixture.URL})
	rule := rulelib.Rule{Kind: "poc", Engine: "native", Definition: rulelib.Definition{Condition: "and", Requests: []rulelib.Request{
		{Method: "GET", Path: "/one", Condition: "and", Matchers: []rulelib.Matcher{{Part: "body", Type: "word", Words: []string{"marker:/one"}}}},
		{Method: "GET", Path: "/two", Condition: "and", Matchers: []rulelib.Matcher{{Part: "body", Type: "word", Words: []string{"marker:/two"}}}},
	}}}
	got := agent.runNativePoC(context.Background(), Endpoint{URL: fixture.URL}, base, rule, Observation{})
	if got.FindingStatus != "matched" || len(got.Checks) != 2 {
		t.Fatalf("missing native checks: %#v", got)
	}
	if !strings.Contains(got.Checks[0].RequestRaw, "GET /one HTTP/1.1") || strings.Contains(got.Checks[0].RequestRaw, "GET /two") ||
		!strings.Contains(got.Checks[0].ResponseRaw, "marker:/one") || strings.Contains(got.Checks[0].ResponseRaw, "marker:/two") {
		t.Fatalf("first check contains concatenated or wrong evidence: %#v", got.Checks[0])
	}
	if !strings.Contains(got.Checks[1].RequestRaw, "GET /two HTTP/1.1") || !strings.Contains(got.Checks[1].ResponseRaw, "marker:/two") {
		t.Fatalf("second check is incomplete: %#v", got.Checks[1])
	}
}

func TestVerificationRejectsLegacyEvidenceTruncation(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(response, "verification-marker"+strings.Repeat("x", maxRawResponse))
	}))
	defer fixture.Close()
	agent, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := pocBaseURL(Endpoint{URL: fixture.URL})
	rule := rulelib.Rule{Kind: "poc", Engine: "native", Purpose: "verification", Definition: rulelib.Definition{Requests: []rulelib.Request{{
		Method: "GET", Path: "/", Matchers: []rulelib.Matcher{{Part: "body", Type: "word", Words: []string{"verification-marker"}}},
	}}}}
	got := agent.runNativePoC(context.Background(), Endpoint{URL: fixture.URL}, base, rule, Observation{})
	if got.FindingStatus != "error" || !got.Truncated || !strings.Contains(got.Error, "incomplete or truncated") || len(got.Checks) != 1 {
		t.Fatalf("verification trusted truncated evidence: %#v", got)
	}
}

func TestNativeReviewedRequestURIPreservesOriginAndBytes(t *testing.T) {
	requests := 0
	var requestURI, requestHost string
	fixture := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		requestURI, requestHost = request.RequestURI, request.Host
		response.Header().Set("Location", "https://must-not-follow.invalid/")
		response.WriteHeader(http.StatusFound)
	}))
	defer fixture.Close()
	agent, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := pocBaseURL(Endpoint{URL: fixture.URL})
	definition := rulelib.Request{Method: "GET", Path: "//shen-open-redirect.invalid/%2e%2e/probe?fixed=1"}
	input, requestRaw, _, _, err := agent.nativePoCRequest(context.Background(), Endpoint{URL: fixture.URL}, base, definition)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || input.Status != http.StatusFound || requestHost != strings.TrimPrefix(fixture.URL, "http://") || requestURI != definition.Path || !strings.Contains(requestRaw, "GET "+definition.Path+" HTTP/1.1") {
		t.Fatalf("reviewed URI changed origin or bytes: count=%d host=%q uri=%q raw=%q", requests, requestHost, requestURI, requestRaw)
	}
	if _, err := nativeRequestURL(base, "https://escape.invalid/path"); err == nil {
		t.Fatal("absolute reviewed URI escaped the endpoint origin")
	}
}

func TestReviewedVerificationsProduceCompleteChecks(t *testing.T) {
	rules := rulelib.ReviewedVerifications()
	if len(rules) != 11 {
		t.Fatalf("reviewed verification count = %d, want 11", len(rules))
	}
	for _, rule := range rules {
		rule := rule
		t.Run(rule.ID, func(t *testing.T) {
			if err := rulelib.Validate(rule); err != nil {
				t.Fatalf("reviewed rule is invalid: %v", err)
			}
			for _, positive := range []bool{true, false} {
				name := "negative"
				wantStatus := "not_matched"
				if positive {
					name = "positive"
					wantStatus = "matched"
				}
				t.Run(name, func(t *testing.T) {
					var receivedURIs, receivedHosts []string
					fixture := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
						receivedURIs = append(receivedURIs, request.RequestURI)
						receivedHosts = append(receivedHosts, request.Host)
						definition := rule.Definition.Requests[len(receivedURIs)-1]
						if request.RequestURI != definition.Path {
							t.Errorf("request URI = %q, want exact reviewed URI %q", request.RequestURI, definition.Path)
						}
						writeVerificationFixture(response, rule, definition, positive)
					}))
					defer fixture.Close()

					agent, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
					if err != nil {
						t.Fatal(err)
					}
					payload, err := json.Marshal(pocPayload{Endpoint: Endpoint{URL: fixture.URL}, Rules: []rulelib.Rule{rule}})
					if err != nil {
						t.Fatal(err)
					}
					var got Observation
					if err := agent.runPoC(context.Background(), Task{Payload: payload}, func(observation Observation) error {
						got = observation
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					if got.FindingStatus != wantStatus || got.Error != "" || got.Truncated {
						t.Fatalf("verification outcome = %#v, want %s with complete evidence", got, wantStatus)
					}
					if len(got.Checks) != len(rule.Definition.Requests) || len(receivedURIs) != len(rule.Definition.Requests) {
						t.Fatalf("checks=%d requests=%d, want %d", len(got.Checks), len(receivedURIs), len(rule.Definition.Requests))
					}
					wantHost := strings.TrimPrefix(fixture.URL, "http://")
					for index, definition := range rule.Definition.Requests {
						if receivedURIs[index] != definition.Path || receivedHosts[index] != wantHost {
							t.Fatalf("request %d escaped or changed: host=%q uri=%q", index+1, receivedHosts[index], receivedURIs[index])
						}
						input := parseCheckEvidence(t, got.Checks[index], wantHost, definition)
						wantRequestMatch := positive || definition.Role == "control"
						if matched := rulelib.MatchRequest(definition, input); matched != wantRequestMatch {
							t.Fatalf("request %d role=%s matcher result=%t, want %t", index+1, definition.Role, matched, wantRequestMatch)
						}
					}
				})
			}
		})
	}
}

func writeVerificationFixture(response http.ResponseWriter, rule rulelib.Rule, request rulelib.Request, positive bool) {
	if !positive || request.Role == "control" {
		response.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(response, "fixture control response")
		return
	}
	if rule.Verification.Category == "file_read" {
		_, _ = io.WriteString(response, "NAME=FixtureOS\nID=fixture\n")
		return
	}
	location := "//shen-verify.invalid"
	if rule.ID == "nv-cve-2025-4123" {
		location = "/\\shen-verify.invalid/?/../../"
	}
	response.Header().Set("Location", location)
	response.WriteHeader(http.StatusFound)
}

func parseCheckEvidence(t *testing.T, check rulelib.CheckEvidence, wantHost string, definition rulelib.Request) rulelib.Input {
	t.Helper()
	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(check.RequestRaw)))
	if err != nil {
		t.Fatalf("parse request evidence: %v\n%s", err, check.RequestRaw)
	}
	if request.Method != definition.Method || request.RequestURI != definition.Path || request.Host != wantHost {
		t.Fatalf("request evidence changed: method=%q host=%q uri=%q", request.Method, request.Host, request.RequestURI)
	}
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(check.ResponseRaw)), request)
	if err != nil {
		t.Fatalf("parse response evidence: %v\n%s", err, check.ResponseRaw)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response evidence: %v", err)
	}
	var headers strings.Builder
	if err := response.Header.Write(&headers); err != nil {
		t.Fatal(err)
	}
	return rulelib.Input{Body: string(body), Header: headers.String(), Status: response.StatusCode}
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
	got := nucleiOutcome(Observation{}, rule, rule.ID, append(event, '\n'), proxy, hasNegativeBodyMatcher(rule))
	if got.FindingStatus != "error" || !strings.Contains(got.Error, "negative body matcher") {
		t.Fatalf("truncated negative-body match was trusted: %#v", got)
	}
	rule.Definition.Requests[0].Matchers[0].Negative = false
	got = nucleiOutcome(Observation{}, rule, rule.ID, append(event, '\n'), proxy, hasNegativeBodyMatcher(rule))
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

func TestNucleiOriginalExecutionStates(t *testing.T) {
	binary := os.Getenv("NUCLEI_TEST_BINARY")
	if binary == "" {
		t.Skip("NUCLEI_TEST_BINARY is not set")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/health" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "shen-local-fixture-ready")
	}))
	baseURL, err := url.Parse(server.URL + "/app")
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(baseURL.Port())
	endpoint := Endpoint{IP: "127.0.0.1", Port: port, URL: baseURL.String()}
	agent := &Agent{cfg: Config{NucleiBinary: binary}, policy: targetPolicy{allowPrivate: true}}
	run := func(template string) Observation {
		rule, err := rulelib.ParseNucleiOriginal(template)
		if err != nil {
			t.Fatal(err)
		}
		base, err := pocOriginalBaseURL(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return agent.runNucleiPoC(ctx, endpoint, base, rule, newPoCObservation(endpoint, base, rule))
	}
	matched := run("id: local-match\ninfo:\n  name: Local match\n  author: shen\n  severity: info\n  metadata:\n    product: ShenFixtureApp\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/health\"]\n    matchers:\n      - type: status\n        status: [200]\n      - type: word\n        part: body\n        words: [\"shen-local-fixture-ready\"]\n")
	if matched.FindingStatus != "matched" || !strings.Contains(matched.RequestRaw, "GET /app/health") || !strings.Contains(matched.ResponseRaw, "shen-local-fixture-ready") {
		t.Fatalf("unexpected matched result: %#v", matched)
	}
	notMatched := run("id: local-miss\ninfo:\n  name: Local miss\n  author: shen\n  severity: info\n  metadata:\n    product: ShenFixtureApp\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/health\"]\n    matchers:\n      - type: word\n        part: body\n        words: [\"not-present-marker\"]\n")
	if notMatched.FindingStatus != "not_matched" {
		t.Fatalf("unexpected not_matched result: %#v", notMatched)
	}
	server.Close()
	failed := run("id: local-error\ninfo:\n  name: Local error\n  author: shen\n  severity: info\n  metadata:\n    product: ShenFixtureApp\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/health\"]\n    matchers:\n      - type: status\n        status: [200]\n")
	if failed.FindingStatus != "error" {
		t.Fatalf("unexpected error result: %#v", failed)
	}
}
