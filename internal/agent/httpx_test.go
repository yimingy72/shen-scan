package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"scanplatform/internal/rulelib"
)

func TestBuildHTTPXCFFUsesOnlyEnabledApps(t *testing.T) {
	rules := []rulelib.Rule{
		httpxRule("httpx-enabled", "Enabled App", true, `{"html":["enabled-marker"]}`),
		httpxRule("httpx-disabled", "Disabled App", false, `{"html":["disabled-marker"]}`),
	}
	encoded, err := buildHTTPXCFF(rules)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Apps map[string]json.RawMessage `json:"apps"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Apps) != 1 || document.Apps["Enabled App"] == nil || document.Apps["Disabled App"] != nil {
		t.Fatalf("CFF apps = %#v, want only enabled product", document.Apps)
	}

	detected := httpxTechnologies([]string{"Enabled App:2.4", "Disabled App", "Unmanaged Builtin"}, rules)
	if len(detected) != 1 || detected[0].Name != "Enabled App" || detected[0].Version != "2.4" || detected[0].RuleID != "httpx-enabled" {
		t.Fatalf("filtered technologies = %#v", detected)
	}
}

func TestHTTPXPreservesCaseDistinctUpstreamApps(t *testing.T) {
	rules := []rulelib.Rule{
		httpxRule("one", "FastSpring", true, `{"html":["one"]}`),
		httpxRule("two", "Fastspring", true, `{"html":["two"]}`),
		httpxRule("three", "_hyperscript", true, `{}`),
		httpxRule("four", "_hyperscript ", true, `{}`),
	}
	data, err := buildHTTPXCFF(rules)
	if err != nil || !bytes.Contains(data, []byte(`"FastSpring"`)) || !bytes.Contains(data, []byte(`"Fastspring"`)) {
		t.Fatalf("case-distinct original apps were lost: %s %v", data, err)
	}
	rules[0].Enabled = false
	if got := httpxTechnologies([]string{"FastSpring"}, rules); len(got) != 0 {
		t.Fatalf("disabled case-distinct app leaked: %+v", got)
	}
}

func TestRuleSetCacheKeepsImmutableHTTPXCFF(t *testing.T) {
	cache := newRuleSetCache(8)
	rules := []rulelib.Rule{httpxRule("httpx-fixture", "Fixture", true, `{"html":["fixture-marker"]}`)}
	cache.add("run:http", rules)
	rules[0].Fingerprint[0] = 'x'
	first, ok := cache.cff("run:http")
	if !ok || !bytes.Contains(first, []byte("fixture-marker")) {
		t.Fatalf("cached CFF = %q", first)
	}
	first[0] = 'x'
	second, ok := cache.cff("run:http")
	if !ok || len(second) == 0 || second[0] != '{' {
		t.Fatalf("cached CFF was mutable: %q", second)
	}
	cachedRules, ok := cache.get("run:http")
	if !ok || !bytes.Contains(cachedRules[0].Fingerprint, []byte("fixture-marker")) {
		t.Fatalf("cached fingerprint was mutable: %#v", cachedRules)
	}
}

func TestHTTPXJSONLWriterHandlesChunkedLines(t *testing.T) {
	var lines []string
	writer := &httpxJSONLWriter{handle: func(line []byte) error {
		lines = append(lines, string(line))
		return nil
	}}
	for _, chunk := range []string{"{\"url\":", "\"http://one\"}\n{\"url\":", "\"http://two\"}"} {
		if _, err := writer.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.finish(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(lines) != `[{"url":"http://one"} {"url":"http://two"}]` {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestHTTPXScopeProxyAllowsOnlyAssignedOrigin(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = fmt.Fprint(response, "fixture")
	}))
	defer fixture.Close()
	agent := newHTTPXTestAgent(t, "unused")
	targets, err := prepareHTTPXTargets(context.Background(), agent, []Endpoint{{URL: fixture.URL}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxy, err := agent.startHTTPXScopeProxy(ctx, targets)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: time.Second}
	response, err := client.Get(fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("assigned origin status = %d", response.StatusCode)
	}
	response, err = client.Get("http://outside.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || proxy.Err() == nil {
		t.Fatalf("outside origin status=%d proxy error=%v", response.StatusCode, proxy.Err())
	}
}

func TestHTTPXCancellationKillsProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	script := filepath.Join(t.TempDir(), "httpx-fixture")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30 &\nwait\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	agent := newHTTPXTestAgent(t, script)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	err := agent.runHTTPX(ctx, []Endpoint{{URL: "http://127.0.0.1:18099"}}, []rulelib.Rule{httpxRule("httpx-fixture", "Fixture", true, `{}`)}, []byte(`{"apps":{"Fixture":{}}}`), time.Second, func(Observation) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runHTTPX cancellation error = %v", err)
	}
}

func TestRealHTTPXCFFDiscovery(t *testing.T) {
	binary := os.Getenv("TEST_HTTPX_BINARY")
	if binary == "" {
		t.Skip("set TEST_HTTPX_BINARY to the official httpx executable")
	}
	newFixture := func(title string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Server", "ShenFixture/2.4")
			_, _ = fmt.Fprintf(response, `<html><head><title>%s</title><meta name="generator" content="WordPress 6.4"></head><body>shen-httpx-marker</body></html>`, title)
		}))
	}
	first := newFixture("HTTPx Fixture One")
	defer first.Close()
	second := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Server", "ShenFixture/2.4")
		_, _ = fmt.Fprint(response, `<html><title>HTTPx Fixture Two</title>shen-httpx-marker</html>`)
	}))
	defer second.Close()
	enabled := httpxRule("httpx-shen-fixture", "Shen Fixture", true, `{"headers":{"server":"ShenFixture\\/([0-9.]+)\\;version:\\1"}}`)
	disabledBuiltin := httpxRule("httpx-wordpress", "WordPress", false, `{}`)
	payload, err := json.Marshal(httpPayload{Endpoints: []Endpoint{{URL: first.URL + "/one"}, {URL: first.URL + "/two"}, {URL: second.URL}}, Rules: []rulelib.Rule{enabled, disabledBuiltin}})
	if err != nil {
		t.Fatal(err)
	}
	agent := newHTTPXTestAgent(t, binary)
	var observations []Observation
	if err := agent.runHTTP(context.Background(), Task{Payload: payload}, func(observation Observation) error {
		observations = append(observations, observation)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(observations) != 3 {
		t.Fatalf("observations = %d, want 3 from one batched process", len(observations))
	}
	titles := make(map[string]bool)
	identities := make(map[string]bool)
	for _, got := range observations {
		titles[got.Title] = true
		identities[got.Target] = true
		if got.StatusCode != http.StatusOK || got.Error != "" || got.RequestRaw == "" || got.ResponseRaw == "" {
			t.Fatalf("httpx observation = %#v", got)
		}
		if len(got.Technologies) != 1 || got.Technologies[0].Name != "Shen Fixture" || got.Technologies[0].Version != "2.4" {
			t.Fatalf("enabled-only technologies = %#v", got.Technologies)
		}
		if strings.Contains(strings.ToLower(fmt.Sprint(got.Technologies)), "wordpress") {
			t.Fatalf("disabled built-in technology leaked into result: %#v", got.Technologies)
		}
		parsed, _ := url.Parse(got.URL)
		if !strings.Contains(got.RequestRaw, "GET "+parsed.RequestURI()+" HTTP/") || !strings.Contains(got.ResponseRaw, "shen-httpx-marker") {
			t.Fatalf("raw evidence missing: request=%q response=%q", got.RequestRaw, got.ResponseRaw)
		}
	}
	if !titles["HTTPx Fixture One"] || !titles["HTTPx Fixture Two"] {
		t.Fatalf("batched titles = %#v", titles)
	}
	if !identities[first.URL+"/one"] || !identities[first.URL+"/two"] || !identities[second.URL] {
		t.Fatalf("original endpoint identities were lost: %#v", identities)
	}
}

func TestHTTPXDefaultPortsAndInputIdentity(t *testing.T) {
	agent := newHTTPXTestAgent(t, "unused")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	targets, err := prepareHTTPXTargets(ctx, agent, []Endpoint{{URL: "http://127.0.0.1/one"}, {URL: "http://127.0.0.1/two"}, {URL: "https://127.0.0.1/"}})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := agent.startHTTPXScopeProxy(ctx, targets)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	for _, authority := range []string{"127.0.0.1:80", "127.0.0.1:443"} {
		if _, ok := proxy.dial[authority]; !ok {
			t.Fatalf("missing effective default port: %s", authority)
		}
	}
	for _, target := range targets {
		got, ok := proxy.Target(target.url.String())
		if !ok || got.endpoint.URL != target.endpoint.URL {
			t.Fatalf("lost input identity for %s", target.url)
		}
	}
}

func TestHTTPXEmptyOutputDoesNotCompleteTask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	script := filepath.Join(t.TempDir(), "httpx-empty")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	agent := newHTTPXTestAgent(t, script)
	err := agent.runHTTPX(context.Background(), []Endpoint{{URL: "http://127.0.0.1:18099"}}, []rulelib.Rule{httpxRule("fixture", "Fixture", true, `{}`)}, []byte(`{"apps":{"Fixture":{}}}`), time.Second, func(Observation) error { t.Fatal("unexpected output"); return nil })
	var taskError *TaskError
	if !errors.As(err, &taskError) || !taskError.Retryable || !strings.Contains(taskError.Reason, "0 of 1") {
		t.Fatalf("empty result incorrectly completed: %v", err)
	}
}

func httpxRule(id, product string, enabled bool, fingerprint string) rulelib.Rule {
	return rulelib.Rule{
		ID: id, Kind: "http", Purpose: "discovery", Name: product, Engine: "httpx-cff", Severity: "info", Enabled: enabled, Revision: 1,
		Definition: rulelib.Definition{Service: "http", Product: product}, Fingerprint: json.RawMessage(fingerprint),
	}
}

func newHTTPXTestAgent(t *testing.T, binary string) *Agent {
	t.Helper()
	agent, err := New(Config{
		ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test",
		AllowPrivateTargets: true, HTTPXBinary: binary, HTTPXMaxProcesses: 2, HTTPXThreads: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	allowHTTPFixture(t, agent)
	t.Cleanup(func() { agent.stopWebProbes(); agent.fingerprints.stop() })
	return agent
}

func TestHTTPXRawResponseIsParseable(t *testing.T) {
	raw := httpxRawResponse(httpxResult{StatusCode: 200, RawHeader: "Server: fixture\r\nContent-Length: 2\r\n", Body: "ok"})
	if !bytes.HasPrefix([]byte(raw), []byte("HTTP/1.1 200 OK\r\n")) || !strings.HasSuffix(raw, "\r\n\r\nok") {
		t.Fatalf("raw response = %q", raw)
	}
}
