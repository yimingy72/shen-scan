package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanplatform/internal/rulelib"
	"scanplatform/internal/webevidence"
)

func TestRealWebProbeHelpers(t *testing.T) {
	binary := os.Getenv("TEST_WEB_PROBE_BINARY")
	fingerprint := os.Getenv("TEST_FINGERPRINT_BINARY")
	if binary == "" || fingerprint == "" {
		t.Skip("set TEST_WEB_PROBE_BINARY and TEST_FINGERPRINT_BINARY to built helpers")
	}
	t.Setenv("WEB_PROBE_BINARY", binary)
	t.Setenv("FINGERPRINT_WORKER_BINARY", fingerprint)
	t.Cleanup(func() { sharedFingerprints.stop() })
	if profile, bundle, _ := discoverWebCapabilities(); profile != webevidence.Profile || bundle != webevidence.FingerprintBundle {
		t.Fatalf("capability not verified: %s %s", profile, bundle)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx")
		w.Write([]byte(`<title>Agent Fixture</title>fixture-marker<meta name="generator" content="WordPress 6.4"><script src="/wp-includes/fixture.js"></script>`))
	}))
	defer server.Close()
	a := newHTTPXTestAgent(t, "unused")
	rules := []rulelib.Rule{httpxRule("fixture", "Fixture", true, `{"html":["fixture-marker"]}`)}
	var results []Observation
	payload := httpPayload{Endpoints: []Endpoint{{URL: server.URL + "/one", WorkKey: "one"}, {URL: server.URL + "/two", WorkKey: "two"}}, Rules: rules}
	if err := a.runWebProbe(context.Background(), Task{}, payload, binary, func(obs Observation) error { results = append(results, obs); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results: %d", len(results))
	}
	for _, obs := range results {
		if obs.Error != "" || obs.StatusCode != 200 || obs.WorkKey == "" || obs.Coverage != "complete" {
			t.Fatalf("incomplete observation: %+v", obs)
		}
		if !strings.Contains(obs.Evidence, "fingerprint") || len(obs.Technologies) == 0 {
			t.Fatal("matcher result/provenance missing")
		}
		var evidence struct {
			Fingerprint webevidence.MatchResult `json:"fingerprint"`
		}
		if err := json.Unmarshal([]byte(obs.Evidence), &evidence); err != nil {
			t.Fatal(err)
		}
		if len(evidence.Fingerprint.Bundle) != 64 || len(evidence.Fingerprint.Matches) == 0 {
			t.Fatal("fingers did not return bundle/hits")
		}
	}
}

func TestCompactProbeDoesNotDiscardMatcherInput(t *testing.T) {
	input := webevidence.ProbeResult{Response: webevidence.Response{Body: []byte("body")}, Icons: []webevidence.Response{{Body: []byte("icon")}}}
	persisted := compactProbe(input)
	if string(input.Icons[0].Body) != "icon" || string(input.Response.Body) != "body" {
		t.Fatal("persisted preview mutated live matcher input")
	}
	if persisted.Response.BodyStorage != "hash_only" || persisted.Icons[0].BodyStorage != "hash_only" || len(persisted.Icons[0].Body) != 0 {
		t.Fatal("persistence completeness not explicit")
	}
}

func TestWebProbeProcessReuseCancellationAndIdentity(t *testing.T) {
	binary := os.Getenv("TEST_WEB_PROBE_BINARY")
	if binary == "" {
		t.Skip("set TEST_WEB_PROBE_BINARY to built helper")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
		fmt.Fprint(w, "fixture")
	}))
	defer server.Close()
	process := webProbeProcess{slot: make(chan struct{}, 1)}
	defer process.stop()
	request := webevidence.ProbeRequest{Protocol: webevidence.Protocol, URL: server.URL, ConnectIP: "127.0.0.1", CFFSHA256: webevidence.SHA256(nil)}
	var pid int
	for _, id := range []string{"one", "two"} {
		request.ID = id
		raw, err := process.run(context.Background(), binary, request)
		if err != nil {
			t.Fatal(err)
		}
		var result webevidence.ProbeResult
		if json.Unmarshal(raw, &result) != nil || result.ID != id {
			t.Fatal("item identity lost")
		}
		if pid != 0 && process.cmd.Process.Pid != pid {
			t.Fatal("helper was restarted for a successful item")
		}
		pid = process.cmd.Process.Pid
	}
	request.ID = "cancelled"
	request.URL = server.URL + "/slow"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	_, err := process.run(ctx, binary, request)
	cancel()
	if err == nil || process.cmd != nil {
		t.Fatalf("cancel did not stop and reap process: %v", err)
	}
	request.ID = "after-cancel"
	request.URL = server.URL
	if _, err = process.run(context.Background(), binary, request); err != nil {
		t.Fatal(err)
	}
	if process.cmd.Process.Pid == pid {
		t.Fatal("cancelled process reused")
	}
	process.stop()
	t.Setenv("HTTP_BUDGET_TEST_SECRET", "must-not-inherit")
	bad := filepath.Join(t.TempDir(), "wrong-reply")
	script := `#!/bin/sh
if [ "$1" = "--capabilities" ]; then
 echo '{"request_admission":"loopback-v1","stream_protocol":"jsonl-item-v1"}'
 exit 0
fi
if [ -n "$HTTP_BUDGET_TEST_SECRET" ]; then exit 9; fi
read item
echo '{"protocol":"shen-web-v1","id":"wrong"}'
`
	if err = os.WriteFile(bad, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = process.run(context.Background(), bad, request); err == nil || !strings.Contains(err.Error(), "identity") || process.cmd != nil {
		t.Fatalf("unrelated envelope accepted or process retained: %v", err)
	}
	request.ID = "after-bad"
	if _, err = process.run(context.Background(), binary, request); err != nil {
		t.Fatalf("bad item poisoned next entry: %v", err)
	}
}

func TestWebProbePermitsTLSPageAndIcons(t *testing.T) {
	t.Cleanup(func() { sharedWebProbe.stop() })
	binary := os.Getenv("TEST_WEB_PROBE_BINARY")
	if binary == "" {
		t.Skip("set TEST_WEB_PROBE_BINARY to built helper")
	}
	var permits, requests atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<title>fixture</title><link rel="icon" href="/icon">`)
		} else {
			fmt.Fprint(w, "icon")
		}
	}))
	defer target.Close()
	a := newHTTPXTestAgent(t, "unused")
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permits.Add(1)
		now := time.Now().UTC()
		json.NewEncoder(w).Encode(map[string]any{"granted": true, "server_time": now, "valid_until": now.Add(500 * time.Millisecond)})
	}))
	defer central.Close()
	a.client.baseURL = central.URL
	ctx := a.withHTTPBudget(context.Background(), Task{ID: "fixture", AttemptNo: 1})
	parsed, _ := url.Parse(target.URL)
	admission, token, closeAdmission, err := startWebAdmission(ctx, "tls-page", "127.0.0.1", parsed, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAdmission()
	request := webevidence.ProbeRequest{ID: "tls-page", Protocol: webevidence.Protocol, URL: target.URL, ConnectIP: "127.0.0.1", CFFSHA256: webevidence.SHA256(nil), AdmissionURL: admission, AdmissionToken: token}
	input, _ := json.Marshal(request)
	output, err := runWebHelper(ctx, binary, input)
	if err != nil {
		t.Fatal(err)
	}
	var result webevidence.ProbeResult
	if json.Unmarshal(output, &result) != nil {
		t.Fatal("invalid helper response")
	}
	if result.Requests != 3 || requests.Load() != 3 || permits.Load() != 3 || result.Response.TLS == nil || result.Response.TLS.Source != "same_http_connection" {
		t.Fatalf("page/icon budget or actual TLS evidence lost: requests=%d permits=%d result=%+v", requests.Load(), permits.Load(), result)
	}
	request.AdmissionToken = "wrong-token"
	input, _ = json.Marshal(request)
	output, err = runWebHelper(ctx, binary, input)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(output, &result) != nil || result.Response.StatusCode != 0 || !strings.Contains(result.Response.Error, "HTTP admission") || requests.Load() != 3 || permits.Load() != 3 {
		t.Fatalf("denied helper callback emitted traffic: actual=%d permits=%d result=%+v", requests.Load(), permits.Load(), result)
	}
}
