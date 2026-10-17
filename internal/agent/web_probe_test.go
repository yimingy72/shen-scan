package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

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
