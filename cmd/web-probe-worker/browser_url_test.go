package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"scanplatform/internal/webevidence"
)

func TestBrowserCanonicalNavigationURL(t *testing.T) {
	requireBrowserIntegration(t)
	defer closeBrowserRuntime()
	var targetHits, permitCalls atomic.Int32
	const document = `<html><head><link rel="icon" href="data:,"></head><body>Canonical browser URL fixture<script>window.CanonicalFixture={version:'3.2.1'};</script></body></html>`
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, document)
	}))
	defer fixture.Close()
	reject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permitCalls.Add(1)
		var frame struct {
			URL string `json:"url"`
		}
		if json.NewDecoder(r.Body).Decode(&frame) != nil || frame.URL != "http://FiXtUrE.TeSt:80" {
			t.Errorf("nil-seed changed fixed target: %q", frame.URL)
		}
		w.WriteHeader(403)
	}))
	defer reject.Close()
	evidence := map[string]any{}
	for _, test := range []struct{ raw, canonical string }{
		{"http://FiXtUrE.TeSt:80", "http://fixture.test/"},
		{"https://FiXtUrE.TeSt:443", "https://fixture.test/"},
		{"http://FiXtUrE.TeSt", "http://fixture.test/"},
		{"http://FiXtUrE.TeSt:80/sub?q=1", "http://fixture.test/sub?q=1"},
	} {
		t.Run(test.raw, func(t *testing.T) {
			input := browserRunInput{Request: webevidence.ProbeRequest{ID: "canonical-seed", Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, URL: test.raw, ConnectIP: "127.0.0.1", Host: "fixed.original.host:80", SNI: "Fixed.Original.SNI", MaxRequests: 2, AdmissionURL: reject.URL, AdmissionToken: "synthetic-never-permit"}, Seed: webevidence.Response{URL: test.raw, StatusCode: 200, Headers: http.Header{"Content-Type": {"text/html"}}, Body: []byte(document), Completeness: "full", DecodedBytes: len(document), BodySHA256: webevidence.SHA256([]byte(document))}, Eval: `() => ({href:location.href,version:CanonicalFixture.version})`}
			input.Screenshot = test.raw == "http://FiXtUrE.TeSt:80"
			original := input.Request
			result, err := runBrowser(context.Background(), input)
			if err != nil || result.Partial || result.JSDOMError != "" || len(result.Attempts) != 0 {
				t.Fatalf("canonical seed failed: %v %+v", err, result)
			}
			var observed struct {
				Href    string `json:"href"`
				Version string `json:"version"`
			}
			if json.Unmarshal(result.Observation, &observed) != nil || observed.Href != test.canonical || observed.Version != "3.2.1" {
				t.Fatalf("wrong canonical document: %s", result.Observation)
			}
			if input.Request.URL != original.URL || input.Request.Host != original.Host || input.Request.SNI != original.SNI || input.Request.Identity != original.Identity {
				t.Fatal("browser normalization mutated fixed Go identity")
			}
			if input.Screenshot {
				if result.Screenshot == nil || result.Screenshot.State != "complete" || len(result.Screenshot.PNG) == 0 {
					t.Fatal("canonical default-port screenshot failed")
				}
				if folder := os.Getenv("CANONICAL_URL_EVIDENCE_DIR"); folder != "" {
					os.MkdirAll(filepath.Join(folder, "screenshots"), 0700)
					os.WriteFile(filepath.Join(folder, "screenshots", "canonical-default80.png"), result.Screenshot.PNG, 0600)
				}
			}
			evidence[test.raw] = observed
			t.Logf("original=%s browser=%s seed reused, target HTTP=0", test.raw, observed.Href)
		})
	}
	if permitCalls.Load() != 0 || targetHits.Load() != 0 {
		t.Fatal("complete seed unexpectedly caused HTTP recollection")
	}
	// No listener is bound to80/443. A missing seed must ask the original scoped
	// admission URL before any dial; refusal prevents touching an unrelated port.
	denied, err := runBrowser(context.Background(), browserRunInput{Request: webevidence.ProbeRequest{ID: "canonical-no-seed", Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, URL: "http://FiXtUrE.TeSt:80", ConnectIP: "127.0.0.1", Host: "fixed.original.host:80", SNI: "Fixed.Original.SNI", MaxRequests: 1, AdmissionURL: reject.URL, AdmissionToken: "synthetic-never-permit"}, Eval: `() => ({})`})
	if err == nil || !strings.Contains(err.Error(), "403") || permitCalls.Load() != 1 || len(denied.Attempts) != 1 || denied.Attempts[0].URL != "http://FiXtUrE.TeSt:80" {
		t.Fatalf("nil-seed admission escaped original target: %v %+v permits=%d", err, denied, permitCalls.Load())
	}
	// A permitted nil-seed recollection still uses the original non-default local
	// origin (not the Chrome canonical location) and consumes exactly one grant.
	var grants atomic.Int32
	allow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants.Add(1)
		var frame struct {
			URL string `json:"url"`
		}
		json.NewDecoder(r.Body).Decode(&frame)
		if frame.URL != fixture.URL {
			t.Errorf("nil seed URL changed: %s", frame.URL)
		}
		fmt.Fprint(w, `{"valid_for_ms":475,"waited_ms":0}`)
	}))
	defer allow.Close()
	recollected, err := runBrowser(context.Background(), browserRunInput{Request: webevidence.ProbeRequest{ID: "canonical-recollect", Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, URL: fixture.URL, ConnectIP: "127.0.0.1", MaxRequests: 1, AdmissionURL: allow.URL, AdmissionToken: "synthetic-canonical-permit"}, Eval: `() => ({href:location.href,version:CanonicalFixture.version})`})
	if err != nil || recollected.Partial || targetHits.Load() != 1 || grants.Load() != 1 || len(recollected.Attempts) != 1 || recollected.Attempts[0].URL != fixture.URL {
		t.Fatalf("scoped nil-seed recollection failed: %v %+v hits=%d grants=%d", err, recollected, targetHits.Load(), grants.Load())
	}
	evidence["nil_seed_recollection"] = recollected
	if folder := os.Getenv("CANONICAL_URL_EVIDENCE_DIR"); folder != "" {
		os.MkdirAll(folder, 0700)
		raw, _ := json.MarshalIndent(evidence, "", "  ")
		os.WriteFile(filepath.Join(folder, "result.json"), raw, 0600)
	}
	t.Logf("nil-seed: refused original:80 before dial, local recollection HTTP=%d permits=%d", targetHits.Load(), grants.Load())
}
