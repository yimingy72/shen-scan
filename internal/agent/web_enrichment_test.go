package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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

	"scanplatform/internal/rulelib"
	"scanplatform/internal/webevidence"
)

func collectionFixture(id, path string) rulelib.Rule {
	return rulelib.Rule{ID: id, Kind: "http", Engine: "native", Purpose: "discovery", Name: "Fixture confirmation", Severity: "info", Enabled: true, Revision: 2,
		Collection: &rulelib.HTTPCollection{Path: path, Products: []string{"Fixture"}}, Definition: rulelib.Definition{Product: "Fixture", Service: "http", Condition: "and", Matchers: []rulelib.Matcher{{Part: "status", Type: "status", Status: []int{200}}, {Part: "body", Type: "word", Words: []string{"confirmed-product"}}}}}
}
func helperForEnrichment(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("TEST_WEB_PROBE_BINARY")
	if binary == "" {
		t.Skip("set TEST_WEB_PROBE_BINARY to actual helper")
	}
	return binary
}

func TestP2AgentEnrichmentRealHelper(t *testing.T) {
	binary := helperForEnrichment(t)
	fingerprint := os.Getenv("TEST_FINGERPRINT_BINARY")
	if fingerprint == "" {
		t.Skip("set actual fingerprint helper")
	}
	t.Setenv("FINGERPRINT_WORKER_BINARY", fingerprint)
	var lock sync.Mutex
	var paths []string
	var packets []map[string]string
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, _ := httputil.DumpRequest(r, true)
		rec := httptest.NewRecorder()
		rec.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		rec.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/start":
			rec.Header().Set("Location", "/home")
			rec.WriteHeader(302)
		case "/home":
			fmt.Fprint(rec, "<title>Fixture</title>fixture-marker")
		case "/confirm":
			fmt.Fprint(rec, "confirmed-product version1.2")
		case "/bad":
			rec.Header().Set("Content-Length", "200")
			fmt.Fprint(rec, "short")
		default:
			rec.WriteHeader(404)
			fmt.Fprint(rec, "missing")
		}
		raw, dumpErr := httputil.DumpResponse(rec.Result(), true)
		if dumpErr != nil {
			var recorded bytes.Buffer
			fmt.Fprintf(&recorded, "HTTP/1.1 %d %s\r\n", rec.Code, http.StatusText(rec.Code))
			rec.Header().Write(&recorded)
			recorded.WriteString("\r\n")
			recorded.Write(rec.Body.Bytes())
			raw = recorded.Bytes()
		}
		lock.Lock()
		paths = append(paths, r.URL.Path)
		packets = append(packets, map[string]string{"request": string(request), "response": string(raw)})
		lock.Unlock()
		for key, values := range rec.Header() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
	}))
	defer fixture.Close()
	a := newHTTPXTestAgent(t, "unused")
	primary := httpxRule("primary", "Fixture", true, `{"html":["fixture-marker"]}`)
	one := collectionFixture("a-confirm", "/confirm")
	two := collectionFixture("b-confirm-same-url", "/confirm")
	two.Definition.VersionRegex = `version([0-9.]+)`
	two.Definition.VersionPart = "body"
	rules := []rulelib.Rule{primary, one, two, collectionFixture("c-bad", "/bad"), collectionFixture("d-never", "/never")}
	run := func(profile string) Observation {
		t.Helper()
		var result Observation
		err := a.runWebProbe(context.Background(), Task{}, httpPayload{WebEnrichmentProfile: profile, Endpoints: []Endpoint{{URL: fixture.URL + "/start", WorkKey: "original"}}, Rules: rules}, binary, func(obs Observation) error { result = obs; return nil })
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	legacy := run("")
	if legacy.StatusCode != 302 || legacy.URL != fixture.URL+"/start" || legacy.Error != "" {
		t.Fatalf("legacy behavior changed: %+v", legacy)
	}
	lock.Lock()
	legacyPaths := append([]string(nil), paths...)
	paths = nil
	lock.Unlock()
	for _, path := range legacyPaths {
		if path == "/home" || path == "/confirm" {
			t.Fatal("legacy task enabled enrichment")
		}
	}
	obs := run(webevidence.EnrichmentProfile)
	if obs.StatusCode != 200 || obs.Error != "" || obs.Outcome != "identified" || obs.WorkKey != "original" || obs.URL != fixture.URL+"/home" {
		t.Fatalf("supplement withdrew/rewrote primary: %+v", obs)
	}
	var evidence webEvidenceEnvelope
	if err := json.Unmarshal([]byte(obs.Evidence), &evidence); err != nil {
		t.Fatal(err)
	}
	if len(evidence.Supplements) != 3 || evidence.Supplements[0].Outcome != "matched" || evidence.Supplements[1].Outcome != "error" || evidence.Supplements[2].Outcome != "skipped_limit" {
		t.Fatalf("supplement outcomes: %+v", evidence.Supplements)
	}
	if len(evidence.Supplements[0].RuleResults) != 2 || evidence.Supplements[0].Response.BodyStorage != "complete" || !bytes.Contains(evidence.Supplements[0].Response.Body, []byte("confirmed-product")) {
		t.Fatal("per-rule/small-body evidence missing")
	}
	lock.Lock()
	counts := map[string]int{}
	for _, path := range paths {
		counts[path]++
	}
	lock.Unlock()
	if counts["/confirm"] != 1 || counts["/bad"] != 1 || counts["/never"] != 0 || len(paths) > 8 {
		t.Fatalf("network scope/counts: %+v", counts)
	}
	if evidence.RequestsBudgetUsed > 8 {
		t.Fatal("entry request budget exceeded")
	}
	// No candidate means no collection, even with enabled collection rules.
	paths = nil
	rules[0] = httpxRule("not-present", "OtherProduct", true, `{"html":["never-present"]}`)
	// fingers may identify other products, but none match the Fixture collection binding.
	unknown := run(webevidence.EnrichmentProfile)
	if unknown.StatusCode != 200 || strings.Contains(unknown.Evidence, `"url":"`+fixture.URL+`/confirm"`) {
		t.Fatal("unknown candidate triggered collection")
	}
	if out := os.Getenv("P2_AGENT_EVIDENCE_DIR"); out != "" {
		os.MkdirAll(out, 0700)
		data, _ := json.MarshalIndent(packets, "", "  ")
		os.WriteFile(filepath.Join(out, "agent-complete-http.json"), data, 0600)
		data, _ = json.MarshalIndent(obs, "", "  ")
		os.WriteFile(filepath.Join(out, "agent-observation.json"), data, 0600)
	}
}

func TestP2ValidateTraceAndFixedIP(t *testing.T) {
	input := webevidence.ProbeRequest{ID: "x", Protocol: webevidence.Protocol, EnrichmentProfile: webevidence.EnrichmentProfile, URL: "http://fixture.test/start", ConnectIP: "127.0.0.1", CFFSHA256: webevidence.SHA256(nil), MaxRequests: 8}
	response := webevidence.Response{URL: "http://fixture.test/end", ConnectIP: "127.0.0.1", StatusCode: 200, Completeness: "full", Body: []byte("ok"), DecodedBytes: 2, BodySHA256: webevidence.SHA256([]byte("ok"))}
	first := webevidence.Response{URL: input.URL, ConnectIP: input.ConnectIP, StatusCode: 302, Headers: http.Header{"Location": []string{"/end"}}}
	result := webevidence.ProbeResult{ID: input.ID, Protocol: input.Protocol, Profile: webevidence.Profile, EnrichmentProfile: input.EnrichmentProfile, InputURL: input.URL, CFFSHA256: input.CFFSHA256, Response: response, Attempts: []webevidence.Response{first, response}, Requests: 2, Redirects: []webevidence.RedirectStep{{FromURL: input.URL, ToURL: response.URL, StatusCode: 302, Outcome: "followed", AttemptIndex: 0}}}
	if err := validateWebResult(input, result); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*webevidence.ProbeResult){func(r *webevidence.ProbeResult) { r.Redirects = nil }, func(r *webevidence.ProbeResult) { r.Response.ConnectIP = "127.0.0.2" }, func(r *webevidence.ProbeResult) { r.InputURL += "wrong" }, func(r *webevidence.ProbeResult) { r.Requests = 9 }, func(r *webevidence.ProbeResult) { r.Response.Body = []byte("tampered") }} {
		raw, _ := json.Marshal(result)
		var bad webevidence.ProbeResult
		json.Unmarshal(raw, &bad)
		mutate(&bad)
		if validateWebResult(input, bad) == nil {
			t.Fatal("forged trace/body/scope accepted")
		}
	}
	legacy := input
	legacy.EnrichmentProfile = ""
	if validateWebResult(legacy, result) == nil {
		t.Fatal("legacy allowed redirect/new profile")
	}
}

func TestP2AdmissionRefreshCountsLogicalOperation(t *testing.T) {
	var grants atomic.Int32
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants.Add(1)
		now := time.Now()
		json.NewEncoder(w).Encode(map[string]any{"granted": true, "server_time": now, "valid_until": now.Add(500 * time.Millisecond)})
	}))
	defer central.Close()
	a := newHTTPXTestAgent(t, "unused")
	a.client.baseURL = central.URL
	ctx := a.withHTTPBudget(context.Background(), Task{ID: "logical", AttemptNo: 1})
	base, _ := url.Parse("https://fixture.test/confirm")
	budget := &webEntryBudget{}
	callback, token, closeCallback, err := startWebAdmissionLimited(ctx, "item", "127.0.0.1", base, false, &webAdmissionLimit{entry: budget, exactURL: true, maxRequests: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer closeCallback()
	invoke := func(seq int, raw string) int {
		data, _ := json.Marshal(map[string]any{"id": "item", "url": raw, "request_seq": seq})
		req, _ := http.NewRequest("POST", callback, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if invoke(1, base.String()) != 200 || invoke(1, base.String()) != 200 || budget.count() != 1 || grants.Load() != 2 {
		t.Fatal("refresh consumed logical budget or bypassed central admission")
	}
	if invoke(2, base.String()) != 429 || invoke(1, "https://fixture.test/other") != 400 {
		t.Fatal("supplement allowed second request/path")
	}
}

func TestP2WorstCaseEvidenceStaysBelowIngest(t *testing.T) {
	body := bytes.Repeat([]byte{0xff}, 2<<20)
	response, storage := compactSupplementResponse(webevidence.Response{Body: body, BodySHA256: webevidence.SHA256(body), Completeness: "full", DecodedBytes: len(body), HeaderRaw: strings.Repeat("h", 64<<10), RequestRaw: strings.Repeat("r", 64<<10)})
	if len(response.Body) != 32<<10 || response.BodyStorage != "prefix" || !storage.HeadersTruncated || !storage.RequestTruncated {
		t.Fatal("bounded binary preview contract broken")
	}
	obs := Observation{Kind: "http", StatusCode: 200}
	envelope := webEvidenceEnvelope{}
	for i := 0; i < 64; i++ {
		envelope.Supplements = append(envelope.Supplements, webSupplement{URL: strings.Repeat("u", 4096), Response: response, Matches: []Technology{{Name: "Fixture", Evidence: strings.Repeat("e", 8192)}}})
	}
	storeWebEvidence(&obs, &envelope, true)
	raw, _ := json.Marshal(obs)
	if len(raw) >= maxBatchBytes-4096 {
		t.Fatalf("oversized ingest: %d", len(raw))
	}
}

func TestP2OversizedEvidenceReturnsWithoutProgress(t *testing.T) {
	for _, metadata := range []struct{ name, value string }{
		{"escaped_control_characters", strings.Repeat("\x01", maxBatchBytes/4)},
		{"overlong_input_url", "http://fixture.test/" + strings.Repeat("u", maxBatchBytes)},
	} {
		t.Run(metadata.name, func(t *testing.T) {
			obs := Observation{Kind: "http", StatusCode: 200}
			envelope := webEvidenceEnvelope{Probe: webevidence.ProbeResult{InputURL: metadata.value}}
			finished := make(chan struct{})
			go func() {
				storeWebEvidence(&obs, &envelope, true)
				close(finished)
			}()
			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("evidence reduction did not return after exhausting reductions")
			}
			raw, err := json.Marshal(obs)
			if err != nil || len(raw)+2 <= maxBatchBytes-4096 {
				t.Fatalf("oversized record must remain rejectable by the common emit guard: size=%d err=%v", len(raw), err)
			}
			var stored webEvidenceEnvelope
			if err := json.Unmarshal([]byte(obs.Evidence), &stored); err != nil || stored.Probe.InputURL != metadata.value {
				t.Fatalf("oversized metadata was silently replaced: %v", err)
			}
		})
	}
}

func TestP2CandidatePlanBoundAndResponseReuse(t *testing.T) {
	a := newHTTPXTestAgent(t, "unused")
	input := webevidence.ProbeRequest{EnrichmentProfile: webevidence.EnrichmentProfile, URL: "http://fixture.test/", ConnectIP: "127.0.0.1"}
	main := webevidence.ProbeResult{Response: webevidence.Response{URL: input.URL, StatusCode: 200, Completeness: "full", Body: []byte("confirmed-product"), DecodedBytes: len("confirmed-product")}}
	rules := make([]rulelib.Rule, 10000)
	for i := range rules {
		rules[i] = collectionFixture(fmt.Sprintf("rule-%05d", i), fmt.Sprintf("/confirm%d", i))
	}
	evidence, _, plan := a.collectWebSupplements(context.Background(), "must-not-execute", input, main, rules, []string{"Fixture"}, &webEntryBudget{used: 8})
	if len(evidence) != 64 || plan.OmittedRules != 9936 || !plan.Truncated || plan.SelectedRules != 64 {
		t.Fatalf("unbounded candidate plan: %d %+v", len(evidence), plan)
	}
	for _, item := range evidence {
		if item.Outcome != "skipped_budget" {
			t.Fatal("budget-exhausted rule pretended checked")
		}
	}
	rule := collectionFixture("reuse", "/")
	items, tech, _ := a.collectWebSupplements(context.Background(), "must-not-execute", input, main, []rulelib.Rule{rule}, []string{"Fixture"}, &webEntryBudget{used: 8})
	if len(items) != 1 || !items[0].Reused || items[0].Outcome != "matched" || len(tech) != 1 {
		t.Fatal("complete response was not reused")
	}
	rule.Collection.Path = "/prior"
	main.Attempts = []webevidence.Response{{URL: "http://fixture.test/prior", Completeness: "full", DecodedBytes: 99}}
	items, _, _ = a.collectWebSupplements(context.Background(), "must-not-execute", input, main, []rulelib.Rule{rule}, []string{"Fixture"}, &webEntryBudget{})
	if len(items) != 1 || items[0].Outcome != "skipped_incomplete_reuse" {
		t.Fatal("incomplete prior response was re-fetched")
	}
}

func TestP2SlowTLSSupplementRefreshesOneLogicalRequest(t *testing.T) {
	binary := helperForEnrichment(t)
	var requests, grants atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, "confirmed-product") }))
	target.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { time.Sleep(650 * time.Millisecond); return nil, nil }}
	target.StartTLS()
	defer target.Close()
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants.Add(1)
		now := time.Now()
		json.NewEncoder(w).Encode(map[string]any{"granted": true, "server_time": now, "valid_until": now.Add(500 * time.Millisecond)})
	}))
	defer central.Close()
	a := newHTTPXTestAgent(t, "unused")
	a.client.baseURL = central.URL
	ctx, cancel := context.WithTimeout(a.withHTTPBudget(context.Background(), Task{ID: "slow-TLS", AttemptNo: 1}), 5*time.Second)
	defer cancel()
	base, _ := url.Parse(target.URL + "/confirm")
	budget := &webEntryBudget{}
	callback, token, closeCallback, err := startWebAdmissionLimited(ctx, "slow-item", "127.0.0.1", base, false, &webAdmissionLimit{entry: budget, exactURL: true, maxRequests: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer closeCallback()
	input := webevidence.ProbeRequest{ID: "slow-item", Protocol: webevidence.Protocol, URL: base.String(), ConnectIP: "127.0.0.1", EnrichmentProfile: webevidence.EnrichmentProfile, Step: "supplement", MaxRequests: 1, CFFSHA256: webevidence.SHA256(nil), AdmissionURL: callback, AdmissionToken: token, EntryTimeoutMillis: entryMillis(ctx)}
	raw, err := a.runWebHelper(ctx, binary, input)
	if err != nil {
		t.Fatal(err)
	}
	var result webevidence.ProbeResult
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if err = validateWebResult(input, result); err != nil {
		t.Fatal(err)
	}
	if result.Response.StatusCode != 200 || result.Requests != 1 || requests.Load() != 1 || grants.Load() < 2 || budget.count() != 1 {
		t.Fatalf("slowTLS logical/wire/grants: status=%d count=%d wire=%d grants=%d logical=%d error=%s", result.Response.StatusCode, result.Requests, requests.Load(), grants.Load(), budget.count(), result.Response.Error)
	}
	t.Logf("slowTLS650ms > TTL500ms: %dcentral grants,1logical request,1actualGET", grants.Load())
}

func TestP2ClaimAdvertisesOnlyExactEnrichmentCapability(t *testing.T) {
	fingerprint := os.Getenv("TEST_FINGERPRINT_BINARY")
	if fingerprint == "" {
		t.Skip("actual fingerprint helper required")
	}
	t.Setenv("FINGERPRINT_WORKER_BINARY", fingerprint)
	for _, advertised := range []string{"", "bounded-enrichment-future", webevidence.EnrichmentProfile} {
		t.Run(advertised, func(t *testing.T) {
			caps := map[string]string{"protocol": webevidence.Protocol, "profile": webevidence.Profile, "request_admission": "loopback-v2", "stream_protocol": "jsonl-item-v1", "enrichment_profile": advertised}
			raw, _ := json.Marshal(caps)
			script := filepath.Join(t.TempDir(), "cap-only-helper")
			os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+string(raw)+"'\n"), 0700)
			t.Setenv("WEB_PROBE_BINARY", script)
			var claim map[string]any
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewDecoder(r.Body).Decode(&claim)
				fmt.Fprint(w, `{"task":null}`)
			}))
			defer control.Close()
			client, err := NewClient(control.URL, "unused", "")
			if err != nil {
				t.Fatal(err)
			}
			client.nmapBinary = "missing-fixture-nmap"
			if _, err = client.Claim(context.Background(), "worker", "session", "request", []string{"http"}, false); err != nil {
				t.Fatal(err)
			}
			value, present := claim["web_enrichment_profile"]
			if advertised == webevidence.EnrichmentProfile {
				if value != webevidence.EnrichmentProfile {
					t.Fatal("new capability omitted")
				}
			} else if present {
				t.Fatalf("old/future helper falsely compatible: %v", value)
			}
		})
	}
}

func TestP2RealEightRequestAndCrossOriginBoundary(t *testing.T) {
	binary := helperForEnrichment(t)
	fingerprint := os.Getenv("TEST_FINGERPRINT_BINARY")
	if fingerprint == "" {
		t.Skip("actual fingerprint helper required")
	}
	t.Setenv("FINGERPRINT_WORKER_BINARY", fingerprint)
	var wire atomic.Int32
	var escaped atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1) }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire.Add(1)
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/one", 302)
		case "/one":
			http.Redirect(w, r, "/two", 302)
		case "/two":
			http.Redirect(w, r, "/home", 302)
		case "/cross":
			w.Header().Set("Location", other.URL+"/external")
			w.WriteHeader(302)
			fmt.Fprint(w, "fixture-marker")
		case "/home":
			fmt.Fprint(w, `fixture-marker<link rel="icon" href="/i1"><link rel="icon" href="/i2">`)
		case "/s1", "/s2", "/s3":
			fmt.Fprint(w, "confirmed-product")
		default:
			fmt.Fprint(w, "icon")
		}
	}))
	defer server.Close()
	a := newHTTPXTestAgent(t, "unused")
	rules := []rulelib.Rule{httpxRule("root", "Fixture", true, `{"html":["fixture-marker"]}`), collectionFixture("a", "/s1"), collectionFixture("b", "/s2"), collectionFixture("c", "/s3")}
	run := func(path string) webEvidenceEnvelope {
		var obs Observation
		if err := a.runWebProbe(context.Background(), Task{}, httpPayload{WebEnrichmentProfile: webevidence.EnrichmentProfile, Endpoints: []Endpoint{{URL: server.URL + path}}, Rules: rules}, binary, func(o Observation) error { obs = o; return nil }); err != nil {
			t.Fatal(err)
		}
		if obs.Error != "" {
			t.Fatal(obs.Error)
		}
		var out webEvidenceEnvelope
		json.Unmarshal([]byte(obs.Evidence), &out)
		return out
	}
	out := run("/start")
	if wire.Load() != 8 || out.RequestsBudgetUsed != 8 || len(out.Probe.Redirects) != 3 || out.Supplements[2].Outcome != "skipped_limit" {
		t.Fatalf("8/2/3 bounds failed: wire=%d evidence=%+v", wire.Load(), out)
	}
	out = run("/cross")
	if escaped.Load() != 0 || len(out.Probe.Redirects) != 1 || out.Probe.Redirects[0].Outcome != "blocked_cross_origin" {
		t.Fatal("cross-origin redirect was followed")
	}
}
