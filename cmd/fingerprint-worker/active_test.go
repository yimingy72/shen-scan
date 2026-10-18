package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/utils/encode"
	"scanplatform/internal/webevidence"
)

func activeFixture(t *testing.T, handler http.HandlerFunc) (webevidence.MatchRequest, func(string, *webevidence.ActiveResult)) {
	t.Helper()
	target := httptest.NewServer(handler)
	t.Cleanup(target.Close)
	var mu sync.Mutex
	var callbacks []string
	admission := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := httputil.DumpRequest(r, true)
		if r.Header.Get("Authorization") != "Bearer synthetic-active-token" {
			t.Error("invalid admission token")
		}
		mu.Lock()
		callbacks = append(callbacks, string(raw)+"\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"valid_for_ms\":1000,\"waited_ms\":0}\n")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"valid_for_ms":1000,"waited_ms":0}`)
	}))
	t.Cleanup(admission.Close)
	parsed, _ := url.Parse(target.URL)
	input := webevidence.MatchRequest{ID: "synthetic-active", Protocol: webevidence.Protocol, ExecutionProfile: webevidence.FullProfile, Response: webevidence.Response{URL: target.URL, StatusCode: 200, Completeness: "full", Body: []byte("unrecognized-page")}, Active: &webevidence.ActiveRequest{EntryURL: target.URL, ConnectIP: "127.0.0.1", Host: parsed.Host, MaxRequests: 100, SegmentMaxRequests: 100, Deadline: time.Now().Add(10 * time.Second), AdmissionURL: admission.URL, AdmissionToken: "synthetic-active-token", TimeoutMillis: 2000}}
	save := func(name string, out *webevidence.ActiveResult) {
		dir := os.Getenv("FINGERPRINT_EVIDENCE_DIR")
		if dir == "" {
			return
		}
		dir = filepath.Join(dir, name)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "outcome.json"), data, 0644); err != nil {
			t.Fatal(err)
		}
		for i, r := range out.Responses {
			packet := r.RequestRaw + "\r\n" + r.HeaderRaw + string(r.Body)
			if r.Error != "" {
				packet += "\nResponse unavailable: " + r.Error
			}
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("target-%02d.http", i+1)), []byte(packet), 0644); err != nil {
				t.Fatal(err)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		for i, p := range callbacks {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("admission-%02d.http", i+1)), []byte(p), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return input, save
}

const cookieChain = `{"id":"chain","info":{"name":"cookie-chain"},"http":[{"method":"POST","path":["{{BaseURL}}/set"],"body":"synthetic=chain","matchers":[{"type":"word","words":["first"]}]},{"method":"GET","path":["{{BaseURL}}/check"],"matchers":[{"type":"word","words":["cookie-ok"]}]}]}`

func activeTarget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	switch r.URL.Path {
	case "/one":
		fmt.Fprint(w, "first-product")
	case "/two":
		fmt.Fprint(w, "second-product")
	case "/same":
		fmt.Fprint(w, "query-"+r.URL.Query().Get("q"))
	case "/set":
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "synthetic-alpha", Path: "/"})
		fmt.Fprint(w, "first")
	case "/check":
		if c, e := r.Cookie("session"); e == nil && c.Value == "synthetic-alpha" {
			fmt.Fprint(w, "cookie-ok")
		} else {
			fmt.Fprint(w, "no-cookie")
		}
	default:
		fmt.Fprint(w, "unrecognized-page")
	}
}
func TestActiveDiscoversUnknownAndOtherProductsWithoutQueryCacheCollision(t *testing.T) {
	native := `[{"name":"first-product","send_data":"/one","rule":[{"regexps":{"body":["first-product"]}}]},{"name":"second-product","send_data":"/two","rule":[{"regexps":{"body":["second-product"]}}]}]`
	hub := `[{"id":"query-one","http":[{"method":"GET","path":["{{BaseURL}}/same?q=one"],"matchers":[{"type":"word","words":["query-one"]}]}]},{"id":"query-two","http":[{"method":"GET","path":["{{BaseURL}}/same?q=two"],"matchers":[{"type":"word","words":["query-two"]}]}]},` + cookieChain + `,{"id":"isolated-cookie","http":[{"method":"GET","path":["{{BaseURL}}/check"],"matchers":[{"type":"word","words":["no-cookie"]}]}]}]`
	engine := fixtureEngine(t, native, hub, `{"fingerprint":[]}`)
	input, save := activeFixture(t, activeTarget)
	input.Active.CandidateProducts = []string{"first-product"}
	passive, err := match(engine, input)
	if err != nil || len(passive) != 0 {
		t.Fatalf("unknown page unexpectedly recognized: %v %v", passive, err)
	}
	matches, out, err := executeActive(engine, input)
	save("unknown-products-query-and-cookie", out)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Complete || len(out.CompletedRuleIDs) != 6 || len(out.RemainingRuleIDs) != 0 || out.Requests != 7 {
		t.Fatalf("incomplete native HTTP run: %+v", out)
	}
	seen := map[string]bool{}
	for _, m := range matches {
		seen[m.Name] = true
	}
	for _, name := range []string{"first-product", "second-product", "query-one", "query-two", "cookie-chain", "isolated-cookie"} {
		if !seen[name] {
			t.Fatalf("missing %s: %v", name, matches)
		}
	}
}
func TestActiveBudgetRestartsWholeChainAndCanceledWorkRemains(t *testing.T) {
	engine := fixtureEngine(t, `[]`, `[`+cookieChain+`]`, `{"fingerprint":[]}`)
	input, save := activeFixture(t, activeTarget)
	input.Active.SegmentMaxRequests = 1
	_, out, err := executeActive(engine, input)
	save("partial-chain-budget", out)
	if err != nil {
		t.Fatal(err)
	}
	if out.Complete || len(out.CompletedRuleIDs) != 0 || len(out.RemainingRuleIDs) != 1 || out.Rules[0].Status != "partial" || out.Requests != 1 {
		t.Fatalf("budget became successful nonmatch: %+v", out)
	}
	input.Active.RequestsUsed = out.Requests
	input.Active.RemainingRuleIDs = out.RemainingRuleIDs
	input.Active.SegmentMaxRequests = 10
	matches, resumed, err := executeActive(engine, input)
	save("resumed-whole-chain", resumed)
	if err != nil || !resumed.Complete || resumed.Requests != 2 || len(matches) != 1 {
		t.Fatalf("whole chain did not restart: %+v %v %v", resumed, matches, err)
	}
	input.Active.Deadline = time.Now().Add(-time.Second)
	_, canceled, err := executeActive(engine, input)
	save("canceled-before-send", canceled)
	if err != nil || canceled.Complete || len(canceled.CompletedRuleIDs) != 0 || len(canceled.RemainingRuleIDs) != 1 || canceled.Requests != 0 || !strings.Contains(canceled.StopReason, "deadline") {
		t.Fatalf("cancellation became successful nonmatch: %+v %v", canceled, err)
	}
}

func TestActiveSafeCacheAndFaviconUsesAssociatedIcon(t *testing.T) {
	icon := []byte("local-active-icon")
	hash := encode.Mmh3Hash32(icon)
	hub := fmt.Sprintf(`[{"id":"shared-one","http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers":[{"type":"word","words":["unrecognized-page"]}]}]},{"id":"shared-two","http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers":[{"type":"word","words":["unrecognized-page"]}]}]},{"id":"page-icon-and","http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers-condition":"and","matchers":[{"type":"word","words":["unrecognized-page"]},{"type":"favicon","hash":[%q]}]}]}]`, hash)
	engine := fixtureEngine(t, `[]`, hub, `{"fingerprint":[]}`)
	input, save := activeFixture(t, activeTarget)
	input.Icons = []webevidence.Response{{StatusCode: 200, Completeness: "full", Body: icon}}
	matches, out, err := executeActive(engine, input)
	save("safe-shared-get-and-associated-icon", out)
	if err != nil || !out.Complete || out.Requests != 1 || len(matches) != 3 {
		t.Fatalf("safe GET cache / associated favicon failed: %+v %v %v", out, matches, err)
	}
	input.Icons = nil
	matches, out, err = executeActive(engine, input)
	save("no-icon-no-favicon-match", out)
	if err != nil || !out.Complete || out.Requests != 1 || len(matches) != 2 {
		t.Fatalf("HTML body acted as icon: %+v %v %v", out, matches, err)
	}
}

func TestActiveNetworkErrorsRemainUncompleted(t *testing.T) {
	engine := fixtureEngine(t, `[]`, `[{"id":"network-failure","http":[{"method":"GET","path":["{{BaseURL}}/failure"],"matchers":[{"type":"word","words":["never"]}]}]}]`, `{"fingerprint":[]}`)
	input, save := activeFixture(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})
	_, out, err := executeActive(engine, input)
	save("network-error-is-not-nonmatch", out)
	if err != nil || out.Complete || len(out.CompletedRuleIDs) != 0 || len(out.RemainingRuleIDs) != 1 || len(out.Rules) != 1 || out.Rules[0].Status != "failed" || out.Rules[0].Error == "" {
		t.Fatalf("network error became successful nonmatch: %+v %v", out, err)
	}
}
