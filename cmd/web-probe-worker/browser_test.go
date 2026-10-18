package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"github.com/shirou/gopsutil/v4/process"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	wapp "github.com/projectdiscovery/wappalyzergo"
	"scanplatform/internal/webevidence"
)

func TestBrowserControlledExecution(t *testing.T) {
	requireBrowserIntegration(t)
	if _, ok := launcher.LookPath(); !ok {
		t.Skip("installed Chromium unavailable")
	}
	defer closeBrowserRuntime()
	// Agent's private TMPDIR is deliberately inaccessible to Chrome's UID.
	t.Setenv("TMPDIR", t.TempDir())
	var hits, deniedHits, permits, files, inFlight atomic.Int32
	evidenceDir := os.Getenv("BROWSER_EVIDENCE_DIR")
	record := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			raw, _ := httputil.DumpRequest(r, true)
			recorder := httptest.NewRecorder()
			handler(recorder, r)
			recorder.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			recorder.Header().Set("Content-Length", fmt.Sprint(recorder.Body.Len()))
			response := recorder.Result()
			response.Header = recorder.Header().Clone()
			response.ContentLength = int64(recorder.Body.Len())
			responseRaw, _ := httputil.DumpResponse(response, true)
			response.Body.Close()
			if evidenceDir != "" {
				os.MkdirAll(evidenceDir, 0700)
				os.WriteFile(filepath.Join(evidenceDir, fmt.Sprintf("http-%03d.txt", files.Add(1))), append(append(raw, []byte("\n\n--- RESPONSE ---\n")...), responseRaw...), 0600)
			}
			for key, values := range recorder.Header() {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(recorder.Code)
			w.Write(recorder.Body.Bytes())
		}
	}
	denied := httptest.NewServer(record(func(w http.ResponseWriter, r *http.Request) { deniedHits.Add(1); fmt.Fprint(w, "MUST NOT REACH") }))
	defer denied.Close()
	var targetURL string
	target := httptest.NewTLSServer(record(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		inFlight.Add(1)
		defer inFlight.Add(-1)
		if r.Host != "virtual.fixture.test" || r.TLS.ServerName != "sni.fixture.test" {
			t.Errorf("fixed identity lost: Host=%s SNI=%s", r.Host, r.TLS.ServerName)
		}
		if _, cookieErr := r.Cookie("fixture_a"); cookieErr != nil {
			t.Errorf("seed HttpOnly cookie lost on %s", r.URL.Path)
		}
		if _, cookieErr := r.Cookie("fixture_b"); cookieErr != nil {
			t.Errorf("duplicate Set-Cookie lost on %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/style.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, "#ready { color: rgb(12,34,56); }")
		case "/head":
			if r.Method != "HEAD" {
				t.Error("HEAD method lost")
			}
			w.Header().Set("X-Head-Fixture", "ready")
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Add("Set-Cookie", "resource_cookie=script; Path=/; Secure")
			w.Header().Set("Content-Encoding", "gzip")
			compressed := gzip.NewWriter(w)
			fmt.Fprint(compressed, `setTimeout(()=>{window.AsyncFixture={version:'9.4.2'};document.querySelector('#ready').setAttribute('data-version','9.4.2')},40);fetch('/api').then(r=>r.text()).then(t=>window.ApiFixture=t);fetch('/head',{method:'HEAD'}).then(r=>window.HeadFixture=r.headers.get('X-Head-Fixture'));localStorage.setItem('private','entry-one');`)
			compressed.Close()
		case "/api":
			if _, cookieErr := r.Cookie("resource_cookie"); cookieErr != nil {
				t.Error("dynamic response cookie lost")
			}
			fmt.Fprint(w, "controlled-api")
		case "/redirect":
			w.Header().Set("Location", denied.URL+"/redirect-escape")
			w.Header().Add("Set-Cookie", "redirect_cookie=preserved; Path=/; Secure; HttpOnly")
			w.WriteHeader(302)
			fmt.Fprint(w, "original-redirect-body")
		case "/error":
			if _, cookieErr := r.Cookie("redirect_cookie"); cookieErr != nil {
				t.Error("redirect Cookie not retained")
			}
			w.Header().Set("X-Fixture-Status", "original-418")
			w.WriteHeader(418)
			fmt.Fprint(w, "fixture-error-body")
		case "/hang":
			<-r.Context().Done()
		default:
			t.Errorf("unexpected actual target request: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer target.Close()
	targetURL = strings.Replace(target.URL, "127.0.0.1", "logical.fixture.test", 1)
	admission := httptest.NewServer(record(func(w http.ResponseWriter, r *http.Request) {
		permits.Add(1)
		var frame struct {
			Sequence int    `json:"request_seq"`
			ID       string `json:"id"`
		}
		if json.NewDecoder(r.Body).Decode(&frame) != nil || frame.Sequence <= 0 || frame.ID != "browser-local" {
			t.Errorf("browser admission sequence missing: %+v", frame)
		}
		fmt.Fprint(w, `{"valid_for_ms":475,"waited_ms":0}`)
	}))
	defer admission.Close()
	input := browserRunInput{Request: webevidence.ProbeRequest{ID: "browser-local", Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, ExecutionProfile: webevidence.BrowserProfile, URL: targetURL + "/", ConnectIP: "127.0.0.1", Host: "virtual.fixture.test", SNI: "sni.fixture.test", AdmissionURL: admission.URL, AdmissionToken: "synthetic-token", MaxRequests: 32, EntryTimeoutMillis: 5000}, Seed: webevidence.Response{URL: targetURL + "/", StatusCode: 200, Headers: http.Header{"Content-Type": {"text/html"}, "Set-Cookie": {"fixture_a=one; Path=/; Secure; HttpOnly", "fixture_b=two; Path=/; Secure"}}, Completeness: "full", Body: []byte(`<html><head><link rel="stylesheet" href="/style.css"></head><body><div id="ready"></div><script src="/app.js"></script></body></html>`)}, Eval: `() => ({version:window.AsyncFixture?.version,dom:document.querySelector('#ready').getAttribute('data-version'),api:window.ApiFixture,head:window.HeadFixture,color:getComputedStyle(document.querySelector('#ready')).color})`}
	input.Seed.DecodedBytes = len(input.Seed.Body)
	input.Seed.BodySHA256 = webevidence.SHA256(input.Seed.Body)
	start := time.Now()
	output, err := runBrowser(context.Background(), input)
	cold := time.Since(start)
	if err != nil {
		t.Fatalf("cold browser failed: %v %+v", err, output)
	}
	var got map[string]any
	if json.Unmarshal(output.Observation, &got) != nil || got["version"] != "9.4.2" || got["dom"] != "9.4.2" || got["api"] != "controlled-api" || got["head"] != "ready" || got["color"] != "rgb(12, 34, 56)" {
		t.Fatalf("JS/DOM missing: %s", output.Observation)
	}
	if hits.Load() != 4 || permits.Load() != 4 || len(output.Attempts) != 4 {
		t.Fatalf("admission accounting: hits=%d permits=%d attempts=%d", hits.Load(), permits.Load(), len(output.Attempts))
	}
	pid := controlledBrowser.launcher.PID()
	profile := controlledBrowser.profile
	if !strings.HasPrefix(profile, "/tmp/shen-browser-") {
		t.Fatalf("Chrome profile not independently accessible: %s", profile)
	}
	assertBrowserUIDAndCDPListener(t, pid)
	coldRSS, rssErr := browserTreeRSS(pid)
	if rssErr != nil {
		t.Fatal(rssErr)
	}
	// A fresh context must lose storage and JS globals while retaining the warm Chrome.
	input.Seed.Body = []byte(`<html><body><div id="ready">second</div></body></html>`)
	input.Eval = `() => ({stored:localStorage.getItem('private'),global:typeof window.AsyncFixture})`
	input.Seed.DecodedBytes = len(input.Seed.Body)
	input.Seed.BodySHA256 = webevidence.SHA256(input.Seed.Body)
	start = time.Now()
	warm, err := runBrowser(context.Background(), input)
	hot := time.Since(start)
	if err != nil || !strings.Contains(string(warm.Observation), `"stored":null`) || !strings.Contains(string(warm.Observation), `"global":"undefined"`) {
		t.Fatalf("context leak: %v %s", err, warm.Observation)
	}
	if controlledBrowser.launcher == nil || controlledBrowser.launcher.PID() != pid {
		t.Fatal("successful context unexpectedly recycled Chrome")
	}
	warmRSS, rssErr := browserTreeRSS(pid)
	if rssErr != nil {
		t.Fatal(rssErr)
	}
	// Explicit fetch escapes, unsupported writes and WS cannot reach either server.
	input.Seed.Body = []byte(fmt.Sprintf(`<html><script>fetch(%q+'/cross');fetch('/redirect').catch(()=>{}).finally(()=>fetch('/error').then(async r=>window.ErrorFixture={status:r.status,body:await r.text(),header:r.headers.get('X-Fixture-Status')}));fetch('/api',{method:'POST',body:'must-not-send'});new WebSocket(%q+'/ws');window.open(%q+'/popup');navigator.serviceWorker.register('/worker.js').catch(()=>{});new Worker('/worker.js');</script></html>`, denied.URL, strings.Replace(denied.URL, "http:", "ws:", 1), denied.URL))
	input.Eval = `() => ({finished:true,error:window.ErrorFixture})`
	input.Seed.DecodedBytes = len(input.Seed.Body)
	input.Seed.BodySHA256 = webevidence.SHA256(input.Seed.Body)
	blocked, err := runBrowser(context.Background(), input)
	if err != nil {
		t.Fatalf("blocked observation: %v %+v", err, blocked)
	}
	if deniedHits.Load() != 0 {
		t.Fatalf("escaped browser egress: %d", deniedHits.Load())
	}
	if !blocked.Partial || len(blocked.Blocked) == 0 || hits.Load() != 6 || permits.Load() != 6 {
		t.Fatalf("blocking incomplete: %+v hits=%d permits=%d", blocked, hits.Load(), permits.Load())
	}
	var errorObservation struct {
		Error struct {
			Status int    `json:"status"`
			Body   string `json:"body"`
			Header string `json:"header"`
		} `json:"error"`
	}
	if json.Unmarshal(blocked.Observation, &errorObservation) != nil || errorObservation.Error.Status != 418 || errorObservation.Error.Body != "fixture-error-body" || errorObservation.Error.Header != "original-418" {
		t.Fatalf("error response promoted/lost: %s", blocked.Observation)
	}
	gzipVerified := false
	for _, attempt := range output.Attempts {
		if strings.HasSuffix(attempt.URL, "/app.js") && attempt.EncodedBytes != int64(attempt.DecodedBytes) && attempt.Headers.Get("Content-Encoding") == "gzip" && strings.Contains(string(attempt.Body), "AsyncFixture") {
			gzipVerified = true
		}
	}
	if !gzipVerified {
		t.Fatal("gzip script decode/full evidence was not verified")
	}
	// Cancellation stops target sockets and disposes the context/process; next entry recovers.
	input.Seed.Body = []byte(`<html><script src="/hang"></script></html>`)
	input.Seed.DecodedBytes = len(input.Seed.Body)
	input.Seed.BodySHA256 = webevidence.SHA256(input.Seed.Body)
	short, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	start = time.Now()
	canceled, cancelErr := runBrowser(short, input)
	cancelElapsed := time.Since(start)
	if cancelErr == nil || cancelElapsed > 3*time.Second {
		t.Fatalf("cancellation failed: %v elapsed=%s %+v", cancelErr, cancelElapsed, canceled)
	}
	if inFlight.Load() != 0 {
		t.Fatalf("target socket remained after cancellation: %d", inFlight.Load())
	}
	if controlledBrowser.engine != nil || controlledBrowser.launcher != nil {
		t.Fatal("canceled browser process was not recycled")
	}
	assertNoBrowserProfileProcesses(t, profile)
	assertNoBrowserUIDProcesses(t)
	if _, statErr := os.Stat(profile); !os.IsNotExist(statErr) {
		t.Fatalf("canceled profile remained: %v", statErr)
	}
	input.Seed.Body = []byte(`<html>recovered</html>`)
	input.Seed.DecodedBytes = len(input.Seed.Body)
	input.Seed.BodySHA256 = webevidence.SHA256(input.Seed.Body)
	recovered, recoverErr := runBrowser(context.Background(), input)
	if recoverErr != nil {
		t.Fatalf("recovery failed: %v %+v", recoverErr, recovered)
	}
	if evidenceDir != "" {
		summary := map[string]any{"cold": cold.String(), "cold_rss_bytes": coldRSS, "warm_rss_bytes": warmRSS, "reused_pid": pid, "canceled_profile_removed": true, "canceled_target_inflight": inFlight.Load(), "warm": hot.String(), "cancel": cancelElapsed.String(), "cold_result": output, "warm_result": warm, "blocked_result": blocked, "cancel_result": canceled, "recovered": recovered, "target_hits": hits.Load(), "denied_target_hits": deniedHits.Load(), "permits": permits.Load()}
		raw, _ := json.MarshalIndent(summary, "", "  ")
		os.WriteFile(filepath.Join(evidenceDir, "summary.json"), raw, 0600)
	}
	if hits.Load() != permits.Load() {
		t.Fatalf("actual HTTP != permits: %d != %d", hits.Load(), permits.Load())
	}
	t.Logf("cold=%s warm=%s cancel=%s target=%d denied=%d permits=%d coldRSS=%d warmRSS=%d reusedPID=%d noCanceledProcesses=true", cold, hot, cancelElapsed, hits.Load(), deniedHits.Load(), permits.Load(), coldRSS, warmRSS, pid)
}

// Prove the proxy itself denies direct browser traffic with Fetch disabled:
// page interception alone is not the browser egress boundary.
func TestBrowserDenyProxyWithoutFetch(t *testing.T) {
	requireBrowserIntegration(t)
	if _, ok := launcher.LookPath(); !ok {
		t.Skip("installed Chromium unavailable")
	}
	defer closeBrowserRuntime()
	var escaped atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1); fmt.Fprint(w, "escaped") }))
	defer target.Close()
	controlledBrowser.mu.Lock()
	defer controlledBrowser.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := controlledBrowser.start(ctx); err != nil {
		t.Fatal(err)
	}
	directContext, err := (proto.TargetCreateBrowserContext{ProxyServer: "direct://", ProxyBypassList: "*"}).Call(controlledBrowser.engine.Context(ctx))
	if err != nil {
		t.Fatal(err)
	}
	isolated := controlledBrowser.engine.Context(ctx)
	isolated.BrowserContextID = directContext.BrowserContextID
	if err != nil {
		t.Fatal(err)
	}
	defer isolated.Context(context.Background()).Close()
	page, err := isolated.Page(proto.TargetCreateTarget{})
	if err != nil {
		t.Fatal(err)
	}
	navigateErr := page.Navigate(target.URL + "/without-fetch")
	if navigateErr == nil {
		t.Fatal("OS UID isolation allowed a direct Chrome navigation with Fetch and proxy disabled")
	}
	if _, liveErr := (proto.BrowserGetVersion{}).Call(controlledBrowser.engine.Context(ctx)); liveErr != nil {
		t.Fatalf("browser died instead of enforcing OS egress: %v", liveErr)
	}
	if listener, listenErr := net.Listen("tcp6", "[::1]:0"); listenErr == nil {
		ipv6 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1); fmt.Fprint(w, "must-not-reach-ipv6") }))
		ipv6.Listener.Close()
		ipv6.Listener = listener
		ipv6.Start()
		defer ipv6.Close()
		ipv6Err := page.Navigate(ipv6.URL + "/direct-ipv6")
		if ipv6Err == nil || escaped.Load() != 0 {
			t.Fatalf("OS UID IPv6 denial failed: %v hits=%d", ipv6Err, escaped.Load())
		}
		t.Logf("Fetch/proxy disabled IPv6 direct: target hits=%d browser=%v", escaped.Load(), ipv6Err)
		port := listener.Addr().(*net.TCPAddr).Port
		probe := fmt.Sprintf("import socket,sys,os\ns=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)\ns.settimeout(1)\ntry: s.connect(('::1',%d))\nexcept OSError as e:\n print('uid=%%d ipv6-connect-denied errno=%%s'%%(os.getuid(),e.errno));sys.exit(23)\ns.sendall(b'GET /uid-probe HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n')\n", port)
		probeOutput, probeErr := exec.Command("/usr/sbin/runuser", "-u", "shen-browser", "--", "/usr/bin/python3", "-c", probe).CombinedOutput()
		exit, ok := probeErr.(*exec.ExitError)
		if !ok || exit.ExitCode() != 23 || !strings.Contains(string(probeOutput), "ipv6-connect-denied errno=") || escaped.Load() != 0 {
			t.Fatalf("native Chrome UID IPv6 firewall refusal unverified: %v %s hits=%d", probeErr, probeOutput, escaped.Load())
		}
		t.Logf("Kernel UID IPv6 direct: %s", strings.TrimSpace(string(probeOutput)))

	} else {
		t.Logf("IPv6 local socket unavailable: %v", listenErr)
	}
	// The Chrome UID cannot open even a localhost proxy socket under the OS
	// boundary. Verify the secondary deny proxy independently from the Go side.
	proxyURL, err := url.Parse(controlledBrowser.launcher.Get("proxy-server"))
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(target.URL + "/proxy-check")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 403 || escaped.Load() != 0 || controlledBrowser.proxyDenied.Load() == 0 {
		t.Fatalf("deny boundary bypassed: hits=%d proxy-status=%d browser=%v", escaped.Load(), response.StatusCode, navigateErr)
	}
	t.Logf("Fetch disabled: target hits=%d, proxy denials=%d, browser=%v", escaped.Load(), controlledBrowser.proxyDenied.Load(), navigateErr)
}

func TestBrowserProtocolRecollection(t *testing.T) {
	requireBrowserIntegration(t)
	if _, ok := launcher.LookPath(); !ok {
		t.Skip("installed Chromium unavailable")
	}
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><link rel="icon" href="data:,"></head><body><div id="fixture" data-version="2.3">Fixture</div><script>window.ProtocolOnly={version:'2.3'};setTimeout(()=>document.querySelector('#fixture').ownVersion='2.3',30);</script></body></html>`)
	}))
	defer target.Close()
	request := webevidence.BrowserRequest{ProbeRequest: webevidence.ProbeRequest{ID: "browser-protocol-local", Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, URL: target.URL + "/", ConnectIP: "127.0.0.1", MaxRequests: 32, CFF: []byte(`{"apps":{"ProtocolOnly":{"js":{"ProtocolOnly.version":"([0-9.]+)\\;version:\\1"},"dom":{"#fixture":{"attributes":{"data-version":"2\\.3"},"properties":{"ownVersion":"2\\.3"},"text":"Fixture","exists":""}}}}}`)}}
	frame, _ := json.Marshal(request)
	var stream bytes.Buffer
	if err := serveBrowser(strings.NewReader(string(frame)+"\n"), &stream); err != nil {
		t.Fatal(err)
	}
	var result webevidence.BrowserResult
	if err := json.Unmarshal(stream.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error != "" || !result.Complete || result.ID != request.ID || result.Profile != webevidence.BrowserProfile || len(result.Matches) != 1 || result.Matches[0].Name != "ProtocolOnly" || result.Matches[0].Version != "2.3" || result.Requests != 1 || hits.Load() != 1 {
		t.Fatalf("browser protocol/recollection failed: %s", stream.Bytes())
	}
	if len(result.Rules) != 5 || result.TotalRules != 5 || result.EvaluatedRules != 5 || result.IncompleteRules != 0 || result.UnsupportedRules != 0 || result.PlanSHA256 == "" || result.SampleWindow == "" {
		t.Fatalf("JS/DOM rules lost: %+v", result.Rules)
	}
	if evidenceDir := os.Getenv("BROWSER_EVIDENCE_DIR"); evidenceDir != "" {
		raw, _ := json.MarshalIndent(result, "", "  ")
		os.WriteFile(filepath.Join(evidenceDir, "protocol-result.json"), raw, 0600)
	}
}

func requireBrowserIntegration(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("full browser integration requires Linux UID egress wrapper; macOS nested sandbox is incompatible with Chrome155 sandbox")
	}
}

func TestBrowserIsolationUnavailable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux wrapper preflight")
	}
	t.Setenv("WEB_BROWSER_EXECUTABLE", filepath.Join(t.TempDir(), "not-installed"))
	defer closeBrowserRuntime()
	var actual atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { actual.Add(1); fmt.Fprint(w, "must-not-reach") }))
	defer target.Close()
	result, err := runBrowser(context.Background(), browserRunInput{Request: webevidence.ProbeRequest{URL: target.URL, ConnectIP: "127.0.0.1", MaxRequests: 32}, Eval: `()=>({})`})
	if err == nil || !strings.Contains(err.Error(), "isolation launcher unavailable") || actual.Load() != 0 || len(result.Attempts) != 0 {
		t.Fatalf("missing isolation did not fail closed: %v %+v hits=%d", err, result, actual.Load())
	}
}

func assertNoBrowserProfileProcesses(t *testing.T, profile string) {
	t.Helper()
	all, err := process.Processes()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all {
		command, _ := p.Cmdline()
		if strings.Contains(command, "--user-data-dir="+profile) {
			t.Errorf("browser process remained after cancellation: pid=%d", p.Pid)
		}
	}
}

func TestBrowserWholeSelectedCFF(t *testing.T) {
	requireBrowserIntegration(t)
	defer closeBrowserRuntime()
	const document = `<html><head><link rel="icon" href="data:,"></head><body><div id="fixture">Whole selected CFF fixture</div><script>window.jQuery={fn:{jquery:'3.7.1'}};</script></body></html>`
	var hits, permits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, document)
		if evidenceDir := os.Getenv("BROWSER_EVIDENCE_DIR"); evidenceDir != "" {
			requestRaw, _ := httputil.DumpRequest(r, true)
			response := &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(document)), ContentLength: int64(len(document))}
			responseRaw, _ := httputil.DumpResponse(response, true)
			os.WriteFile(filepath.Join(evidenceDir, "whole-cff-http.txt"), append(append(requestRaw, []byte("\n\n--- RESPONSE ---\n")...), responseRaw...), 0600)
		}
	}))
	defer target.Close()
	admission := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permits.Add(1)
		fmt.Fprint(w, `{"valid_for_ms":475,"waited_ms":0}`)
	}))
	defer admission.Close()
	input := webevidence.BrowserRequest{ProbeRequest: webevidence.ProbeRequest{ID: "whole-cff-local", Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, URL: target.URL + "/", ConnectIP: "127.0.0.1", MaxRequests: 32, AdmissionURL: admission.URL, AdmissionToken: "synthetic-whole-token", CFF: []byte(wapp.GetFingerprints())}}
	start := time.Now()
	result, err := probeBrowser(context.Background(), input)
	elapsed := time.Since(start)
	if err != nil || result.Error != "" {
		t.Fatalf("whole browser CFF failed: %v %+v", err, result)
	}
	if result.TotalRules != 7075 || result.UnsupportedRules != 2 || result.IncompleteRules != 1 || result.EvaluatedRules+result.IncompleteRules+result.UnsupportedRules != 7075 || result.Complete {
		t.Fatalf("whole CFF accounting invalid: total=%d evaluated=%d incomplete=%d unsupported=%d complete=%v", result.TotalRules, result.EvaluatedRules, result.IncompleteRules, result.UnsupportedRules, result.Complete)
	}
	invalidSelector := false
	for _, rule := range result.Rules {
		if strings.Contains(rule.Error, "Progress WS_FTP") && strings.Contains(rule.Error, "not a valid selector") {
			invalidSelector = true
		}
	}
	if !invalidSelector {
		t.Fatal("original upstream WS_FTP selector gap was not retained")
	}
	found := false
	for _, match := range result.Matches {
		if strings.EqualFold(match.Name, "jquery") && match.Version == "3.7.1" {
			found = true
		}
	}
	if !found || hits.Load() != 1 || permits.Load() != 1 || result.Requests != 1 {
		t.Fatalf("full-selected JS-only positive/accounting lost: found=%v hits=%d permits=%d requests=%d", found, hits.Load(), permits.Load(), result.Requests)
	}
	raw, _ := json.MarshalIndent(result, "", "  ")
	if len(raw) > 512<<10 {
		t.Fatalf("whole CFF result exceeds evidence limit: %d", len(raw))
	}
	if evidenceDir := os.Getenv("BROWSER_EVIDENCE_DIR"); evidenceDir != "" {
		os.WriteFile(filepath.Join(evidenceDir, "whole-cff-result.json"), raw, 0600)
	}
	t.Logf("whole CFF: total=%d evaluated=%d incomplete=%d unsupported=%d negative-omitted=%d bytes=%d elapsed=%s requests=%d permits=%d", result.TotalRules, result.EvaluatedRules, result.IncompleteRules, result.UnsupportedRules, result.OmittedNegativeRules, len(raw), elapsed, result.Requests, permits.Load())
}

func TestBrowserOutputKeepsPositiveNamesVersions(t *testing.T) {
	result := webevidence.BrowserResult{Complete: true, BlockedCount: 64}
	original := map[string]string{}
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("Positive%d", i)
		version := fmt.Sprintf("1.%d", i)
		original[name] = version
		result.Matches = append(result.Matches, webevidence.Match{Name: name, Version: version, Engine: browserEngine, Evidence: json.RawMessage(`{"value":"` + strings.Repeat("x", 8192) + `"}`)})
	}
	for i := 0; i < 64; i++ {
		result.Blocked = append(result.Blocked, webevidence.BrowserBlockedRequest{URL: "https://fixture.test/" + strings.Repeat("x", 3000), Reason: "blocked"})
	}
	compactBrowserResult(&result)
	if result.Complete || result.Error == "" || len(result.Matches) != len(original) || len(result.EvidenceSHA256) != 64 || result.BlockedCount != 64 || len(result.Blocked) != 0 {
		t.Fatalf("output compaction lost coverage/evidence: %+v", result)
	}
	for _, match := range result.Matches {
		if version, ok := original[match.Name]; !ok || version != match.Version {
			t.Fatal("positive name/version lost")
		}
	}
	raw, _ := json.Marshal(result)
	if len(raw) > 512<<10 {
		t.Fatalf("output still oversized: %d", len(raw))
	}
}

func assertNoBrowserUIDProcesses(t *testing.T) {
	t.Helper()
	raw, err := exec.Command("/usr/bin/id", "-u", "shen-browser").Output()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	all, err := process.Processes()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all {
		uids, _ := p.Uids()
		if len(uids) > 0 && int64(uids[0]) == uid {
			name, _ := p.Name()
			t.Errorf("Chrome UID process remained after cancellation: pid=%d name=%s", p.Pid, name)
		}
	}
}

func assertBrowserUIDAndCDPListener(t *testing.T, pid int) {
	t.Helper()
	raw, err := exec.Command("/usr/bin/id", "-u", "shen-browser").Output()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	root, err := process.NewProcess(int32(pid))
	if err != nil {
		t.Fatal(err)
	}
	pending := []*process.Process{root}
	chromeCount, listeners := 0, 0
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		children, _ := current.Children()
		pending = append(pending, children...)
		name, _ := current.Name()
		if !strings.HasPrefix(name, "chrome") {
			continue
		}
		uids, uidErr := current.Uids()
		if uidErr != nil {
			continue
		}
		chromeCount++
		for _, uid := range uids {
			if int64(uid) != expected {
				t.Fatalf("Chrome descendant UID differs: pid=%d name=%s uid=%d expected=%d", current.Pid, name, uid, expected)
			}
		}
		command, _ := current.Cmdline()
		if strings.Contains(command, "--no-sandbox") || strings.Contains(command, "--disable-setuid-sandbox") {
			t.Fatalf("Chrome sandbox disabled: pid=%d", current.Pid)
		}
		connections, _ := current.Connections()
		for _, connection := range connections {
			if connection.Status == "LISTEN" && connection.Laddr.Port == uint32(browserCDPPort) {
				if connection.Laddr.IP != "127.0.0.1" {
					t.Fatalf("CDP listens outside fixed loopback: %s", connection.Laddr.IP)
				}
				listeners++
			}
		}
	}
	if chromeCount == 0 || listeners == 0 {
		t.Fatalf("Chrome UID/CDP listener not verified: chrome=%d listeners=%d", chromeCount, listeners)
	}
	t.Logf("OS process/socket: Chrome descendants=%d all UID=%d sandbox retained, CDP127.0.0.1:%d listeners=%d", chromeCount, expected, browserCDPPort, listeners)
}
