package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/ysmood/leakless"
	"scanplatform/internal/webevidence"
)

type browserRunInput struct {
	Request    webevidence.ProbeRequest
	Seed       webevidence.Response
	Eval       string
	Screenshot bool
}
type browserBlockedRequest struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Reason string `json:"reason"`
}
type browserRunOutput struct {
	Observation    json.RawMessage
	Samples        []json.RawMessage
	Attempts       []webevidence.Response
	Blocked        []browserBlockedRequest
	BlockedCount   int
	Partial        bool
	Error          string
	BrowserVersion string
	JSDOMError     string
	Screenshot     *webevidence.BrowserScreenshot
	ResourceTypes  map[string]int
}
type browserRuntime struct {
	mu             sync.Mutex
	engine         *rod.Browser
	launcher       *launcher.Launcher
	proxy          *http.Server
	profile        string
	uses           int
	version        string
	proxyDenied    atomic.Int64
	idleTimer      *time.Timer
	idleGeneration uint64
}

const browserCDPPort = 19222

var controlledBrowser browserRuntime

func closeBrowserRuntime() {
	controlledBrowser.mu.Lock()
	defer controlledBrowser.mu.Unlock()
	controlledBrowser.close()
}
func (b *browserRuntime) stopIdleLocked() {
	b.idleGeneration++
	if b.idleTimer != nil {
		b.idleTimer.Stop()
		b.idleTimer = nil
	}
}
func (b *browserRuntime) stopIdle() { b.mu.Lock(); defer b.mu.Unlock(); b.stopIdleLocked() }
func (b *browserRuntime) scheduleIdle(delay time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopIdleLocked()
	generation := b.idleGeneration
	b.idleTimer = time.AfterFunc(delay, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.idleGeneration == generation {
			b.close()
		}
	})
}
func (b *browserRuntime) close() {
	b.stopIdleLocked()
	if b.engine != nil {
		_ = b.engine.Timeout(time.Second).Close()
	}
	if b.launcher != nil {
		b.launcher.Kill()
		b.launcher.Cleanup()
	}
	if b.proxy != nil {
		_ = b.proxy.Close()
	}
	if b.profile != "" {
		_ = os.RemoveAll(b.profile)
	}
	b.engine, b.launcher, b.proxy, b.profile, b.uses = nil, nil, nil, "", 0
}
func (b *browserRuntime) start(ctx context.Context) error {
	if b.engine != nil && b.uses < 64 {
		if rss, memoryErr := browserTreeRSS(b.launcher.PID()); memoryErr == nil && rss < 768<<20 {
			return nil
		}
	}
	b.close()
	// Rod otherwise falls back to resolving an existing browser at a fixed port.
	if !leakless.Support() {
		return errors.New("owned Chromium process launcher unavailable on this platform")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	b.proxy = &http.Server{ReadHeaderTimeout: time.Second, MaxHeaderBytes: 32 << 10, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.proxyDenied.Add(1)
		w.Header().Set("Connection", "close")
		http.Error(w, "browser direct egress denied", http.StatusForbidden)
	})}
	denyServer := b.proxy
	go func() { _ = denyServer.Serve(listener) }()
	profileParent := ""
	if runtime.GOOS == "linux" {
		profileParent = "/tmp"
	}
	b.profile, err = os.MkdirTemp(profileParent, "shen-browser-*")
	if err != nil {
		b.close()
		return err
	}
	bin, err := browserIsolatedLauncher(ctx, b.profile)
	if err != nil {
		b.close()
		return err
	}
	b.launcher = launcher.New().Bin(bin).UserDataDir(b.profile).Headless(true).Leakless(true).NoSandbox(false).
		Set("remote-debugging-address", "127.0.0.1").Set("remote-debugging-port", fmt.Sprint(browserCDPPort)).
		Proxy("http://"+listener.Addr().String()).Set("proxy-bypass-list", "<-loopback>").
		Set("host-resolver-rules", "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1").Set("disable-quic").Set("dns-prefetch-disable").
		Set("force-webrtc-ip-handling-policy", "disable_non_proxied_udp").
		Set("disable-features", "WebTransport,MediaRouter,OptimizationHints,AutofillServerCommunication,CertificateTransparencyComponentUpdater").
		Set("disable-background-networking").Set("disable-component-update").Set("disable-extensions").Set("disable-sync").Set("no-pings").
		Set("block-new-web-contents").Set("js-flags", "--max-old-space-size=128").
		Delete("disable-popup-blocking").Delete("disable-site-isolation-trials").Delete("disable-ipc-flooding-protection")
	// Launcher lifetime is independent from entries; startup itself remains bounded.
	launchCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	type launchResult struct {
		url string
		err error
	}
	done := make(chan launchResult, 1)
	chromeLauncher := b.launcher
	go func() { u, e := chromeLauncher.Launch(); done <- launchResult{u, e} }()
	var result launchResult
	select {
	case result = <-done:
	case <-launchCtx.Done():
		b.launcher.Kill()
		result.err = context.Cause(launchCtx)
	}
	if result.err != nil {
		b.close()
		return fmt.Errorf("launch isolated Chromium: %w", result.err)
	}
	client, err := cdp.StartWithURL(launchCtx, result.url, nil)
	if err != nil {
		b.close()
		return err
	}
	engine := rod.New().Client(client).NoDefaultDevice()
	if err = engine.Connect(); err != nil {
		b.close()
		return err
	}
	b.engine = engine
	version, err := (proto.BrowserGetVersion{}).Call(b.engine.Context(launchCtx))
	if err != nil {
		b.close()
		return err
	}
	b.version = version.Product
	return nil
}

func runBrowser(parent context.Context, input browserRunInput) (output browserRunOutput, err error) {
	target, parseErr := url.Parse(input.Request.URL)
	if parseErr != nil || target == nil || target.User != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") || net.ParseIP(input.Request.ConnectIP) == nil {
		return output, errors.New("invalid fixed browser target")
	}
	if target.Fragment != "" || len(target.String()) > 4096 || (input.Eval == "" && !input.Screenshot) {
		return output, errors.New("browser requires fixed URL and observation plan")
	}
	seedOK := input.Seed.URL == target.String() && input.Seed.Completeness == "full" && input.Seed.StatusCode >= 200 && input.Seed.StatusCode < 600 && (input.Screenshot || input.Seed.StatusCode < 300) && len(input.Seed.Body) <= webevidence.MaxBody && input.Seed.DecodedBytes == len(input.Seed.Body) && input.Seed.BodySHA256 == webevidence.SHA256(input.Seed.Body)
	timeout := 5 * time.Second
	if input.Screenshot {
		timeout = 10 * time.Second
	}
	if requested := time.Duration(input.Request.EntryTimeoutMillis) * time.Millisecond; requested > 0 && requested < timeout {
		timeout = requested
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	for !controlledBrowser.mu.TryLock() {
		select {
		case <-ctx.Done():
			return output, context.Cause(ctx)
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer controlledBrowser.mu.Unlock()
	defer func() {
		if err != nil {
			output.Partial = true
			output.Error = err.Error()
		}
	}()
	if err = controlledBrowser.start(ctx); err != nil {
		return output, err
	}
	b := &controlledBrowser
	b.uses++
	output.BrowserVersion = b.version
	deniedBefore := b.proxyDenied.Load()
	isolated, err := b.engine.Context(ctx).Incognito()
	if err != nil {
		b.close()
		return output, err
	}
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
		closeErr := isolated.Context(cleanupCtx).Close()
		stop()
		if closeErr != nil || ctx.Err() != nil {
			b.close()
		}
	}()
	// Canceling CDP alone does not stop hostile JavaScript: dispose the actual context.
	stopClose := context.AfterFunc(ctx, func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer stop()
		_ = isolated.Context(cleanupCtx).Close()
	})
	defer stopClose()
	page, err := isolated.Page(proto.TargetCreateTarget{})
	if err != nil {
		return output, err
	}
	// Chrome canonicalizes default ports, an empty path and hostname case.
	// Ask its native URL parser once while this isolated page is still blank;
	// keep the original target untouched for all Go authorization/HTTP identity.
	canonical, err := page.Eval(`value => new URL(value).href`, target.String())
	if err != nil {
		return output, err
	}
	navigationURL := canonical.Value.Str()
	if len(navigationURL) == 0 || len(navigationURL) > 4096 {
		return output, errors.New("invalid browser navigation URL")
	}
	if input.Screenshot {
		if err = (proto.EmulationSetScrollbarsHidden{Hidden: true}).Call(page); err != nil {
			return output, err
		}
		if err = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{Width: screenshotWidth, Height: screenshotHeight, DeviceScaleFactor: 1, Mobile: false}); err != nil {
			return output, err
		}
	}
	if err = (proto.NetworkSetBypassServiceWorker{Bypass: true}).Call(page); err != nil {
		return output, err
	}
	if err = (proto.BrowserSetDownloadBehavior{Behavior: proto.BrowserSetDownloadBehaviorBehaviorDeny, BrowserContextID: isolated.BrowserContextID}).Call(isolated); err != nil {
		return output, err
	}
	host, sni := input.Request.Host, input.Request.SNI
	if host == "" {
		host = input.Request.HTTPHost
	}
	if sni == "" {
		sni = input.Request.TLSSNI
	}
	if host == "" {
		host = target.Host
	}
	if sni == "" {
		sni = target.Hostname()
	}
	if len(host) > 1024 || len(sni) > 253 || strings.ContainsAny(host, "\r\n/\t ") || (strings.ContainsAny(sni, "\r\n/:\t ") && net.ParseIP(sni) == nil) {
		return output, errors.New("invalid fixed browser Host/SNI")
	}
	budget := input.Request.MaxRequests
	if budget <= 0 || budget > 32 {
		budget = 32
	}
	input.Request.MaxRequests = budget
	input.Request.AlternateScheme = false
	requestCtx, cancelRequests := context.WithCancel(ctx)
	defer cancelRequests()
	capture := &fullCapture{ctx: requestCtx, input: input.Request, target: target, timeout: timeout, host: host}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: sni, MinVersion: tls.VersionTLS10}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort(input.Request.ConnectIP, portOf(target)))
		},
	}
	bounded := capture.wrap(transport)
	defer transport.CloseIdleConnections()
	defer func() {
		capture.mu.Lock()
		output.Attempts = append([]webevidence.Response(nil), capture.attempts...)
		capture.mu.Unlock()
	}()
	if !seedOK {
		request, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet, target.String(), nil)
		if requestErr != nil {
			return output, requestErr
		}
		request.Host = host
		request.Header.Set("Accept-Encoding", "identity")
		request.Header.Set("User-Agent", "shen-scan/3")
		response, fetchErr := bounded.RoundTrip(request)
		if fetchErr != nil {
			return output, fetchErr
		}
		response.Body.Close()
		capture.mu.Lock()
		input.Seed = capture.attempts[len(capture.attempts)-1]
		capture.mu.Unlock()
		if input.Seed.Completeness != "full" || input.Seed.StatusCode < 200 || input.Seed.StatusCode >= 600 || (!input.Screenshot && input.Seed.StatusCode >= 300) {
			return output, errors.New("browser primary recollection incomplete or unsupported status")
		}
	}
	contentType := strings.ToLower(input.Seed.Headers.Get("Content-Type"))
	if !input.Screenshot && !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml+xml") {
		return output, errors.New("browser seed is not HTML")
	}
	var stateMu sync.Mutex
	var requests sync.WaitGroup
	seeded, closed := false, false
	active := make(chan struct{}, 4)
	nonce := make([]byte, 8)
	if _, err = rand.Read(nonce); err != nil {
		return output, err
	}
	binding := "__shenBrowserBlocked_" + hex.EncodeToString(nonce)
	block := func(u, method, reason string) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if len(u) > 4096 {
			u = u[:4096]
			reason = "URL truncated; " + reason
		}
		if len(reason) > 512 {
			reason = reason[:512]
		}
		output.BlockedCount++
		if len(output.Blocked) < 64 {
			output.Blocked = append(output.Blocked, browserBlockedRequest{u, method, reason})
		}
		output.Partial = true
	}
	fail := func(e *proto.FetchRequestPaused, reason string) {
		block(e.Request.URL, e.Request.Method, reason)
		_ = (proto.FetchFailRequest{RequestID: e.RequestID, ErrorReason: proto.NetworkErrorReasonBlockedByClient}).Call(page)
	}
	eventCtx, endEvents := context.WithCancel(ctx)
	defer endEvents()
	wait := page.Context(eventCtx).EachEvent(func(e *proto.FetchRequestPaused) {
		stateMu.Lock()
		if closed {
			stateMu.Unlock()
			return
		}
		if output.ResourceTypes == nil {
			output.ResourceTypes = map[string]int{}
		}
		output.ResourceTypes[string(e.ResourceType)]++
		select {
		case active <- struct{}{}:
		default:
			stateMu.Unlock()
			fail(e, "resource_concurrency_limit")
			return
		}
		requests.Add(1)
		stateMu.Unlock()
		go func() {
			defer requests.Done()
			defer func() { <-active }()
			if len(e.Request.URL) > 4096 {
				fail(e, "request_url_limit")
				return
			}
			u, parseErr := url.Parse(e.Request.URL)
			if parseErr != nil || u.User != nil || !strings.EqualFold(u.Scheme, target.Scheme) || !strings.EqualFold(u.Hostname(), target.Hostname()) || portOf(u) != portOf(target) {
				fail(e, "outside_fixed_origin")
				return
			}
			if e.Request.Method != http.MethodGet && e.Request.Method != http.MethodHead {
				fail(e, "method_blocked")
				return
			}
			stateMu.Lock()
			seed := !seeded && e.ResourceType == proto.NetworkResourceTypeDocument && e.Request.URL == navigationURL && e.Request.Method == http.MethodGet
			if seed {
				seeded = true
			}
			stateMu.Unlock()
			if seed {
				if fulfillErr := browserFulfill(page, e, input.Seed.StatusCode, input.Seed.Headers, input.Seed.Body, true); fulfillErr != nil {
					block(e.Request.URL, e.Request.Method, "seed_fulfill_failed: "+fulfillErr.Error())
				}
				return
			}
			switch e.ResourceType {
			case proto.NetworkResourceTypeScript, proto.NetworkResourceTypeStylesheet, proto.NetworkResourceTypeXHR, proto.NetworkResourceTypeFetch:
			case proto.NetworkResourceTypeImage, proto.NetworkResourceTypeFont, proto.NetworkResourceTypeOther:
				if !input.Screenshot {
					fail(e, "resource_type_blocked: "+string(e.ResourceType))
					return
				}
			default:
				fail(e, "resource_type_blocked: "+string(e.ResourceType))
				return
			}
			request, requestErr := http.NewRequestWithContext(requestCtx, e.Request.Method, u.String(), nil)
			if requestErr != nil {
				fail(e, "invalid_request")
				return
			}
			headerBytes := 0
			for key, value := range e.Request.Headers {
				headerBytes += len(key) + len(value.String())
			}
			if headerBytes > 32<<10 {
				fail(e, "request_header_limit")
				return
			}
			for key, value := range e.Request.Headers {
				if !strings.EqualFold(key, "Host") && !strings.EqualFold(key, "Content-Length") {
					request.Header.Set(key, value.String())
				}
			}
			request.Host = host
			request.Header.Set("Accept-Encoding", "identity")
			request.Header.Set("User-Agent", "shen-scan/3")
			response, fetchErr := bounded.RoundTrip(request)
			if fetchErr != nil {
				fail(e, "controlled_fetch_failed: "+fetchErr.Error())
				return
			}
			defer response.Body.Close()
			body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(webevidence.MaxBody)+1))
			if readErr != nil || len(body) > webevidence.MaxBody {
				fail(e, "incomplete_resource")
				return
			}
			capture.mu.Lock()
			complete := true
			for _, attempt := range capture.attempts {
				if attempt.URL == u.String() && attempt.Completeness != "full" {
					complete = false
				}
			}
			capture.mu.Unlock()
			if !complete {
				fail(e, "incomplete_resource")
				return
			}
			if fulfillErr := browserFulfill(page, e, response.StatusCode, response.Header, body, false); fulfillErr != nil {
				block(u.String(), e.Request.Method, "resource_fulfill_failed: "+fulfillErr.Error())
			}
		}()
	}, func(e *proto.RuntimeBindingCalled) {
		if e.Name == binding {
			var attempt browserBlockedRequest
			if json.Unmarshal([]byte(e.Payload), &attempt) == nil {
				block(attempt.URL, attempt.Method, attempt.Reason)
			}
		}
	}, func(e *proto.PageJavascriptDialogOpening) {
		block(e.URL, "", "javascript_dialog_blocked")
		_ = (proto.PageHandleJavaScriptDialog{Accept: false}).Call(page)
	}, func(e *proto.NetworkWebSocketCreated) { block(e.URL, "GET", "websocket_blocked_by_deny_proxy") }, func(e *proto.NetworkWebTransportCreated) { block(e.URL, "CONNECT", "webtransport_disabled") })
	eventsDone := make(chan struct{})
	go func() { defer close(eventsDone); wait() }()
	extraTargetsDone := make(chan struct{})
	extraTargets := isolated.Context(eventCtx).EachEvent(func(e *proto.TargetTargetCreated) {
		if e.TargetInfo.BrowserContextID == isolated.BrowserContextID && e.TargetInfo.TargetID != page.TargetID {
			block(e.TargetInfo.URL, "", "extra_target_blocked: "+string(e.TargetInfo.Type))
			_, _ = (proto.TargetCloseTarget{TargetID: e.TargetInfo.TargetID}).Call(isolated)
		}
	})
	go func() { defer close(extraTargetsDone); extraTargets() }()
	defer func() { endEvents(); <-extraTargetsDone }()
	if err = (proto.RuntimeAddBinding{Name: binding}).Call(page); err != nil {
		return output, err
	}
	injection := fmt.Sprintf(`(() => {
 const report=globalThis[%q];delete globalThis[%q];
 const blocked=(url,reason)=>report(JSON.stringify({url:String(url||location.href),method:'',reason}));
 addEventListener('securitypolicyviolation',e=>blocked(e.blockedURI,'csp_blocked: '+e.violatedDirective));
 Object.defineProperty(window,'open',{value:function(url){blocked(url,'popup_blocked');return null;},writable:false,configurable:false});
 for(const name of ['Worker','SharedWorker','WebTransport','RTCPeerConnection','webkitRTCPeerConnection']) {
  if(name in globalThis) Object.defineProperty(globalThis,name,{value:function(url){blocked(url,name+'_blocked');throw new DOMException('Disabled in bounded fingerprint context','NotAllowedError');},writable:false,configurable:false});
 }
})()`, binding, binding)
	if _, err = page.EvalOnNewDocument(injection); err != nil {
		return output, err
	}
	if err = (proto.FetchEnable{Patterns: []*proto.FetchRequestPattern{{URLPattern: "*"}}}).Call(page); err != nil {
		return output, err
	}
	defer func() {
		// The observation window has ended. Stop accepting requests before
		// waiting, so Wait cannot race another Add. Existing admitted work gets
		// a short grace window; cancellation never waits out that grace.
		stateMu.Lock()
		closed = true
		stateMu.Unlock()
		// Keep Fetch enabled until accepted requests have been fulfilled. Rod's
		// event cleanup restores/disables domains when its event context ends.
		finished, drained := drainBrowserRequests(ctx, &requests, 500*time.Millisecond)
		if !drained {
			block("browser://request-drain", "", "controlled request drain deadline exceeded")
			cancel() // unblock pending CDP calls as well as target HTTP sockets
		}
		cancelRequests()
		<-finished
		endEvents()
		<-eventsDone
		capture.mu.Lock()
		output.Attempts = append([]webevidence.Response(nil), capture.attempts...)
		capture.mu.Unlock()
		if b.proxyDenied.Load() > deniedBefore {
			block("browser://background-network", "", "direct_egress_denied")
		}
		if output.Partial && output.Screenshot != nil && output.Screenshot.State == "complete" {
			output.Screenshot.State = "partial"
			output.Screenshot.Error = "some page resources were blocked or incomplete"
		}
	}()
	if err = page.Navigate(navigationURL); err != nil {
		return output, err
	}
	// Each sample collects the entire plan in one CDP call. The bounded window is
	// DOMContentLoaded followed by 400ms; later asynchronous changes are outside it.
	for sample := 0; input.Eval != "" && sample < 2; sample++ {
		waitJS := `if(document.readyState==='loading') await new Promise(resolve=>document.addEventListener('DOMContentLoaded',resolve,{once:true}));`
		if sample > 0 {
			waitJS = `await new Promise(resolve=>setTimeout(resolve,400));`
		}
		fixedURL, _ := json.Marshal(navigationURL)
		options := rod.Eval("async () => {" + waitJS + "if(location.href!==" + string(fixedURL) + ") throw new Error('browser document escaped fixed URL'); return (" + input.Eval + ")(); }")
		options.AwaitPromise = true
		observed, evalErr := page.Evaluate(options)
		if evalErr != nil {
			output.JSDOMError = evalErr.Error()
			break
		}
		raw, marshalErr := observed.Value.MarshalJSON()
		if marshalErr != nil {
			output.JSDOMError = marshalErr.Error()
			break
		}
		if len(raw) > 2<<20 {
			output.JSDOMError = "browser observation exceeds limit"
			break
		}
		output.Observation = json.RawMessage(raw)
		output.Samples = append(output.Samples, json.RawMessage(raw))
	}
	if input.Screenshot {
		output.Screenshot = browserCaptureScreenshot(page)
	}
	if output.JSDOMError != "" && !input.Screenshot {
		return output, errors.New(output.JSDOMError)
	}
	return output, nil
}

func browserFulfill(page *rod.Page, e *proto.FetchRequestPaused, status int, headers http.Header, body []byte, document bool) error {
	values := []*proto.FetchHeaderEntry{}
	for key, entries := range headers {
		switch strings.ToLower(key) {
		case "content-length", "content-encoding", "transfer-encoding", "connection":
			continue
		}
		for _, value := range entries {
			values = append(values, &proto.FetchHeaderEntry{Name: key, Value: value})
		}
	}
	if document {
		values = append(values, &proto.FetchHeaderEntry{Name: "Content-Security-Policy", Value: "worker-src 'none'; frame-src 'none'; object-src 'none'"})
	}
	values = append(values, &proto.FetchHeaderEntry{Name: "Content-Length", Value: fmt.Sprint(len(body))})
	return (proto.FetchFulfillRequest{RequestID: e.RequestID, ResponseCode: status, ResponseHeaders: values, Body: body}).Call(page)
}

// Sum the isolated process tree before reuse; recycle at a bounded aggregate RSS.
// Chromium's per-renderer JS heap is also capped to 128 MiB at launch.
func browserTreeRSS(pid int) (uint64, error) {
	root, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0, err
	}
	pending := []*process.Process{root}
	var total uint64
	for len(pending) > 0 {
		p := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		memory, readErr := p.MemoryInfo()
		if readErr != nil {
			return 0, readErr
		}
		total += memory.RSS
		children, _ := p.Children()
		pending = append(pending, children...)
	}
	return total, nil
}

// Drain only already accepted work, never arbitrary network-idle. The caller
// closes admission first and force-cancels requests if this bound is exhausted.
func drainBrowserRequests(ctx context.Context, requests *sync.WaitGroup, limit time.Duration) (<-chan struct{}, bool) {
	finished := make(chan struct{})
	go func() { requests.Wait(); close(finished) }()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-finished:
		return finished, true
	case <-ctx.Done():
		return finished, false
	case <-timer.C:
		return finished, false
	}
}
