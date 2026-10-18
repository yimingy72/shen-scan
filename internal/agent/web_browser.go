package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"scanplatform/internal/webevidence"
)

func browserTask(payload []byte) bool {
	var p webevidence.BrowserAssignment
	return json.Unmarshal(payload, &p) == nil && p.Phase == "browser"
}

func (a *Agent) canAdmitBrowser() bool {
	if !a.canAdmitWork() {
		return false
	}
	a.mu.Lock()
	count := len(a.active)
	for _, t := range a.active {
		if t.browser {
			a.mu.Unlock()
			return false
		}
	}
	a.mu.Unlock()
	if count >= max(1, a.cfg.MaxTasks) {
		return false
	}
	metrics := a.resources.metrics()
	if available, ok := metrics["mem_available_mib"].(float64); ok && available < 768 {
		return false
	}
	if cpu, ok := metrics["cpu_percent"].(float64); ok && cpu >= 75 {
		return false
	}
	used, _ := a.connectionEstimate()
	// Keep at least one connection available for the ordinary lane.
	return used+3 <= a.cfg.EndpointConcurrency
}

func (a *Agent) runBrowserTask(ctx context.Context, task Task, emit func(Observation) error) error {
	var p httpPayload
	if err := json.Unmarshal(task.Payload, &p); err != nil {
		return &TaskError{Reason: "invalid browser payload", Retryable: false}
	}
	if p.WebBrowserProfile != webevidence.BrowserProfile || len(p.Endpoints) != 1 {
		return &TaskError{Reason: "unsupported browser assignment", Retryable: false}
	}
	ep := p.Endpoints[0]
	if p.RulesRef != "" && (task.RunID == "" || p.RulesRef != task.RunID+":http" || p.Rules != nil) {
		return &TaskError{Reason: "browser rules reference changed frozen run scope", Retryable: false}
	}
	identity := p.BrowserParent.Identity
	identity.TaskID = task.ID
	identity.AttemptNo = task.AttemptNo
	identity.Segment = 0
	id, err := RandomID()
	if err != nil {
		return err
	}
	result := webevidence.BrowserResult{ID: id, Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, Identity: identity, Parent: p.BrowserParent, CFFSHA256: p.BrowserCFFSHA256, Engine: "wappalyzer-browser"}
	finish := func(reason string, stopReason ...string) error {
		if reason != "" {
			result.Complete = false
			result.Error = reason
			result.StopReason = "browser-error"
			if len(stopReason) > 0 {
				result.StopReason = stopReason[0]
			}
		}
		obs := Observation{Kind: "http", Target: endpointTarget(ep), IP: p.BrowserConnectIP, URL: p.BrowserURL, Port: ep.Port, WorkKey: ep.WorkKey, ExecutionProfile: webevidence.BrowserProfile, Outcome: "incomplete", Coverage: "partial", Browser: &webevidence.BrowserStage{Profile: webevidence.BrowserProfile, State: "partial", StopReason: result.StopReason, Requests: result.Requests}}
		if result.JSDOMEnabled == nil {
			enabled := p.WebScanOptions == nil || p.WebScanOptions.JSDOM
			result.JSDOMEnabled = &enabled
		}
		a.recordBrowserAvailability(result)
		result = compactBrowserEvidence(result)
		raw, _ := json.Marshal(map[string]any{"browser": result})
		obs.Evidence = string(raw)
		return emit(obs)
	}
	var cff []byte
	jsEnabled := p.WebScanOptions == nil || p.WebScanOptions.JSDOM
	if p.BrowserJSDOMRequired != nil {
		jsEnabled = jsEnabled && *p.BrowserJSDOMRequired
	}
	cached := !jsEnabled
	if !cached && p.RulesRef != "" {
		cff, cached = a.ruleSets.cff(p.RulesRef)
	}
	if !cached {
		rules, err := a.resolveTaskRules(ctx, task, p.RulesRef, p.Rules, "http")
		if err != nil {
			return finish(err.Error())
		}
		// Resolving a referenced set already builds its existing cached CFF.
		cff, cached = a.ruleSets.cff(p.RulesRef)
		if !cached {
			cff, err = buildHTTPXCFF(rules)
			if err != nil {
				return finish(err.Error())
			}
		}
	}
	if jsEnabled && webevidence.SHA256(cff) != p.BrowserCFFSHA256 {
		return finish("browser frozen CFF hash mismatch", "browser-assignment-error")
	}
	u, err := url.Parse(p.BrowserURL)
	if err != nil || u.Hostname() == "" {
		return finish("invalid fixed browser URL", "browser-assignment-error")
	}
	// Validate the pinned address through the same Agent target policy as HTTP.
	ip, err := a.httpDialHost(ctx, u.Hostname(), urlPort(u), p.BrowserConnectIP, u.Hostname())
	if err != nil || ip != p.BrowserConnectIP {
		return finish("browser pinned address is not authorized", "browser-assignment-error")
	}
	remaining := 32 - p.BrowserRequestsUsed
	if remaining <= 0 {
		return finish("browser cumulative request budget exhausted", "cumulative-budget")
	}
	if p.BrowserDeadline.IsZero() || !time.Now().Before(p.BrowserDeadline) {
		return finish("browser cumulative deadline exhausted", "cumulative-deadline")
	}
	pageTimeout := 5 * time.Second
	if p.WebScanOptions != nil && p.WebScanOptions.Screenshot {
		pageTimeout = 10 * time.Second
	}
	pageCtx, cancel := context.WithTimeout(a.withHTTPBudget(ctx, task), pageTimeout)
	defer cancel()
	budget := &webEntryBudget{maximum: remaining}
	admission, token, closeAdmission, err := startWebAdmissionLimited(pageCtx, id, ip, u, false, &webAdmissionLimit{entry: budget, maxRequests: remaining})
	if err != nil {
		return finish(err.Error())
	}
	defer closeAdmission()
	inputOptions := p.WebScanOptions
	if inputOptions != nil {
		copyOptions := *inputOptions
		copyOptions.JSDOM = jsEnabled
		inputOptions = &copyOptions
	}
	result.JSDOMEnabled = &jsEnabled
	input := webevidence.BrowserRequest{ProbeRequest: webevidence.ProbeRequest{WebScanOptions: inputOptions, ID: id, Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, ExecutionProfile: webevidence.BrowserProfile, Identity: identity, URL: p.BrowserURL, ConnectIP: ip, Host: p.BrowserHost, HTTPHost: p.BrowserHost, SNI: p.BrowserSNI, TLSSNI: p.BrowserSNI, CFF: cff, CFFSHA256: p.BrowserCFFSHA256, AdmissionURL: admission, AdmissionToken: token, MaxRequests: remaining, EntryTimeoutMillis: int(pageTimeout / time.Millisecond), TimeoutMillis: 5000}, Parent: p.BrowserParent, Seed: p.BrowserSeed}
	binary, ok := webProbeBinary()
	if !ok {
		return finish("web browser helper is not installed", "browser-unavailable")
	}
	helperCtx, stopHelper := context.WithTimeout(ctx, pageTimeout+time.Second)
	defer stopHelper()
	output, err := a.browser.run(helperCtx, binary, input, a.resources)
	if err != nil {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		result.Requests = budget.count()
		stopReason := "browser-error"
		if errors.Is(err, context.DeadlineExceeded) {
			stopReason = "browser-timeout"
		} else {
			for _, marker := range []string{"unavailable", "not installed", "no such file", "sandbox", "isolation"} {
				if strings.Contains(strings.ToLower(err.Error()), marker) {
					stopReason = "browser-unavailable"
					break
				}
			}
		}
		return finish(err.Error(), stopReason)
	}
	if err = json.Unmarshal(output, &result); err != nil {
		return finish("invalid browser helper JSON", "browser-protocol-error")
	}
	if result.ID != id || result.Protocol != webevidence.Protocol || result.Profile != webevidence.BrowserProfile || result.Identity != identity || result.Parent != p.BrowserParent || result.CFFSHA256 != p.BrowserCFFSHA256 || result.Requests < budget.count() || result.Requests > remaining {
		result = webevidence.BrowserResult{ID: id, Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, Identity: identity, Parent: p.BrowserParent, CFFSHA256: p.BrowserCFFSHA256, Engine: "wappalyzer-browser", Requests: budget.count()}
		return finish("browser helper identity or request count mismatch", "browser-protocol-error")
	}
	return finish("")
}

// One reusable helper per Agent, separate from ordinary httpx helper processes.
// Only the random loopback admission token crosses IPC, never Control credentials.
type browserProcess struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	done    chan error
	dir     string
}

func browserCommand(binary string) (*exec.Cmd, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, err
	}
	return exec.Command(path, "--browser-worker"), nil
}

func (p *browserProcess) start(binary string, resources *resourceSampler) (err error) {
	cmd, err := browserCommand(binary)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "shen-browser-")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	for _, name := range []string{"home", "config", "cache", "tmp"} {
		if err = os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			return err
		}
	}
	setProcessGroup(cmd)
	cmd.Env = append(httpxEnvironment(dir), "PATH=/usr/local/bin:/usr/bin:/bin")
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		cmd.Env = append(cmd.Env, "WEB_BROWSER_EXECUTABLE=/usr/local/libexec/shen-browser-chrome")
	}
	cmd.Dir = dir
	cmd.Stderr = &stderrTail{limit: 8192}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return err
	}
	if err = cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return err
	}
	p.cmd, p.stdin, p.dir = cmd, stdin, dir
	p.scanner = bufio.NewScanner(stdout)
	p.scanner.Buffer(make([]byte, 64<<10), webevidence.MaxMessage)
	p.done = make(chan error, 1)
	release := resources.trackTool(toolBrowser, cmd.Process.Pid)
	go func() { err := cmd.Wait(); release(); p.done <- err }()
	return nil
}

func (p *browserProcess) run(ctx context.Context, binary string, input webevidence.BrowserRequest, resources *resourceSampler) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil {
		if err := p.start(binary, resources); err != nil {
			return nil, err
		}
	}
	type reply struct {
		raw []byte
		err error
	}
	done := make(chan reply, 1)
	stdin, scanner := p.stdin, p.scanner
	go func() {
		if err := json.NewEncoder(stdin).Encode(input); err != nil {
			done <- reply{err: err}
			return
		}
		if !scanner.Scan() {
			err := scanner.Err()
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			done <- reply{err: err}
			return
		}
		done <- reply{raw: append([]byte(nil), scanner.Bytes()...)}
	}()
	select {
	case <-ctx.Done():
		p.stopLocked()
		<-done
		return nil, context.Cause(ctx)
	case r := <-done:
		if r.err != nil {
			p.stopLocked()
		}
		return r.raw, r.err
	}
}
func (p *browserProcess) stop() { p.mu.Lock(); defer p.mu.Unlock(); p.stopLocked() }
func (p *browserProcess) stopLocked() {
	if p.cmd == nil {
		return
	}
	killProcessGroup(p.cmd.Process)
	p.stdin.Close()
	<-p.done
	os.RemoveAll(p.dir)
	p.cmd = nil
	p.stdin = nil
	p.scanner = nil
}

// Persist hashes for bounded resource bodies, keeping the complete collected
// state and matcher summary. Source bodies have already been consumed in Chrome.
func compactBrowserEvidence(result webevidence.BrowserResult) webevidence.BrowserResult {
	var imageData []byte
	if result.Screenshot != nil {
		copyShot := *result.Screenshot
		result.Screenshot = &copyShot
		imageData = copyShot.PNG
		result.Screenshot.PNG = nil
	}
	result.Attempts = append([]webevidence.Response(nil), result.Attempts...)
	for i := range result.Attempts {
		r := &result.Attempts[i]
		if len(r.Body) > 0 {
			r.Body = nil
			r.BodyStorage = "hash_only"
		}
	}
	raw, _ := json.Marshal(result)
	if len(raw) > 512<<10 {
		for i := range result.Attempts {
			r := &result.Attempts[i]
			r.Headers = nil
			r.HeaderRaw = ""
			r.RequestRaw = ""
			r.TLS = nil
		}
	}
	raw, _ = json.Marshal(result)
	if len(raw) > maxBatchBytes-8192 {
		result.Complete = false
		result.StopReason = "evidence-size-limit"
		// Keep positive names/version and summary; large raw rule diagnostics can be
		// inspected in the frozen CFF via plan digest rather than repeated per page.
		for i := range result.Rules {
			result.Rules[i].Error = ""
		}
		for i := range result.Matches {
			if len(result.Matches[i].Evidence) > 1024 {
				result.Matches[i].Evidence = nil
			}
		}
	}
	if result.Screenshot != nil {
		result.Screenshot.PNG = imageData
	}
	return result
}
