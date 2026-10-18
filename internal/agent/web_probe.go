package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	fb "scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/rulelib"
	"scanplatform/internal/webevidence"
)

func webProbeBinary() (string, bool) {
	value := strings.TrimSpace(os.Getenv("WEB_PROBE_BINARY"))
	if value == "disabled" {
		return "", false
	}
	if value == "" {
		value = "web-probe-worker"
	}
	binary, err := exec.LookPath(value)
	if err != nil {
		return value, os.Getenv("WEB_PROBE_BINARY") != ""
	}
	return binary, true
}

func (a *Agent) runWebProbe(ctx context.Context, task Task, payload httpPayload, binary string, emit func(Observation) error) error {
	if payload.WebExecutionProfile == webevidence.FullProfile {
		return a.runWebFull(ctx, task, payload, binary, emit)
	}
	if payload.WebEnrichmentProfile != "" && payload.WebEnrichmentProfile != webevidence.EnrichmentProfile {
		return &TaskError{Reason: "unsupported web enrichment profile", Retryable: false}
	}
	if payload.FingerprintBundle == "" {
		if payload.FingerprintBundleSchema != "" {
			return &TaskError{Reason: "external fingerprint schema requires an assigned bundle", Retryable: false}
		}
		payload.FingerprintBundle = webevidence.FingerprintBundle
	}
	if payload.FingerprintBundleSchema != "" && !supportedFingerprintSchema(payload.FingerprintBundleSchema) {
		return &TaskError{Reason: "unsupported fingerprint bundle schema", Retryable: false}
	}
	if payload.FingerprintBundleSchema == "" && payload.FingerprintBundle != fb.EmbeddedBundle && payload.FingerprintBundle != fb.LegacyEmbeddedBundle {
		return &TaskError{Reason: "external fingerprint bundle requires schema capability", Retryable: false}
	}
	cff, cached := a.ruleSets.cff(payload.RulesRef)
	if !cached {
		var err error
		cff, err = buildHTTPXCFF(payload.Rules)
		if err != nil {
			return &TaskError{Reason: err.Error()}
		}
	}
	return runEndpointsWithLimit(ctx, payload.Endpoints, a.endpointSlots, 2, func(ctx context.Context, ep Endpoint) Observation {
		select {
		case a.httpxSlots <- struct{}{}:
			defer func() { <-a.httpxSlots }()
		case <-ctx.Done():
			return webFailure(ep, context.Cause(ctx))
		}
		release, err := a.acquireHTTPTarget(ctx, httpTargetKey(ep))
		if err != nil {
			return webFailure(ep, err)
		}
		defer release()
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		raw, err := endpointURL(ep)
		if err != nil {
			return webFailure(ep, err)
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return webFailure(ep, err)
		}
		targets, err := prepareHTTPXTargets(ctx, a, []Endpoint{ep})
		if err != nil {
			return webFailure(ep, err)
		}
		raw = targets[0].url.String()
		parsed = targets[0].url
		ip, err := a.httpDialHost(ctx, parsed.Hostname(), urlPort(parsed), ep.IP, parsed.Hostname())
		if err != nil {
			return webFailure(ep, err)
		}
		itemID, err := RandomID()
		if err != nil {
			return webFailure(ep, err)
		}
		input := webevidence.ProbeRequest{EnrichmentProfile: payload.WebEnrichmentProfile, ID: itemID, Protocol: webevidence.Protocol, URL: raw, ConnectIP: ip, AlternateScheme: ep.URL == "", TimeoutMillis: int(minDuration(boundedTimeout(payload.TimeoutSeconds, 8*time.Second), 8*time.Second) / time.Millisecond), EntryTimeoutMillis: 90000, CFF: cff, CFFSHA256: webevidence.SHA256(cff)}
		var entryBudget *webEntryBudget
		var admissionLimit *webAdmissionLimit
		if payload.WebEnrichmentProfile != "" {
			input.MaxRequests = 8
			input.Step = "entry"
			input.EntryTimeoutMillis = entryMillis(ctx)
			entryBudget = &webEntryBudget{}
			admissionLimit = &webAdmissionLimit{entry: entryBudget}
		}
		admissionURL, token, closeAdmission, err := startWebAdmissionLimited(ctx, input.ID, ip, parsed, input.AlternateScheme, admissionLimit)
		if err != nil {
			return webFailure(ep, err)
		}
		defer closeAdmission()
		input.AdmissionURL, input.AdmissionToken = admissionURL, token
		output, err := a.runWebHelper(ctx, binary, input)
		if err != nil {
			return webFailure(ep, err)
		}
		var result webevidence.ProbeResult
		if err = json.Unmarshal(output, &result); err != nil {
			return webFailure(ep, fmt.Errorf("decode web helper: %w", err))
		}
		if err = validateWebResult(input, result); err != nil {
			return webFailure(ep, err)
		}
		if entryBudget != nil {
			if entryBudget.count() > result.Requests {
				return webFailure(ep, fmt.Errorf("helper underreported admitted requests"))
			}
			entryBudget.consumeAtLeast(result.Requests)
		}

		obs := webProbeObservation(ep, result, payload.Rules)
		var actualMatch webevidence.MatchResult
		if result.Response.StatusCode > 0 && result.Response.Completeness == "full" {
			var resolve func(context.Context) (string, error)
			if supportedFingerprintSchema(payload.FingerprintBundleSchema) {
				resolve = func(ctx context.Context) (string, error) {
					return a.fingerprints.cache.get(ctx, a.client, a.workerID, a.cfg.SessionID, task, payload.FingerprintBundle)
				}
			}
			match, matchErr := a.fingerprints.matchBundle(ctx, webevidence.MatchRequest{Protocol: webevidence.Protocol, ID: webevidence.SHA256([]byte(raw)) + "/" + result.Response.BodySHA256, ExpectedBundle: payload.FingerprintBundle, Response: result.Response, Icons: result.Icons}, payload.FingerprintBundleSchema, resolve)
			actualMatch = match
			if matchErr != nil {
				obs.Error = joinWebError(obs.Error, "passive fingerprint: "+matchErr.Error())
				obs.Outcome = "incomplete"
			} else {
				var additional []Technology
				for _, m := range match.Matches {
					additional = append(additional, Technology{Candidate: m.Candidate, CandidateReason: m.CandidateReason, Name: m.Name, Version: m.Version, RuleID: "fingers:" + m.Engine + ":" + m.Name, Evidence: string(m.Evidence)})
				}
				obs.Technologies = mergeTechnologies(obs.Technologies, additional)
			}
		}
		var supplements []webSupplement
		var supplementSummary *supplementPlan
		if entryBudget != nil {
			products := make([]string, 0, len(obs.Technologies))
			for _, technology := range obs.Technologies {
				products = append(products, technology.Name)
			}
			var added []Technology
			var plan supplementPlan
			supplements, added, plan = a.collectWebSupplements(ctx, binary, input, result, payload.Rules, products, entryBudget)
			supplementSummary = &plan
			obs.Technologies = mergeTechnologies(obs.Technologies, added)
		}
		// An assigned bundle is distinct from a matcher actually executed. Missing
		// or partial HTTP evidence does not pretend that fingerprinting ran.
		evidence := webEvidenceEnvelope{SupplementPlan: supplementSummary, Probe: compactProbe(result), Fingerprint: actualMatch, AssignedBundle: payload.FingerprintBundle, BundleSchema: payload.FingerprintBundleSchema, Supplements: supplements}
		if entryBudget != nil {
			evidence.RequestsBudgetUsed = entryBudget.count()
		}
		storeWebEvidence(&obs, &evidence, payload.WebEnrichmentProfile != "")
		return obs
	}, emit)
}
func joinWebError(old, next string) string {
	if old == "" {
		return next
	}
	return old + "; " + next
}
func webFailure(ep Endpoint, err error) Observation {
	return Observation{Kind: "http", WorkKey: ep.WorkKey, Target: endpointTarget(ep), IP: ep.IP, Port: ep.Port, URL: ep.URL, Engine: "web-probe-worker", Outcome: "error", Coverage: "incomplete", Error: err.Error()}
}
func compactProbe(result webevidence.ProbeResult) webevidence.ProbeResult {
	result.Attempts = append([]webevidence.Response(nil), result.Attempts...)
	result.Icons = append([]webevidence.Response(nil), result.Icons...)
	// Wire evidence storage remains bounded by the existing ingest contract. The
	// full bounded body is handed directly to the matcher; persisted excerpts are
	// explicitly incomplete if larger than the response storage budget.
	result.Response.Body = nil
	result.Response.BodyStorage = "hash_only"
	for i := range result.Attempts {
		result.Attempts[i].Body = nil
		result.Attempts[i].BodyStorage = "hash_only"
	}
	for i := range result.Icons {
		result.Icons[i].Body = nil
		result.Icons[i].BodyStorage = "hash_only"
	}
	return result
}
func webProbeObservation(ep Endpoint, result webevidence.ProbeResult, rules []rulelib.Rule) Observation {
	response := result.Response
	obs := Observation{Kind: "http", WorkKey: ep.WorkKey, Target: endpointTarget(ep), URL: response.URL, IP: response.ConnectIP, StatusCode: response.StatusCode, Headers: response.Headers, Title: result.Title, Server: response.Headers.Get("Server"), Error: response.Error, Engine: result.Engine, ExecutionProfile: result.Profile, ContentSHA256: response.BodySHA256, Coverage: response.Completeness, Outcome: "identified", EvidenceProfile: "bounded-excerpt-v1"}
	parsed, _ := url.Parse(response.URL)
	if parsed != nil {
		obs.Protocol = parsed.Scheme
		obs.Port, _ = strconv.Atoi(urlPort(parsed))
	}
	obs.Title, _ = truncateBytes([]byte(obs.Title), 2048)
	if obs.Coverage == "full" {
		obs.Coverage = "complete"
	}
	var truncated bool
	obs.RequestRaw, obs.Truncated = truncateBytes([]byte(response.RequestRaw), maxRawRequest)
	obs.ResponseRaw, truncated = truncateBytes(normalizedWebResponse(response), maxRawResponse)
	obs.Truncated = obs.Truncated || truncated || response.Completeness != "full"
	obs.BodyExcerpt, _ = truncateBytes(response.Body, maxBodyExcerpt)
	obs.httpBody, obs.httpHeader = string(response.Body), response.HeaderRaw
	if response.Completeness == "full" {
		obs.Technologies = mergeTechnologies(httpxTechnologies(result.Technologies, rules), matchHTTPRules(nativeHTTPRules(rules), obs))
	}
	obs.httpBody, obs.httpHeader = "", ""
	if response.StatusCode == 0 {
		obs.Outcome = "no_response"
	} else if response.Completeness != "full" {
		obs.Outcome = "incomplete"
	}
	encoded, _ := json.Marshal(compactProbe(result))
	obs.Evidence = string(encoded)
	return obs
}

// The decoder body is not the compressed wire body. Store a replayable
// normalized response and keep the actual wire headers in the evidence envelope.
func normalizedWebResponse(response webevidence.Response) []byte {
	headers := response.Headers.Clone()
	headers.Del("Content-Encoding")
	headers.Del("Transfer-Encoding")
	headers.Del("Content-Length")
	normalized := &http.Response{StatusCode: response.StatusCode, Status: fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode)), Proto: response.Proto, ProtoMajor: 1, ProtoMinor: 1, Header: headers, Body: io.NopCloser(bytes.NewReader(response.Body)), ContentLength: int64(len(response.Body))}
	raw, err := httputil.DumpResponse(normalized, true)
	if err != nil {
		return []byte(response.HeaderRaw + string(response.Body))
	}
	return raw
}

// The existing httpxSlots admission and this Agent-owned queue have the same
// bounded capacity. Each borrowed process remains sequential and owns its cache.
func (a *Agent) runWebHelper(ctx context.Context, binary string, input webevidence.ProbeRequest) ([]byte, error) {
	select {
	case process := <-a.webProbes:
		defer func() { a.webProbes <- process }()
		return process.run(ctx, binary, input)
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

// Called after task cancellation and wg.Wait, when no process is borrowed.
func (a *Agent) stopWebProbes() {
	for i := 0; i < cap(a.webProbes); i++ {
		process := <-a.webProbes
		process.stop()
		a.webProbes <- process
	}
}

// Standalone IPC fixtures retain one helper; production uses the Agent pool.
// Failed/canceled items destroy their process before another item is dispatched.
var sharedWebProbe = webProbeProcess{slot: make(chan struct{}, 1)}

func runWebHelper(ctx context.Context, binary string, input []byte) ([]byte, error) {
	var request webevidence.ProbeRequest
	if err := json.Unmarshal(input, &request); err != nil {
		return nil, err
	}
	if request.ID == "" {
		id, err := RandomID()
		if err != nil {
			return nil, err
		}
		request.ID = id
	}
	return sharedWebProbe.run(ctx, binary, request)
}

type webProbeProcess struct {
	resources  *resourceSampler
	slot       chan struct{}
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	scanner    *bufio.Scanner
	stderr     *stderrTail
	done       chan error
	enrichment string
	binary     string
	dir        string
}

func (p *webProbeProcess) run(ctx context.Context, binary string, request webevidence.ProbeRequest) ([]byte, error) {
	select {
	case p.slot <- struct{}{}:
		defer func() { <-p.slot }()
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	if p.cmd != nil && p.binary != binary {
		p.stop()
	}
	if p.cmd == nil {
		if err := p.start(binary); err != nil {
			return nil, err
		}
	}
	if request.EnrichmentProfile != "" && p.enrichment != webevidence.EnrichmentProfile {
		p.stop()
		return nil, fmt.Errorf("web helper lacks exact enrichment capability")
	}
	type reply struct {
		data []byte
		err  error
	}
	done := make(chan reply, 1)
	stdin, scanner := p.stdin, p.scanner
	go func() {
		if err := json.NewEncoder(stdin).Encode(request); err != nil {
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
		data := append([]byte(nil), scanner.Bytes()...)
		var result webevidence.ProbeResult
		err := json.Unmarshal(data, &result)
		if err == nil && (result.ID != request.ID || result.Protocol != webevidence.Protocol || result.CFFSHA256 != request.CFFSHA256) {
			err = fmt.Errorf("web helper reply identity/digest mismatch")
		}
		if err == nil && result.Error != "" {
			err = fmt.Errorf("web helper: %s", result.Error)
		}
		done <- reply{data, err}
	}()
	select {
	case <-ctx.Done():
		p.stop()
		<-done
		return nil, context.Cause(ctx)
	case reply := <-done:
		if reply.err != nil {
			detail := p.stderr.String()
			p.stop()
			return nil, fmt.Errorf("%w: %s", reply.err, strings.TrimSpace(detail))
		}
		return reply.data, nil
	}
}
func (p *webProbeProcess) start(binary string) (err error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return err
	}
	capCtx, capCancel := context.WithTimeout(context.Background(), 3*time.Second)
	capability := exec.CommandContext(capCtx, path, "--capabilities")
	capability.Env = []string{"NO_COLOR=1"}
	capability.Stderr = &stderrTail{limit: 4096}
	var advertised cappedWebBuffer
	capability.Stdout = &advertised
	err = capability.Run()
	capCancel()
	var contract struct {
		Enrichment string `json:"enrichment_profile"`
		Admission  string `json:"request_admission"`
		Stream     string `json:"stream_protocol"`
	}
	if err != nil || advertised.overflow || json.Unmarshal(advertised.Bytes(), &contract) != nil || contract.Admission != "loopback-v2" || contract.Stream != "jsonl-item-v1" {
		return fmt.Errorf("web helper lacks request admission/item isolation capability")
	}
	p.enrichment = contract.Enrichment
	dir, err := os.MkdirTemp("", "shen-web-")
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
	cmd := exec.Command(path)
	setProcessGroup(cmd)
	cmd.Env, cmd.Dir = httpxEnvironment(dir), dir
	stderr := &stderrTail{limit: 32 << 10}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return err
	}
	if err = cmd.Start(); err != nil {
		stdin.Close()
		output.Close()
		return err
	}
	p.cmd, p.stdin, p.stderr, p.binary, p.dir = cmd, stdin, stderr, binary, dir
	p.scanner = bufio.NewScanner(output)
	p.scanner.Buffer(make([]byte, 64<<10), webevidence.MaxMessage)
	p.done = make(chan error, 1)
	releaseProcess := p.resources.trackTool(toolWebProbe, cmd.Process.Pid)
	go func(done chan error) { err := cmd.Wait(); releaseProcess(); done <- err }(p.done)
	return nil
}
func (p *webProbeProcess) stop() {
	if p.cmd == nil {
		return
	}
	killProcessGroup(p.cmd.Process)
	p.stdin.Close()
	<-p.done
	os.RemoveAll(p.dir)
	p.cmd, p.stdin, p.scanner = nil, nil, nil
}

type cappedWebBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *cappedWebBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := webevidence.MaxMessage - b.Len()
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

// ponytail: one active fingerprint bundle, serialized requests. Measure matcher
// memory/CPU before introducing multiple resident engines on small Workers.
var sharedFingerprints = fingerprintProcess{slot: make(chan struct{}, 1)}

type fingerprintProcess struct {
	resources *resourceSampler
	slot      chan struct{}
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	scanner   *bufio.Scanner
	stderr    *stderrTail
	done      chan error
	binary    string
	bundle    string
	schema    string
	cache     fingerprintBundleCache
}

func (p *fingerprintProcess) match(ctx context.Context, input webevidence.MatchRequest) (webevidence.MatchResult, error) {
	return p.matchBundle(ctx, input, "", nil)
}

func (p *fingerprintProcess) matchBundle(ctx context.Context, input webevidence.MatchRequest, schema string, resolve func(context.Context) (string, error)) (webevidence.MatchResult, error) {
	select {
	case p.slot <- struct{}{}:
		defer func() { <-p.slot }()
	case <-ctx.Done():
		return webevidence.MatchResult{}, context.Cause(ctx)
	}
	binary := os.Getenv("FINGERPRINT_WORKER_BINARY")
	if binary == "" {
		binary = "fingerprint-worker"
	}
	if schema != "" && (!supportedFingerprintSchema(schema) || resolve == nil || !fingerprintDigestPattern.MatchString(input.ExpectedBundle)) {
		return webevidence.MatchResult{}, fmt.Errorf("invalid external fingerprint matcher assignment")
	}
	if schema == "" && input.ExpectedBundle != "" && input.ExpectedBundle != fb.EmbeddedBundle && input.ExpectedBundle != fb.LegacyEmbeddedBundle {
		return webevidence.MatchResult{}, fmt.Errorf("unrecognized embedded fingerprint bundle")
	}
	expected := input.ExpectedBundle
	if expected == "" {
		expected = fb.EmbeddedBundle
	}
	if p.cmd != nil && (p.binary != binary || p.bundle != expected || p.schema != schema) {
		p.stop()
	}
	if p.cmd == nil {
		var args []string
		if schema == "" && expected == fb.LegacyEmbeddedBundle {
			args = []string{"--legacy-embedded"}
		}
		if schema != "" {
			file, err := resolve(ctx)
			if err != nil {
				return webevidence.MatchResult{}, fmt.Errorf("prepare fingerprint cache: %w", err)
			}
			args = []string{"--bundle-file", file}
		}
		path, err := exec.LookPath(binary)
		if err != nil {
			return webevidence.MatchResult{}, err
		}
		p.cmd = exec.CommandContext(context.Background(), path, args...)
		setProcessGroup(p.cmd)
		p.binary = binary
		p.bundle = expected
		p.schema = schema
		p.cmd.Env = []string{"NO_COLOR=1"}
		p.stderr = &stderrTail{limit: 32 << 10}
		p.cmd.Stderr = p.stderr
		p.stdin, err = p.cmd.StdinPipe()
		if err != nil {
			p.cmd = nil
			return webevidence.MatchResult{}, err
		}
		output, err := p.cmd.StdoutPipe()
		if err != nil {
			p.stdin.Close()
			p.cmd = nil
			return webevidence.MatchResult{}, err
		}
		p.scanner = bufio.NewScanner(output)
		p.scanner.Buffer(make([]byte, 64<<10), webevidence.MaxMessage)
		if err = p.cmd.Start(); err != nil {
			p.stdin.Close()
			output.Close()
			p.cmd = nil
			return webevidence.MatchResult{}, err
		}
		p.done = make(chan error, 1)
		releaseProcess := p.resources.trackTool(toolFingerprint, p.cmd.Process.Pid)
		go func(cmd *exec.Cmd, done chan error) { err := cmd.Wait(); releaseProcess(); done <- err }(p.cmd, p.done)
	}
	type reply struct {
		result webevidence.MatchResult
		err    error
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
		var output webevidence.MatchResult
		err := json.Unmarshal(scanner.Bytes(), &output)
		if err == nil && (output.Protocol != webevidence.Protocol || output.ID != input.ID || output.Bundle != expected) {
			err = fmt.Errorf("fingerprint helper reply identity mismatch")
		}
		if err == nil && output.Error != "" {
			err = fmt.Errorf("%s", output.Error)
		}
		done <- reply{output, err}
	}()
	select {
	case <-ctx.Done():
		p.stop()
		<-done
		return webevidence.MatchResult{}, context.Cause(ctx)
	case reply := <-done:
		if reply.err != nil {
			detail := p.stderr.String()
			p.stop()
			return reply.result, fmt.Errorf("%w: %s", reply.err, strings.TrimSpace(detail))
		}
		return reply.result, nil
	}
}
func (p *fingerprintProcess) stop() {
	if p.cmd == nil {
		return
	}
	killProcessGroup(p.cmd.Process)
	p.stdin.Close()
	<-p.done
	p.cmd = nil
	p.scanner = nil
	p.stdin = nil
}

// Identity is checked once per Agent/client lifetime. Tools are changed during a
// drained Worker upgrade, followed by Agent restart, never underneath a run.
func discoverWebCapabilities() (string, string, string) {
	p, b, s, _ := discoverWebCapabilitiesFull()
	return p, b, s
}
func discoverWebCapabilitiesFull() (string, string, string, string) {
	binary, present := webProbeBinary()
	if !present {
		return "", "", "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	identity := func(binary, argument string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, binary, argument)
		setProcessGroup(cmd)
		cmd.Env = []string{"NO_COLOR=1"}
		var output cappedWebBuffer
		cmd.Stdout = &output
		cmd.Stderr = &stderrTail{limit: 4096}
		err := cmd.Run()
		if output.overflow {
			return nil, fmt.Errorf("tool capability response exceeds limit")
		}
		return output.Bytes(), err
	}
	raw, err := identity(binary, "--capabilities")
	if err != nil {
		return "", "", "", ""
	}
	var profile struct {
		Enrichment string `json:"enrichment_profile"`
		Protocol   string `json:"protocol"`
		Profile    string `json:"profile"`
		Admission  string `json:"request_admission"`
		Stream     string `json:"stream_protocol"`
	}
	if json.Unmarshal(raw, &profile) != nil || profile.Protocol != webevidence.Protocol || profile.Profile != webevidence.Profile || profile.Admission != "loopback-v2" || profile.Stream != "jsonl-item-v1" {
		return "", "", "", ""
	}
	matcher := os.Getenv("FINGERPRINT_WORKER_BINARY")
	if matcher == "" {
		matcher = "fingerprint-worker"
	}
	raw, err = identity(matcher, "--bundle")
	if err != nil || strings.TrimSpace(string(raw)) != webevidence.FingerprintBundle {
		return "", "", "", ""
	}
	embedded := strings.TrimSpace(string(raw))
	enrichment := ""
	if profile.Enrichment == webevidence.EnrichmentProfile {
		enrichment = profile.Enrichment
	}
	raw, err = identity(matcher, "--capabilities")
	var capabilities fb.Capabilities
	if err == nil && json.Unmarshal(raw, &capabilities) == nil && capabilities.Schema == fb.Schema && capabilities.EngineRevision == fb.EngineRevision && capabilities.SelectionProfile == fb.SelectionProfile && capabilities.EmbeddedBundle == embedded {
		return profile.Profile, embedded, capabilities.Schema, enrichment
	}
	return profile.Profile, embedded, "", enrichment
}

func supportedFingerprintSchema(schema string) bool {
	return schema == fb.Schema || schema == fb.LegacySchema
}

// Advertise v2 only when both installed helpers explicitly attest it. Legacy
// profile/schema advertisement remains independent and continues to claim v1.
func discoverFullExecutionProfile() string {
	probe, ok := webProbeBinary()
	if !ok {
		return ""
	}
	matcher := os.Getenv("FINGERPRINT_WORKER_BINARY")
	if matcher == "" {
		matcher = "fingerprint-worker"
	}
	for _, binary := range []string{probe, matcher} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, binary, "--capabilities")
		cmd.Env = []string{"NO_COLOR=1"}
		setProcessGroup(cmd)
		var output cappedWebBuffer
		cmd.Stdout = &output
		cmd.Stderr = &stderrTail{limit: 4096}
		err := cmd.Run()
		cancel()
		var cap struct {
			ExecutionProfile string `json:"execution_profile"`
			FullProfile      string `json:"full_profile"`
		}
		if err != nil || output.overflow || json.Unmarshal(output.Bytes(), &cap) != nil || (cap.ExecutionProfile != webevidence.FullProfile && cap.FullProfile != webevidence.FullProfile) {
			return ""
		}
	}
	return webevidence.FullProfile
}
