package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"scanplatform/internal/rulelib"
)

// A batch shares only process startup. Every original template keeps its own
// manifest identity, one planned request, matcher event and completion evidence.
func (a *Agent) runNucleiBatch(ctx context.Context, ep Endpoint, rules []rulelib.Rule, emit func(Observation) error) error {
	if len(rules) > rulelib.MaxNucleiBatchTemplates {
		return &TaskError{Reason: "Nuclei batch exceeds four templates"}
	}
	if len(rules) == 0 {
		return nil
	} // All templates already have immutable receipts.
	base, err := pocOriginalBaseURL(ep)
	if err != nil {
		return err
	}
	if !a.supportsNucleiBatch() {
		return &TaskError{Reason: "Nuclei batch requires verified engine 3.11.1"}
	}
	binary, err := exec.LookPath(a.cfg.NucleiBinary)
	if err != nil {
		return err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "scanplatform-nuclei-batch-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	for _, dir := range []string{"home", "config", "cache", "templates", "tmp"} {
		if err = os.Mkdir(filepath.Join(work, dir), 0700); err != nil {
			return err
		}
	}
	type planned struct {
		rule     rulelib.Rule
		request  rulelib.Request
		path     string
		negative bool
	}
	manifest := map[string]planned{}
	var scope []rulelib.Request
	var files []string
	for index, rule := range rules {
		if !rulelib.NucleiBatchEligible(rule) {
			return &TaskError{Reason: "Nuclei batch contains an incompatible template"}
		}
		analysis, _ := rulelib.AnalyzeNucleiOriginal([]byte(rule.Template))
		requests, resolveErr := rulelib.ResolveNucleiOriginalRequests(analysis.Plan, base)
		if resolveErr != nil {
			return resolveErr
		}
		if _, duplicate := manifest[rule.Nuclei.TemplateID]; duplicate {
			return &TaskError{Reason: "Nuclei batch template IDs must be unique"}
		}
		path := filepath.Join(work, "templates", fmt.Sprintf("%02d.yaml", index))
		if err = os.WriteFile(path, []byte(rule.Template), 0600); err != nil {
			return err
		}
		written, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if digest := sha256.Sum256(written); fmt.Sprintf("%x", digest[:]) != rule.Nuclei.ContentSHA256 {
			return &TaskError{Reason: "Nuclei batch template SHA changed before execution"}
		}
		manifest[rule.Nuclei.TemplateID] = planned{rule, requests[0], path, analysis.Plan.HasNegativeBodyMatcher}
		scope = append(scope, requests[0])
		files = append(files, path)
	}
	proxy, err := a.startScopeProxy(ctx, ep, base.String(), scope)
	if err != nil {
		return err
	}
	defer proxy.Close()
	args := []string{"-target", base.String(), "-templates", strings.Join(files, ","), "-type", "http", "-jsonl", "-silent", "-no-color", "-matcher-status", "-include-rr", "-disable-clustering",
		"-disable-update-check", "-no-interactsh", "-disable-redirects", "-no-httpx", "-no-stdin", "-proxy", proxy.URL(), "-proxy-internal", "-auth=false",
		"-rate-limit", "3", "-bulk-size", "1", "-concurrency", "1", "-payload-concurrency", "1", "-retries", "0", "-timeout", "8", "-response-size-read", "1048576", "-response-size-save", "196608"}
	cmd := exec.Command(binary, args...)
	setProcessGroup(cmd)
	cmd.Dir = work
	cmd.Env = nucleiEnvironment(work)
	stderr := &stderrTail{limit: 64 << 10}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			killProcessGroup(cmd.Process)
		case <-stopped:
		}
	}()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), maxNucleiLine)
	completed := map[string]bool{}
	var executionErr error
	total := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		total += len(line)
		if len(line) == 0 {
			continue
		}
		if total > maxNucleiOutput {
			executionErr = fmt.Errorf("Nuclei batch JSONL exceeded %d bytes", maxNucleiOutput)
			killProcessGroup(cmd.Process)
			break
		}
		var event struct {
			nucleiEvent
			TemplatePath string `json:"template-path"`
		}
		if err = json.Unmarshal(line, &event); err != nil {
			executionErr = fmt.Errorf("invalid Nuclei batch JSONL: %w", err)
			killProcessGroup(cmd.Process)
			break
		}
		plan, found := manifest[event.TemplateID]
		if !found || filepath.Clean(event.TemplatePath) != plan.path {
			executionErr = fmt.Errorf("Nuclei batch event does not match dispatched ID/path manifest")
			killProcessGroup(cmd.Process)
			break
		}
		if completed[event.TemplateID] {
			continue
		}
		view := &scopeProxy{base: base, allowed: map[string]bool{plan.request.Method + " " + plan.request.Path: true}, allowedPaths: map[string]bool{plan.request.Path: true}}
		if event.Error != "" || event.MatcherStatus == nil || !view.ResultAllowed("", event.Request) || !nucleiBatchRequestMatches(event.Request, plan.request, base) || !completeNucleiResponse(event.nucleiEvent, view) {
			continue
		}
		if !proxy.consumeUpstreamExchange(event.Request, event.Response) {
			continue
		}
		obs := newPoCObservation(ep, base, plan.rule)
		obs.URL = base.Scheme + "://" + base.Host + plan.request.Path
		obs.EngineVersion = "3.11.1"
		obs.EvidenceProfile = nucleiSingleResponseProfile
		obs = nucleiOutcomeEvidence(obs, plan.rule, event.TemplateID, line, proxy, plan.negative, false)
		if obs.FindingStatus != "matched" && obs.FindingStatus != "not_matched" {
			continue
		}
		// Emitting immediately lets the task uploader seal this exact template while
		// later templates are still running. A cancelled tail cannot retract it.
		if err = emit(obs); err != nil {
			executionErr = err
			killProcessGroup(cmd.Process)
			break
		}
		completed[event.TemplateID] = true
	}
	if scanErr := scanner.Err(); executionErr == nil && scanErr != nil {
		executionErr = scanErr
		killProcessGroup(cmd.Process)
	}
	if waitErr := cmd.Wait(); executionErr == nil && waitErr != nil {
		executionErr = waitErr
	}
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	for _, rule := range rules {
		if completed[rule.Nuclei.TemplateID] {
			continue
		}
		obs := newPoCObservation(ep, base, rule)
		obs.URL = base.Scheme + "://" + base.Host + manifest[rule.Nuclei.TemplateID].request.Path
		obs.EngineVersion = "3.11.1"
		obs.EvidenceProfile = nucleiSingleResponseProfile
		obs.FindingStatus = "unknown"
		obs.Coverage = "partial"
		obs.Evidence = "Nuclei batch omitted a complete attributed matcher/response event"
		if executionErr != nil {
			obs.Evidence += "; " + executionErr.Error()
		}
		if err = emit(obs); err != nil {
			return err
		}
	}
	return nil
}

// Kept separate so tests can assert the raw single-request identity used for a
// negative without depending on Nuclei process exit status.
func nucleiBatchRequestMatches(raw string, request rulelib.Request, base *url.URL) bool {
	parsed, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return false
	}
	defer parsed.Body.Close()
	if parsed.Method != request.Method || scopedURLPath(parsed.URL) != request.Path {
		return false
	}
	host, err := url.Parse(base.Scheme + "://" + parsed.Host)
	return err == nil && sameAuthority(host, base)
}
