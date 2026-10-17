package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"scanplatform/internal/rulelib"
)

const (
	maxNucleiOutput        = 2 << 20
	maxNucleiLine          = 1 << 20
	maxNucleiSavedResponse = 192 << 10
)

type boundedCapture struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (capture *boundedCapture) Write(p []byte) (int, error) {
	n := len(p)
	remaining := capture.limit - capture.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = capture.Buffer.Write(p)
	}
	if n > remaining {
		capture.overflow = true
	}
	return n, nil
}

type nucleiEvent struct {
	TemplateID    string `json:"template-id"`
	MatchedAt     string `json:"matched-at"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	Request       string `json:"request"`
	Response      string `json:"response"`
	MatcherStatus *bool  `json:"matcher-status"`
	Error         string `json:"error"`
}

func (a *Agent) runNucleiPoC(ctx context.Context, ep Endpoint, baseURL fmt.Stringer, rule rulelib.Rule, obs Observation) Observation {
	parsed, err := rulelib.ParseNuclei(rule.Template)
	if err != nil {
		return pocError(obs, "nuclei template failed strict validation: "+err.Error())
	}
	binary, err := exec.LookPath(a.cfg.NucleiBinary)
	if err != nil {
		return pocError(obs, fmt.Sprintf("nuclei executable %q was not found", a.cfg.NucleiBinary))
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return pocError(obs, "resolve nuclei executable: "+err.Error())
	}
	workDir, err := os.MkdirTemp("", "scanplatform-nuclei-")
	if err != nil {
		return pocError(obs, "create nuclei workspace: "+err.Error())
	}
	defer os.RemoveAll(workDir)
	for _, dir := range []string{"home", "config", "cache", "templates", "tmp"} {
		if err := os.Mkdir(filepath.Join(workDir, dir), 0o700); err != nil {
			return pocError(obs, "prepare nuclei workspace: "+err.Error())
		}
	}
	templatePath := filepath.Join(workDir, "template.yaml")
	if err := os.WriteFile(templatePath, []byte(parsed.Template), 0o600); err != nil {
		return pocError(obs, "write nuclei template: "+err.Error())
	}
	errorLog := filepath.Join(workDir, "errors.log")

	proxy, err := a.startScopeProxy(ctx, ep, baseURL.String(), parsed.Definition.Requests)
	if err != nil {
		return pocError(obs, "start nuclei scope proxy: "+err.Error())
	}
	defer proxy.Close()
	args := []string{
		"-target", baseURL.String(), "-templates", templatePath, "-type", "http",
		"-jsonl", "-silent", "-no-color", "-matcher-status", "-include-rr",
		"-disable-update-check", "-no-interactsh", "-disable-redirects", "-no-httpx", "-no-stdin",
		"-proxy", proxy.URL(), "-proxy-internal", "-auth=false",
		"-rate-limit", "3", "-bulk-size", "1", "-concurrency", "1", "-payload-concurrency", "1",
		"-retries", "0", "-timeout", "8", "-response-size-read", "1048576", "-response-size-save", "196608",
		"-error-log", errorLog,
	}
	cmd := exec.Command(binary, args...)
	setProcessGroup(cmd)
	cmd.Dir = workDir
	cmd.Env = nucleiEnvironment(workDir)
	stdout := &boundedCapture{limit: maxNucleiOutput}
	stderr := &stderrTail{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return pocError(obs, "start nuclei: "+err.Error())
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	var waitErr error
	select {
	case <-ctx.Done():
		killProcessGroup(cmd.Process)
		waitErr = <-waitDone
		_ = waitErr
		waitErr = context.Cause(ctx)
	case waitErr = <-waitDone:
	}
	if waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = waitErr.Error()
		}
		return nucleiError(obs, "nuclei execution failed: "+detail, proxy)
	}
	if stdout.overflow {
		return nucleiError(obs, fmt.Sprintf("nuclei JSONL exceeded %d bytes", maxNucleiOutput), proxy)
	}
	if scopeErr := proxy.Err(); scopeErr != nil {
		return nucleiError(obs, "nuclei scope proxy: "+scopeErr.Error(), proxy)
	}
	if data, readErr := os.ReadFile(errorLog); readErr == nil && strings.TrimSpace(string(data)) != "" {
		message, _ := truncateBytes(data, 64<<10)
		return nucleiError(obs, "nuclei request error: "+strings.TrimSpace(message), proxy)
	} else if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nucleiError(obs, "read nuclei error log: "+readErr.Error(), proxy)
	}
	return nucleiOutcome(obs, rule, stdout.Bytes(), proxy)
}

func nucleiError(obs Observation, message string, proxy *scopeProxy) Observation {
	if obs.RequestRaw == "" && obs.ResponseRaw == "" {
		obs.RequestRaw, obs.ResponseRaw = proxy.Evidence()
	}
	obs.Truncated = obs.Truncated || proxy.Truncated()
	return pocError(obs, message)
}

func nucleiEnvironment(workDir string) []string {
	return []string{
		"HOME=" + filepath.Join(workDir, "home"),
		"XDG_CONFIG_HOME=" + filepath.Join(workDir, "config"),
		"XDG_CACHE_HOME=" + filepath.Join(workDir, "cache"),
		"TMPDIR=" + filepath.Join(workDir, "tmp"),
		"NUCLEI_TEMPLATES_DIR=" + filepath.Join(workDir, "templates"),
		"DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true",
		"DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD=true",
		"DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD=true",
		"DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD=true",
		"DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD=true",
		"NO_COLOR=1",
	}
}

func nucleiOutcome(obs Observation, rule rulelib.Rule, output []byte, proxy *scopeProxy) Observation {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64<<10), maxNucleiLine)
	matched, events, truncated := false, 0, false
	var requests, responses bytes.Buffer
	var jsonEvidence bytes.Buffer
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event nucleiEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nucleiError(obs, "invalid nuclei JSONL: "+err.Error(), proxy)
		}
		if event.TemplateID != rule.ID {
			return nucleiError(obs, fmt.Sprintf("nuclei returned unexpected template id %q", event.TemplateID), proxy)
		}
		if event.Error != "" {
			return nucleiError(obs, "nuclei request error: "+event.Error, proxy)
		}
		if event.MatcherStatus == nil {
			return nucleiError(obs, "nuclei JSONL omitted matcher-status", proxy)
		}
		if !proxy.ResultAllowed(event.MatchedAt, event.Request) {
			return nucleiError(obs, fmt.Sprintf("nuclei returned out-of-scope result matched-at=%q host=%q path=%q", event.MatchedAt, event.Host, event.Path), proxy)
		}
		events++
		if *event.MatcherStatus {
			matched = true
		}
		appendBounded(&requests, event.Request, maxRawRequest)
		appendBounded(&responses, event.Response, maxRawResponse)
		appendBounded(&jsonEvidence, string(line), 32<<10)
		truncated = truncated || len(event.Response) >= maxNucleiSavedResponse
	}
	if err := scanner.Err(); err != nil {
		return nucleiError(obs, "read nuclei JSONL: "+err.Error(), proxy)
	}
	if proxy.RequestCount() == 0 {
		return pocError(obs, "nuclei completed without issuing a scoped request")
	}
	if events == 0 {
		return nucleiError(obs, "nuclei completed without a valid matcher-status event", proxy)
	}
	if requests.Len() == 0 && responses.Len() == 0 {
		proxyRequest, proxyResponse := proxy.Evidence()
		appendBounded(&requests, proxyRequest, maxRawRequest)
		appendBounded(&responses, proxyResponse, maxRawResponse)
	}
	obs.RequestRaw, obs.ResponseRaw = requests.String(), responses.String()
	obs.Truncated = truncated || requests.Len() >= maxRawRequest || responses.Len() >= maxRawResponse || proxy.Truncated()
	if !matched && obs.Truncated {
		return nucleiError(obs, "nuclei response evidence was truncated; negative result is incomplete", proxy)
	}
	if matched {
		obs.FindingStatus = "matched"
		obs.Evidence = "nuclei matcher status matched"
	} else {
		obs.FindingStatus = "not_matched"
		obs.Evidence = "nuclei completed the scoped read-only request; matchers did not match"
	}
	if jsonEvidence.Len() > 0 {
		obs.Evidence += "; JSONL: " + jsonEvidence.String()
	}
	return obs
}

func pocError(obs Observation, message string) Observation {
	obs.FindingStatus, obs.Error, obs.Evidence = "error", message, message
	return obs
}
