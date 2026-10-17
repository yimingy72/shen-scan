package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanplatform/internal/rulelib"
)

const (
	maxHTTPXCFFBytes = 32 << 20
	maxHTTPXJSONLine = 8 << 20
)

type httpxResult struct {
	URL           string         `json:"url"`
	Input         string         `json:"input"`
	Scheme        string         `json:"scheme"`
	Port          string         `json:"port"`
	Title         string         `json:"title"`
	WebServer     string         `json:"webserver"`
	Body          string         `json:"body"`
	RawHeader     string         `json:"raw_header"`
	Request       string         `json:"request"`
	Error         string         `json:"error"`
	Host          string         `json:"host"`
	HostIP        string         `json:"host_ip"`
	Headers       map[string]any `json:"header"`
	Technologies  []string       `json:"tech"`
	StatusCode    int            `json:"status_code"`
	ContentLength int            `json:"content_length"`
	Failed        bool           `json:"failed"`
}

type httpxJSONLWriter struct {
	buffer bytes.Buffer
	err    error
	handle func([]byte) error
	failed chan struct{}
	once   sync.Once
}

func (writer *httpxJSONLWriter) fail(err error) {
	writer.err = err
	if writer.failed != nil {
		writer.once.Do(func() { close(writer.failed) })
	}
}

func (writer *httpxJSONLWriter) Write(data []byte) (int, error) {
	written := len(data)
	if writer.err != nil {
		return written, nil
	}
	_, _ = writer.buffer.Write(data)
	for {
		line, err := writer.buffer.ReadBytes('\n')
		if err != nil {
			_, _ = writer.buffer.Write(line)
			if writer.buffer.Len() > maxHTTPXJSONLine {
				writer.fail(fmt.Errorf("httpx JSONL line exceeds %d bytes", maxHTTPXJSONLine))
			}
			return written, nil
		}
		if len(line) > maxHTTPXJSONLine {
			writer.fail(fmt.Errorf("httpx JSONL line exceeds %d bytes", maxHTTPXJSONLine))
			return written, nil
		}
		if line = bytes.TrimSpace(line); len(line) > 0 {
			if err := writer.handle(line); err != nil {
				writer.fail(err)
				return written, nil
			}
		}
	}
}

func (writer *httpxJSONLWriter) finish() error {
	if writer.err != nil {
		return writer.err
	}
	line := bytes.TrimSpace(writer.buffer.Bytes())
	if len(line) == 0 {
		return nil
	}
	if len(line) > maxHTTPXJSONLine {
		return fmt.Errorf("httpx JSONL line exceeds %d bytes", maxHTTPXJSONLine)
	}
	return writer.handle(line)
}

func hasEnabledHTTPXCFF(rules []rulelib.Rule) bool {
	for _, rule := range rules {
		if rule.Enabled && rule.Engine == "httpx-cff" {
			return true
		}
	}
	return false
}

func buildHTTPXCFF(rules []rulelib.Rule) ([]byte, error) {
	apps := make(map[string]json.RawMessage)
	for _, rule := range rules {
		if rule.Engine != "httpx-cff" || !rule.Enabled {
			continue
		}
		product := rule.Definition.Product
		if _, exists := apps[product]; exists {
			return nil, fmt.Errorf("duplicate enabled httpx product %q", product)
		}
		var object map[string]any
		if strings.TrimSpace(product) == "" || json.Unmarshal(rule.Fingerprint, &object) != nil || object == nil {
			return nil, fmt.Errorf("rule %q has an invalid httpx fingerprint", rule.ID)
		}
		apps[product] = append([]byte(nil), rule.Fingerprint...)
	}
	if len(apps) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(struct {
		Apps map[string]json.RawMessage `json:"apps"`
	}{Apps: apps})
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxHTTPXCFFBytes {
		return nil, fmt.Errorf("enabled httpx fingerprint snapshot exceeds %d bytes", maxHTTPXCFFBytes)
	}
	return encoded, nil
}

func (a *Agent) runHTTPX(ctx context.Context, endpoints []Endpoint, rules []rulelib.Rule, cff []byte, timeout time.Duration, emit func(Observation) error) error {
	// Keep the existing protocol fallback for port-derived endpoints. Explicit
	// input URLs keep their requested scheme.
	originals := make(map[string]Endpoint, len(endpoints))
	for _, endpoint := range endpoints {
		raw, err := endpointURL(endpoint)
		if err != nil {
			return err
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return err
		}
		originals[httpxInputKey(parsed)] = endpoint
	}
	var alternate []Endpoint
	failed := make(map[string]Observation)
	if err := a.runHTTPXBatch(ctx, endpoints, rules, cff, timeout, func(observation Observation) error {
		parsed, _ := url.Parse(observation.URL)
		endpoint, ok := originals[httpxInputKey(parsed)]
		if !ok || endpoint.URL != "" || observation.StatusCode != 0 {
			return emit(observation)
		}
		if parsed.Scheme == "http" {
			parsed.Scheme = "https"
		} else {
			parsed.Scheme = "http"
		}
		endpoint.URL = parsed.String()
		alternate = append(alternate, endpoint)
		failed[httpxInputKey(parsed)] = observation
		return nil
	}); err != nil {
		return err
	}
	if len(alternate) == 0 {
		return nil
	}
	return a.runHTTPXBatch(ctx, alternate, rules, cff, timeout, func(observation Observation) error {
		parsed, _ := url.Parse(observation.URL)
		first := failed[httpxInputKey(parsed)]
		observation.Target = first.Target
		if observation.StatusCode == 0 {
			observation.Error = first.Error + "; alternate protocol: " + observation.Error
		}
		return emit(observation)
	})
}

func (a *Agent) runHTTPXBatch(ctx context.Context, endpoints []Endpoint, rules []rulelib.Rule, cff []byte, timeout time.Duration, emit func(Observation) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if len(cff) == 0 {
		return &TaskError{Reason: "httpx task has no enabled fingerprints", Retryable: false}
	}
	select {
	case a.httpxSlots <- struct{}{}:
		defer func() { <-a.httpxSlots }()
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	binary, err := exec.LookPath(a.cfg.HTTPXBinary)
	if err != nil {
		return &TaskError{Reason: fmt.Sprintf("httpx executable %q was not found", a.cfg.HTTPXBinary), Retryable: true}
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return &TaskError{Reason: "resolve httpx executable: " + err.Error(), Retryable: true}
	}
	workDir, err := os.MkdirTemp("", "scanplatform-httpx-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)
	for _, directory := range []string{"home", "config", "cache", "tmp"} {
		if err := os.Mkdir(filepath.Join(workDir, directory), 0o700); err != nil {
			return err
		}
	}
	targets, err := prepareHTTPXTargets(ctx, a, endpoints)
	if err != nil {
		return &TaskError{Reason: "invalid httpx target: " + err.Error(), Retryable: false}
	}
	proxy, err := a.startHTTPXScopeProxy(ctx, targets)
	if err != nil {
		return &TaskError{Reason: "start httpx scope proxy: " + err.Error(), Retryable: true}
	}
	defer proxy.Close()
	targetPath := filepath.Join(workDir, "targets.txt")
	if err := os.WriteFile(targetPath, []byte(strings.Join(httpxTargetURLs(targets), "\n")+"\n"), 0o600); err != nil {
		return err
	}
	cffPath := filepath.Join(workDir, "fingerprints.json")
	if err := os.WriteFile(cffPath, cff, 0o600); err != nil {
		return err
	}
	timeoutSeconds := int(timeout / time.Second)
	if timeoutSeconds < 1 {
		timeoutSeconds = 1
	}
	args := []string{
		"-list", targetPath, "-json", "-include-response", "-probe",
		"-status-code", "-title", "-web-server", "-tech-detect", "-custom-fingerprint-file", cffPath,
		"-silent", "-no-color", "-disable-update-check", "-no-stdin", "-no-fallback-scheme", "-stream",
		"-proxy", proxy.URL(), "-auth=false", "-cdn=false", "-random-agent=false",
		"-threads", strconv.Itoa(a.cfg.HTTPXThreads), "-rate-limit", strconv.Itoa(a.cfg.HTTPXThreads),
		"-retries", "0", "-timeout", strconv.Itoa(timeoutSeconds), "-max-host-error", strconv.Itoa(max(4, len(targets)*2)),
		"-response-size-to-read", strconv.Itoa(maxHTTPBody), "-response-size-to-save", strconv.Itoa(maxHTTPBody),
	}
	seen := make(map[string]bool, len(targets))
	writer := &httpxJSONLWriter{failed: make(chan struct{}), handle: func(line []byte) error {
		var result httpxResult
		if err := json.Unmarshal(line, &result); err != nil {
			return fmt.Errorf("decode httpx JSONL: %w", err)
		}
		observation, err := httpxObservation(result, proxy, rules)
		if err != nil {
			return err
		}
		input := result.Input
		if input == "" {
			input = result.URL
		}
		target, ok := proxy.Target(input)
		if !ok {
			return fmt.Errorf("httpx returned an unknown input %q", input)
		}
		key := httpxInputKey(target.url)
		if seen[key] {
			return nil
		}
		seen[key] = true
		return emit(observation)
	}}
	stderr := &stderrTail{limit: 64 << 10}
	cmd := exec.CommandContext(ctx, binary, args...)
	setProcessGroup(cmd)
	cmd.Dir = workDir
	cmd.Env = httpxEnvironment(workDir)
	cmd.Stdout = writer
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return &TaskError{Reason: "start httpx: " + err.Error(), Retryable: true}
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	var waitErr error
	select {
	case <-ctx.Done():
		killProcessGroup(cmd.Process)
		<-waitDone
		return context.Cause(ctx)
	case <-writer.failed:
		killProcessGroup(cmd.Process)
		<-waitDone
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		return &TaskError{Reason: writer.err.Error(), Retryable: false}
	case waitErr = <-waitDone:
	}
	if err := writer.finish(); err != nil {
		return &TaskError{Reason: err.Error(), Retryable: false}
	}
	if scopeErr := proxy.Err(); scopeErr != nil {
		return &TaskError{Reason: "httpx scope proxy: " + scopeErr.Error(), Retryable: false}
	}
	if waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = waitErr.Error()
		}
		return &TaskError{Reason: "httpx execution failed: " + detail, Retryable: true}
	}
	if len(seen) != len(proxy.inputs) {
		return &TaskError{Reason: fmt.Sprintf("httpx returned %d of %d target results", len(seen), len(proxy.inputs)), Retryable: true}
	}
	return nil
}

func httpxEnvironment(workDir string) []string {
	return []string{
		"HOME=" + filepath.Join(workDir, "home"),
		"XDG_CONFIG_HOME=" + filepath.Join(workDir, "config"),
		"XDG_CACHE_HOME=" + filepath.Join(workDir, "cache"),
		"TMPDIR=" + filepath.Join(workDir, "tmp"),
		"NO_COLOR=1",
	}
}

func httpxTargetURLs(targets []httpxScopeTarget) []string {
	urls := make([]string, len(targets))
	for index := range targets {
		urls[index] = targets[index].url.String()
	}
	sort.Strings(urls)
	return urls
}

func httpxObservation(result httpxResult, proxy *httpxScopeProxy, rules []rulelib.Rule) (Observation, error) {
	input := result.Input
	if input == "" {
		input = result.URL
	}
	target, ok := proxy.Target(input)
	if !ok {
		return Observation{}, fmt.Errorf("httpx returned out-of-scope input %q", input)
	}
	if result.URL == "" && result.Failed {
		result.URL = target.url.String()
	}
	observed, err := url.Parse(result.URL)
	if err != nil || httpxOrigin(observed) != target.origin || observed.User != nil || observed.Fragment != "" {
		return Observation{}, fmt.Errorf("httpx returned out-of-scope URL %q", result.URL)
	}
	observation := Observation{Kind: "http", WorkKey: target.endpoint.WorkKey, Target: endpointTarget(target.endpoint), URL: result.URL, Title: result.Title, Server: result.WebServer, StatusCode: result.StatusCode}
	observation.Protocol = target.url.Scheme
	observation.Port, _ = strconv.Atoi(urlPort(target.url))
	if target.endpoint.IP != "" {
		observation.IP = target.endpoint.IP
	} else {
		observation.IP = proxy.connectedIP(target.origin)
	}
	if result.Failed || result.Error != "" {
		observation.Error = strings.TrimSpace(result.Error)
		if observation.Error == "" {
			observation.Error = "httpx probe failed"
		}
		return observation, nil
	}
	var requestTruncated, responseTruncated bool
	observation.RequestRaw, requestTruncated = truncateBytes([]byte(result.Request), maxRawRequest)
	observation.ResponseRaw, responseTruncated = truncateBytes([]byte(httpxRawResponse(result)), maxRawResponse)
	observation.Headers = httpxHeaders(result.Headers)
	observation.BodyExcerpt, _ = truncateBytes([]byte(result.Body), maxBodyExcerpt)
	observation.Truncated = result.ContentLength > len(result.Body) || len(result.Body) >= maxHTTPBody || requestTruncated || responseTruncated
	header := result.RawHeader
	observation.httpBody, observation.httpHeader = result.Body, header
	observation.Technologies = mergeTechnologies(httpxTechnologies(result.Technologies, rules), matchHTTPRules(nativeHTTPRules(rules), observation))
	observation.httpBody, observation.httpHeader = "", ""
	return observation, nil
}

func httpxRawResponse(result httpxResult) string {
	header := strings.TrimRight(result.RawHeader, "\r\n")
	if !strings.HasPrefix(header, "HTTP/") {
		status := http.StatusText(result.StatusCode)
		header = fmt.Sprintf("HTTP/1.1 %d %s\r\n%s", result.StatusCode, status, header)
	}
	return header + "\r\n\r\n" + result.Body
}

func httpxHeaders(values map[string]any) http.Header {
	headers := make(http.Header, len(values))
	for name, value := range values {
		switch typed := value.(type) {
		case string:
			headers.Add(name, typed)
		case []any:
			for _, item := range typed {
				headers.Add(name, fmt.Sprint(item))
			}
		default:
			headers.Add(name, fmt.Sprint(value))
		}
	}
	return headers
}

func nativeHTTPRules(rules []rulelib.Rule) []rulelib.Rule {
	native := make([]rulelib.Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.Engine == "native" {
			native = append(native, rule)
		}
	}
	return native
}

func httpxTechnologies(detected []string, rules []rulelib.Rule) []Technology {
	// httpx v1.12 loads its embedded database even when -cff is set. Keep only
	// products enabled in this immutable task snapshot.
	enabled := make([]rulelib.Rule, 0)
	for _, rule := range rules {
		if rule.Engine == "httpx-cff" && rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	sort.Slice(enabled, func(left, right int) bool {
		return len(enabled[left].Definition.Product) > len(enabled[right].Definition.Product)
	})
	technologies := make([]Technology, 0, len(detected))
	seen := make(map[string]bool)
	for _, value := range detected {
		for _, rule := range enabled {
			product := rule.Definition.Product
			version := ""
			if value != product {
				prefix := product + ":"
				if len(value) <= len(prefix) || !strings.HasPrefix(value, prefix) {
					continue
				}
				version = value[len(prefix):]
			}
			key := strings.ToLower(product)
			if !seen[key] {
				technologies = append(technologies, Technology{Name: product, Version: version, Evidence: "httpx-cff technology match", RuleID: rule.ID, RuleRevision: rule.Revision})
				seen[key] = true
			}
			break
		}
	}
	return technologies
}

func mergeTechnologies(groups ...[]Technology) []Technology {
	var merged []Technology
	seen := make(map[string]int)
	for _, group := range groups {
		for _, technology := range group {
			key := strings.ToLower(technology.Name)
			if index, ok := seen[key]; ok {
				if merged[index].Version == "" && technology.Version != "" {
					merged[index] = technology
				}
				continue
			}
			seen[key] = len(merged)
			merged = append(merged, technology)
		}
	}
	return merged
}
