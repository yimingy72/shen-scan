package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"scanplatform/internal/rulelib"
)

const (
	maxControlResponse = 4 << 20
	maxRuleSetResponse = 16 << 20
)

type Client struct {
	serviceCapabilityOnce   sync.Once
	nmapBinary              string
	serviceProfile          string
	webCapabilityOnce       sync.Once
	webEnrichmentProfile    string
	webEvidenceProfile      string
	fingerprintBundle       string
	fingerprintBundleSchema string
	baseURL                 string
	joinToken               string
	workerToken             string
	control                 *http.Client
	upload                  *http.Client
}

func NewClient(baseURL, joinToken, caFile string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid control URL %q", baseURL)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read agent CA file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("agent CA file contains no valid PEM certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &Client{
		baseURL: u.String(), joinToken: joinToken,
		control: &http.Client{Transport: transport, Timeout: 5 * time.Second},
		upload:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}, nil
}

func (c *Client) Register(ctx context.Context, in RegisterRequest) (RegisterResponse, error) {
	var out RegisterResponse
	_, err := c.do(ctx, c.control, http.MethodPost, "/api/workers/register", c.joinToken, in, &out)
	if err == nil {
		if out.WorkerID == "" || out.WorkerToken == "" {
			return out, fmt.Errorf("register returned empty worker credentials")
		}
		c.workerToken = out.WorkerToken
	}
	return out, err
}

func (c *Client) Heartbeat(ctx context.Context, in HeartbeatRequest) (HeartbeatResponse, error) {
	var out HeartbeatResponse
	_, err := c.do(ctx, c.control, http.MethodPost, "/api/workers/heartbeat", c.workerToken, in, &out)
	return out, err
}

func (c *Client) Claim(ctx context.Context, workerID, sessionID, requestID string, types []string, supportsNucleiOriginal bool, portStartReserved ...bool) (*Task, error) {
	var out struct {
		Task *Task `json:"task"`
	}
	reserved := len(portStartReserved) > 0 && portStartReserved[0]
	c.serviceCapabilityOnce.Do(func() {
		binary := c.nmapBinary
		if binary == "" {
			binary = "nmap"
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(probeCtx, binary, "--version")
		setProcessGroup(cmd)
		output, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "Nmap version ") {
			c.serviceProfile = "nmap-light-v1"
		}
	})
	c.webCapabilityOnce.Do(func() {
		c.webEvidenceProfile, c.fingerprintBundle, c.fingerprintBundleSchema, c.webEnrichmentProfile = discoverWebCapabilitiesFull()
	})
	claim := map[string]any{
		"worker_id": workerID, "session_id": sessionID, "request_id": requestID,
		"types": types, "use_rule_sets": true, "supports_httpx_cff": true,
		"supports_nuclei_http_original": supportsNucleiOriginal,
		"supports_nuclei_http_batch":    len(portStartReserved) > 1 && portStartReserved[1],
		"supports_confirmed_stop":       true,
		"supports_http_request_budget":  true,
		"service_profile":               c.serviceProfile,
		"supports_port_ranges":          true, "port_start_reserved": reserved,
		"web_evidence_profile": c.webEvidenceProfile, "fingerprint_bundle": c.fingerprintBundle,
		"fingerprint_bundle_schema": c.fingerprintBundleSchema,
	}
	if c.webEnrichmentProfile != "" {
		claim["web_enrichment_profile"] = c.webEnrichmentProfile
	}
	sentAt, err := c.do(ctx, c.control, http.MethodPost, "/api/tasks/claim", c.workerToken, claim, &out)
	if out.Task != nil {
		out.Task.requestSentAt = sentAt
	}
	return out.Task, err
}

type ruleSetResponse struct {
	Ref   string         `json:"ref"`
	Kind  string         `json:"kind"`
	Rules []rulelib.Rule `json:"rules"`
}

func (c *Client) Rules(ctx context.Context, workerID, sessionID string, task Task) (ruleSetResponse, error) {
	var out ruleSetResponse
	query := url.Values{
		"worker_id":  []string{workerID},
		"session_id": []string{sessionID},
		"attempt_no": []string{fmt.Sprint(task.AttemptNo)},
	}
	rulesCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := c.doLimit(rulesCtx, c.upload, http.MethodGet, "/api/tasks/"+url.PathEscape(task.ID)+"/rules?"+query.Encode(), c.workerToken, nil, &out, maxRuleSetResponse)
	return out, err
}

func (c *Client) Renew(ctx context.Context, workerID, sessionID string, task Task) (renewResponse, time.Time, error) {
	var out renewResponse
	sentAt, err := c.do(ctx, c.control, http.MethodPost, "/api/tasks/"+url.PathEscape(task.ID)+"/renew", c.workerToken, map[string]any{
		"worker_id": workerID, "session_id": sessionID, "attempt_no": task.AttemptNo,
	}, &out)
	return out, sentAt, err
}

func (c *Client) Batch(ctx context.Context, workerID, sessionID string, task Task, seq int, items []Observation) error {
	var out struct {
		Accepted bool `json:"accepted"`
	}
	_, err := c.do(ctx, c.upload, http.MethodPost, "/api/tasks/"+url.PathEscape(task.ID)+"/batches", c.workerToken, map[string]any{
		"worker_id": workerID, "session_id": sessionID, "attempt_no": task.AttemptNo,
		"batch_seq": seq, "items": items,
	}, &out)
	if err == nil && !out.Accepted {
		return fmt.Errorf("batch %d was not accepted", seq)
	}
	return err
}

func (c *Client) Complete(ctx context.Context, workerID, sessionID string, task Task, lastSeq int) error {
	var out struct {
		Completed bool `json:"completed"`
	}
	_, err := c.do(ctx, c.upload, http.MethodPost, "/api/tasks/"+url.PathEscape(task.ID)+"/complete", c.workerToken, map[string]any{
		"worker_id": workerID, "session_id": sessionID, "attempt_no": task.AttemptNo, "last_batch_seq": lastSeq,
	}, &out)
	if err == nil && !out.Completed {
		return fmt.Errorf("task was not completed")
	}
	return err
}

func (c *Client) Release(ctx context.Context, workerID, sessionID string, task Task, reason string, retryable bool, failureClass string) error {
	var out struct {
		Released bool `json:"released"`
	}
	_, err := c.do(ctx, c.upload, http.MethodPost, "/api/tasks/"+url.PathEscape(task.ID)+"/release", c.workerToken, map[string]any{
		"worker_id": workerID, "session_id": sessionID, "attempt_no": task.AttemptNo,
		"reason": reason, "retryable": retryable, "failure_class": failureClass,
		"stopped": true,
	}, &out)
	if err == nil && !out.Released {
		return fmt.Errorf("task was not released")
	}
	return err
}

func (c *Client) do(ctx context.Context, client *http.Client, method, path, token string, in, out any) (time.Time, error) {
	return c.doLimit(ctx, client, method, path, token, in, out, maxControlResponse)
}

func (c *Client) doLimit(ctx context.Context, client *http.Client, method, requestPath, token string, in, out any, responseLimit int) (time.Time, error) {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return time.Time{}, err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+requestPath, body)
	if err != nil {
		return time.Time{}, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	sentAt := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sentAt, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(responseLimit)+1))
	if err != nil {
		return sentAt, err
	}
	if len(data) > responseLimit {
		return sentAt, fmt.Errorf("control response exceeds %d bytes", responseLimit)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Error != "" {
			return sentAt, fmt.Errorf("control API %s: %s", resp.Status, apiErr.Error)
		}
		return sentAt, fmt.Errorf("control API %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) != 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return sentAt, fmt.Errorf("decode control response: %w", err)
		}
	}
	return sentAt, nil
}
