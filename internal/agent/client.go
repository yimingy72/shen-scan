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
	"strings"
	"time"
)

const maxControlResponse = 4 << 20

type Client struct {
	baseURL     string
	joinToken   string
	workerToken string
	control     *http.Client
	upload      *http.Client
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

func (c *Client) Claim(ctx context.Context, workerID, sessionID, requestID string, types []string) (*Task, error) {
	var out struct {
		Task *Task `json:"task"`
	}
	sentAt, err := c.do(ctx, c.control, http.MethodPost, "/api/tasks/claim", c.workerToken, map[string]any{
		"worker_id": workerID, "session_id": sessionID, "request_id": requestID,
		"types": types,
	}, &out)
	if out.Task != nil {
		out.Task.requestSentAt = sentAt
	}
	return out.Task, err
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
	}, &out)
	if err == nil && !out.Released {
		return fmt.Errorf("task was not released")
	}
	return err
}

func (c *Client) do(ctx context.Context, client *http.Client, method, path, token string, in, out any) (time.Time, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxControlResponse+1))
	if err != nil {
		return sentAt, err
	}
	if len(data) > maxControlResponse {
		return sentAt, fmt.Errorf("control response exceeds %d bytes", maxControlResponse)
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
