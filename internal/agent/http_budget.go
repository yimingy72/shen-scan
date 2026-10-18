package agent

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"scanplatform/internal/httpadmission"
)

type httpBudgetKey struct{}
type httpFullSegmentKey struct{}
type httpTaskBudget struct {
	agent *Agent
	task  Task
	lock  chan struct{}
	seq   int64
}

func (a *Agent) withHTTPBudget(ctx context.Context, task Task) context.Context {
	return context.WithValue(ctx, httpBudgetKey{}, &httpTaskBudget{agent: a, task: task, lock: make(chan struct{}, 1)})
}

func admitHTTPRequest(ctx context.Context, ip, host, port string) error {
	_, err := admitHTTPPermit(ctx, ip, host, port)
	return err
}
func admitHTTPPermit(ctx context.Context, ip, host, port string) (time.Time, error) {
	return admitHTTPPermitMode(ctx, ip, host, port, true)
}
func admitHTTPPermitMode(ctx context.Context, ip, host, port string, wait bool) (time.Time, error) {
	budget, ok := ctx.Value(httpBudgetKey{}).(*httpTaskBudget)
	if !ok {
		return time.Now().Add(500 * time.Millisecond), nil
	} // Internal standalone collectors used by local fixtures.
	// The server retains a single monotonic receipt/task. Serialize admissions so
	// concurrent entries cannot reorder IDs or mistake a newer receipt for a replay.
	select {
	case budget.lock <- struct{}{}:
		defer func() { <-budget.lock }()
	case <-ctx.Done():
		return time.Time{}, context.Cause(ctx)
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, context.Cause(ctx)
	}
	budget.seq++
	number, err := strconv.Atoi(port)
	if err != nil || net.ParseIP(ip) == nil {
		return time.Time{}, fmt.Errorf("invalid HTTP admission target")
	}
	request := map[string]any{
		"worker_id": budget.agent.workerID, "session_id": budget.agent.cfg.SessionID,
		"attempt_no": budget.task.AttemptNo, "request_id": strconv.FormatInt(budget.seq, 10),
		"connect_ip": ip, "host": host, "port": number,
	}
	if segment, ok := ctx.Value(httpFullSegmentKey{}).(int); ok {
		request["segment"] = segment
	}
	for {
		var response struct {
			Granted      bool      `json:"granted"`
			ServerTime   time.Time `json:"server_time"`
			ValidUntil   time.Time `json:"valid_until"`
			RetryAfterMS int64     `json:"retry_after_ms"`
		}
		sentAt, err := budget.agent.client.do(ctx, budget.agent.client.control, http.MethodPost, "/api/tasks/"+url.PathEscape(budget.task.ID)+"/http-permit", budget.agent.client.workerToken, request, &response)
		if err != nil {
			return time.Time{}, fmt.Errorf("HTTP permit: %w", err)
		}
		if response.Granted {
			// Use send time and a small safety margin, never Worker/server wall-clock
			// subtraction. A slow response consumes the permission instead of extending it.
			deadline := sentAt.Add(response.ValidUntil.Sub(response.ServerTime) - 25*time.Millisecond)
			if response.ServerTime.IsZero() || response.ValidUntil.IsZero() || !time.Now().Before(deadline) {
				return time.Time{}, fmt.Errorf("HTTP permit expired before request start")
			}
			if err := ctx.Err(); err != nil {
				return time.Time{}, context.Cause(ctx)
			}
			return deadline, nil
		}
		if response.RetryAfterMS < 1 || response.RetryAfterMS > 5000 {
			return time.Time{}, fmt.Errorf("invalid HTTP permit retry interval")
		}
		if !wait {
			return time.Time{}, httpadmission.ErrPending
		}
		timer := time.NewTimer(time.Duration(response.RetryAfterMS) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return time.Time{}, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

type budgetHTTPTransport struct {
	transport *http.Transport
	timeout   time.Duration
}

func (b budgetHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return (httpadmission.Transport{Base: b.transport, NetworkTimeout: b.timeout, Permit: admitHTTPPermitMode}).RoundTrip(request)
}

// This callback carries only one item's random bearer token. Worker credentials
// and the complete task binding remain in this process, never helper IPC/env.
type webEntryBudget struct {
	mu         sync.Mutex
	used       int
	operations map[string]string
	maximum    int
}

func (b *webEntryBudget) consumeAtLeast(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used = max(b.used, n)
}
func (b *webEntryBudget) count() int { b.mu.Lock(); defer b.mu.Unlock(); return b.used }

type webAdmissionLimit struct {
	entry       *webEntryBudget
	exactURL    bool
	maxRequests int
}

func startWebAdmission(ctx context.Context, inputID, fixedIP string, base *url.URL, alternate bool) (string, string, func(), error) {
	return startWebAdmissionLimited(ctx, inputID, fixedIP, base, alternate, nil)
}
func startWebAdmissionLimited(ctx context.Context, inputID, fixedIP string, base *url.URL, alternate bool, limit *webAdmissionLimit) (string, string, func(), error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", "", nil, err
	}
	token, err := RandomID()
	if err != nil {
		listener.Close()
		return "", "", nil, err
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	localOperations := map[int]string{}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		if r.Method != http.MethodPost || r.URL.Path != "/admit" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		var item struct {
			ID         string `json:"id"`
			URL        string `json:"url"`
			Wait       *bool  `json:"wait,omitempty"`
			RequestSeq int    `json:"request_seq,omitempty"`
		}
		bodyLimit := int64(4097)
		if limit != nil {
			bodyLimit = 8193
		}
		if json.NewDecoder(io.LimitReader(r.Body, bodyLimit)).Decode(&item) != nil || item.ID != inputID {
			http.Error(w, "invalid item", 400)
			return
		}
		target, err := url.Parse(item.URL)
		if err != nil || target.User != nil || target.Fragment != "" || !sameAuthority(target, base) || (target.Scheme != base.Scheme && (!alternate || target.Scheme != "http" && target.Scheme != "https")) {
			http.Error(w, "outside entry", 400)
			return
		}
		if limit != nil {
			if !strings.EqualFold(target.Hostname(), base.Hostname()) {
				http.Error(w, "outside exact entry host", 400)
				return
			}
			limit.entry.mu.Lock()
			defer limit.entry.mu.Unlock()
			maximum := limit.entry.maximum
			if maximum <= 0 {
				maximum = 8
			}
			if item.RequestSeq < 1 || item.RequestSeq > maximum {
				http.Error(w, "invalid logical request sequence", 400)
				return
			}
			if limit.exactURL && (target.Scheme != base.Scheme || target.EscapedPath() != base.EscapedPath() || target.RawQuery != base.RawQuery || target.ForceQuery != base.ForceQuery) {
				http.Error(w, "outside supplemental URL", 400)
				return
			}
			if prior, exists := localOperations[item.RequestSeq]; exists && prior != item.URL {
				http.Error(w, "logical request URL changed", 400)
				return
			}
			key := item.ID + "/" + strconv.Itoa(item.RequestSeq)
			if limit.entry.operations == nil {
				limit.entry.operations = map[string]string{}
			}
			if prior, exists := limit.entry.operations[key]; exists {
				if prior != item.URL {
					http.Error(w, "logical request URL changed", 400)
					return
				}
			} else {
				if limit.entry.used >= maximum || limit.maxRequests > 0 && len(localOperations) >= limit.maxRequests {
					http.Error(w, "entry request budget exhausted", 429)
					return
				}
				limit.entry.used++
				limit.entry.operations[key] = item.URL
				localOperations[item.RequestSeq] = item.URL
			}
		}
		wait := item.Wait == nil || *item.Wait
		deadline, err := admitHTTPPermitMode(r.Context(), fixedIP, target.Hostname(), urlPort(target), wait)
		if err != nil {
			if errors.Is(err, httpadmission.ErrPending) {
				http.Error(w, "pending", http.StatusTooManyRequests)
				return
			}
			http.Error(w, "admission failed", 503)
			return
		}
		now := time.Now()
		json.NewEncoder(w).Encode(map[string]int64{
			"valid_for_ms": max(int64(0), deadline.Sub(now).Milliseconds()),
			"waited_ms":    now.Sub(started).Milliseconds(),
		})
	})
	go server.Serve(listener)
	return "http://" + listener.Addr().String() + "/admit", token, func() { server.Close() }, nil
}
