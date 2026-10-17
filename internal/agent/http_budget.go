package agent

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type httpBudgetKey struct{}
type httpTaskBudget struct {
	agent *Agent
	task  Task
	mu    sync.Mutex
	seq   int64
}

func (a *Agent) withHTTPBudget(ctx context.Context, task Task) context.Context {
	return context.WithValue(ctx, httpBudgetKey{}, &httpTaskBudget{agent: a, task: task})
}

func admitHTTPRequest(ctx context.Context, ip, host, port string) error {
	_, err := admitHTTPPermit(ctx, ip, host, port)
	return err
}
func admitHTTPPermit(ctx context.Context, ip, host, port string) (time.Time, error) {
	budget, ok := ctx.Value(httpBudgetKey{}).(*httpTaskBudget)
	if !ok {
		return time.Now().Add(500 * time.Millisecond), nil
	} // Internal standalone collectors used by local fixtures.
	// The server retains a single monotonic receipt/task. Serialize admissions so
	// concurrent entries cannot reorder IDs or mistake a newer receipt for a replay.
	budget.mu.Lock()
	defer budget.mu.Unlock()
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
		timer := time.NewTimer(time.Duration(response.RetryAfterMS) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return time.Time{}, context.Cause(ctx)
		case <-timer.C:
		}
	}
}

// Admission runs after connection/TLS establishment and before net/http hands
// the request to its write loop. Every fresh connection (including a retry) is
// charged. All callers disable keepalives. Failed admission closes the socket
// before returning to the writer, so a cancellation race cannot emit headers.
type budgetHTTPTransport struct{ transport *http.Transport }

func (b budgetHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(request.Context())

	var permitErr error
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		permitErr = admitHTTPRequest(ctx, remoteHost(info.Conn.RemoteAddr()), request.URL.Hostname(), urlPort(request.URL))
		if permitErr != nil {
			_ = info.Conn.Close()
			cancel(permitErr)
		}
	}}
	response, err := b.transport.RoundTrip(request.Clone(httptrace.WithClientTrace(ctx, trace)))
	if permitErr != nil {
		if response != nil {
			response.Body.Close()
		}
		return nil, permitErr
	}
	if err != nil {
		cancel(err)
		return nil, err
	}
	response.Body = &budgetHTTPBody{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type budgetHTTPBody struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

func (b *budgetHTTPBody) Close() error { err := b.ReadCloser.Close(); b.cancel(nil); return err }

// This callback carries only one item's random bearer token. Worker credentials
// and the complete task binding remain in this process, never helper IPC/env.
func startWebAdmission(ctx context.Context, inputID, fixedIP string, base *url.URL, alternate bool) (string, string, func(), error) {
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
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admit" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		var item struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4097)).Decode(&item) != nil || item.ID != inputID {
			http.Error(w, "invalid item", 400)
			return
		}
		target, err := url.Parse(item.URL)
		if err != nil || target.User != nil || target.Fragment != "" || !sameAuthority(target, base) || (target.Scheme != base.Scheme && (!alternate || target.Scheme != "http" && target.Scheme != "https")) {
			http.Error(w, "outside entry", 400)
			return
		}
		deadline, err := admitHTTPPermit(r.Context(), fixedIP, target.Hostname(), urlPort(target))
		if err != nil {
			http.Error(w, "admission failed", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]int64{"valid_for_ms": max(int64(0), time.Until(deadline).Milliseconds())})
	})
	go server.Serve(listener)
	return "http://" + listener.Addr().String() + "/admit", token, func() { server.Close() }, nil
}
