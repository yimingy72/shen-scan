package httpadmission

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testTransport(server *httptest.Server, permit Permit, timeout time.Duration) Transport {
	return Transport{Base: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx = RequestContext(ctx)
		host, port, _ := net.SplitHostPort(address)
		ctx, err := BeforeDial(ctx, host, host, port)
		if err != nil {
			return nil, err
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		return AfterDial(ctx, conn, err)
	}}, Permit: permit, NetworkTimeout: timeout}
}
func TestQueueDoesNotConsumeNetworkBudgetOrOpenSocket(t *testing.T) {
	var accepted atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	server.Config.ReadHeaderTimeout = 50 * time.Millisecond
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	permit := func(ctx context.Context, _, _, _ string, wait bool) (time.Time, error) {
		if accepted.Load() != 0 {
			t.Error("target connection opened during queue wait")
		}
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return time.Time{}, context.Cause(ctx)
		case <-timer.C:
		}
		return time.Now().Add(500 * time.Millisecond), nil
	}
	client := &http.Client{Transport: testTransport(server, permit, 100*time.Millisecond)}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || accepted.Load() != 1 {
		t.Fatal("queued request did not complete")
	}
}

type delayedListener struct {
	net.Listener
	delay time.Duration
}

func (l delayedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &delayedRead{Conn: conn, delay: l.delay}, nil
}

type delayedRead struct {
	net.Conn
	delay time.Duration
	read  bool
}

func (c *delayedRead) Read(data []byte) (int, error) {
	if !c.read {
		c.read = true
		time.Sleep(c.delay)
	}
	return c.Conn.Read(data)
}
func TestSlowTLSRefreshAndOnlyUnsentRetry(t *testing.T) {
	var received, pre, final atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); fmt.Fprint(w, "ok") }))
	server.Listener = delayedListener{Listener: server.Listener, delay: 600 * time.Millisecond}
	server.StartTLS()
	defer server.Close()
	permit := func(ctx context.Context, _, _, _ string, wait bool) (time.Time, error) {
		if wait {
			pre.Add(1)
		} else if final.Add(1) == 1 {
			return time.Time{}, ErrPending
		}
		return time.Now().Add(475 * time.Millisecond), nil
	}
	client := &http.Client{Transport: testTransport(server, permit, 2*time.Second)}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	if response.StatusCode != 200 || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 || received.Load() != 1 || pre.Load() != 2 || final.Load() != 2 {
		t.Fatalf("bad slowTLS/unsent retry: pre=%d final=%d target=%d TLS=%v", pre.Load(), final.Load(), received.Load(), response.TLS != nil)
	}
}
func TestNoRetryAfterHTTPWriteAndCancellationBeforeDial(t *testing.T) {
	var received, accepted atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	permit := func(context.Context, string, string, string, bool) (time.Time, error) {
		return time.Now().Add(500 * time.Millisecond), nil
	}
	client := &http.Client{Transport: testTransport(server, permit, time.Second)}
	if _, err := client.Get(server.URL); err == nil || received.Load() != 1 {
		t.Fatalf("HTTP error retried: err=%v target=%d", err, received.Load())
	}
	accepted.Store(0)
	permit = func(ctx context.Context, _, _, _ string, _ bool) (time.Time, error) {
		<-ctx.Done()
		return time.Time{}, context.Cause(ctx)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	client.Transport = testTransport(server, permit, time.Second)
	if _, err := client.Do(request); !errors.Is(err, context.DeadlineExceeded) || accepted.Load() != 0 {
		t.Fatalf("canceled queue opened target: err=%v accepted=%d", err, accepted.Load())
	}
}
func TestActiveNetworkDeadlineRemainsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	permit := func(context.Context, string, string, string, bool) (time.Time, error) {
		return time.Now().Add(500 * time.Millisecond), nil
	}
	client := &http.Client{Transport: testTransport(server, permit, 50*time.Millisecond)}
	started := time.Now()
	if _, err := client.Get(server.URL); err == nil || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("active network limit lost: err=%v elapsed=%s", err, time.Since(started))
	}
}

func TestUnsentRetryRejectsNonReplayableBody(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	server.Listener = delayedListener{Listener: server.Listener, delay: 600 * time.Millisecond}
	server.StartTLS()
	defer server.Close()
	permit := func(_ context.Context, _, _, _ string, wait bool) (time.Time, error) {
		if !wait {
			return time.Time{}, ErrPending
		}
		return time.Now().Add(475 * time.Millisecond), nil
	}
	request, _ := http.NewRequest("GET", server.URL, io.NopCloser(strings.NewReader("body")))
	_, err := (&http.Client{Transport: testTransport(server, permit, 2*time.Second)}).Do(request)
	if err == nil || !strings.Contains(err.Error(), "non-replayable") || requests.Load() != 0 {
		t.Fatalf("unsafe body replay: err=%v requests=%d", err, requests.Load())
	}
}
