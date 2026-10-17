package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"scanplatform/internal/webevidence"
)

// Nine Agent-owned pools with two helper processes each reproduce the Worker
// process limit. The controller fixture uses the production 10/s burst-one admission
// algorithm; the actual Agent callback/client and helper transport are exercised.
func TestWebProbeSharedIPContention(t *testing.T) {
	binary := os.Getenv("TEST_WEB_PROBE_BINARY")
	if binary == "" {
		t.Skip("set TEST_WEB_PROBE_BINARY to built helper")
	}
	var mu sync.Mutex
	var next time.Time
	var grants, requests atomic.Int32
	var closedUnread atomic.Int32
	type connection struct {
		start  time.Time
		active bool
	}
	connections := map[net.Conn]connection{}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if strings.HasPrefix(r.URL.Path, "/slow/") {
			time.Sleep(200 * time.Millisecond)
		}
		fmt.Fprint(w, "<title>fixture</title>")
	}))
	target.Config.ReadHeaderTimeout = 3 * time.Second
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.Config.ConnState = func(c net.Conn, state http.ConnState) {
		mu.Lock()
		defer mu.Unlock()
		switch state {
		case http.StateNew:
			connections[c] = connection{start: time.Now()}
		case http.StateActive:
			v := connections[c]
			v.active = true
			connections[c] = v
		case http.StateClosed:
			v := connections[c]
			delete(connections, c)
			if !v.active {
				closedUnread.Add(1)
				t.Logf("target closed connection before request headers after %s", time.Since(v.start))
			}
		}
	}
	target.Start()
	defer target.Close()
	port := target.Listener.Addr().(*net.TCPAddr).Port
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		now := time.Now()
		if now.Before(next) {
			wait := (time.Until(next).Microseconds() + 999) / 1000
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"granted": false, "retry_after_ms": max(int64(1), wait)})
			return
		}
		next = now.Add(100 * time.Millisecond)
		grants.Add(1)
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"granted": true, "server_time": now.UTC(), "valid_until": now.Add(500 * time.Millisecond).UTC()})
	}))
	defer central.Close()
	jobs := make(chan int, 128)
	for i := 1; i <= 128; i++ {
		jobs <- i
	}
	close(jobs)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var success, failed atomic.Int32
	for worker := 0; worker < 9; worker++ {
		a, err := New(Config{ControlURL: central.URL, JoinToken: "local", InstanceID: fmt.Sprint(worker), Hostname: "fixture", SessionID: fmt.Sprint(worker), AllowPrivateTargets: true, HTTPXMaxProcesses: 2})
		if err != nil {
			t.Fatal(err)
		}
		a.workerID = fmt.Sprint(worker)
		t.Cleanup(a.stopWebProbes)
		for slot := 0; slot < a.cfg.HTTPXMaxProcesses; slot++ {
			wg.Add(1)
			go func(a *Agent, worker int) {
				defer wg.Done()
				for index := range jobs {
					id := strconv.Itoa(index)
					base, _ := url.Parse(fmt.Sprintf("http://fixture%s.test:%d/slow/%s", id, port, id))
					itemCtx := a.withHTTPBudget(ctx, Task{ID: "fixture-" + id, AttemptNo: 1})
					callback, token, closeCallback, err := startWebAdmission(itemCtx, id, "127.0.0.1", base, false)
					if err != nil {
						t.Error(err)
						return
					}
					request := webevidence.ProbeRequest{Protocol: webevidence.Protocol, ID: id, URL: base.String(), ConnectIP: "127.0.0.1", CFFSHA256: webevidence.SHA256(nil), TimeoutMillis: 8000, EntryTimeoutMillis: 90000, AdmissionURL: callback, AdmissionToken: token}
					started := time.Now()
					raw, err := a.runWebHelper(itemCtx, binary, request)
					closeCallback()
					var result webevidence.ProbeResult
					if err == nil {
						err = json.Unmarshal(raw, &result)
					}
					if err != nil || result.Response.StatusCode != 200 {
						failed.Add(1)
						t.Logf("worker=%d item=%d elapsed=%s error=%v response_error=%s", worker, index, time.Since(started), err, result.Response.Error)
					} else {
						success.Add(1)
					}
				}
			}(a, worker)
		}
	}
	wg.Wait()
	t.Logf("workers=9 max_helpers=18 success=%d failed=%d grants=%d target_requests=%d closed_before_headers=%d", success.Load(), failed.Load(), grants.Load(), requests.Load(), closedUnread.Load())
	if success.Load() != 128 || requests.Load() != 256 || closedUnread.Load() != 0 {
		t.Fatalf("shared-IP contention lost %d of128 page responses", failed.Load())
	}
}
