package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScanMasscan(t *testing.T) {
	input := "#masscan\nopen tcp 443 192.0.2.10 1\n"
	var got []Observation
	if err := scanMasscan(strings.NewReader(input), func(obs Observation) error { got = append(got, obs); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Port != 443 || got[0].IP != "192.0.2.10" || got[0].Kind != "port" {
		t.Fatalf("unexpected observations: %#v", got)
	}
}

func TestMasscanSpoolFollowsTailAndEnforcesLimit(t *testing.T) {
	spool, err := os.CreateTemp(t.TempDir(), "masscan-*.list")
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	info, err := spool.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("spool permissions = %v", info.Mode().Perm())
	}
	reader, err := os.Open(spool.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	processDone := make(chan struct{})
	go func() {
		_, _ = io.WriteString(spool, "open tcp 80 192.0.2.10 1\n")
		time.Sleep(25 * time.Millisecond)
		_, _ = io.WriteString(spool, "open tcp 443 192.0.2.10 1\n")
		close(processDone)
	}()
	var got []Observation
	err = scanMasscan(&followingFileReader{ctx: context.Background(), file: reader, processDone: processDone}, func(obs Observation) error {
		got = append(got, obs)
		return nil
	})
	if err != nil || len(got) != 2 || got[0].Port != 80 || got[1].Port != 443 {
		t.Fatalf("spool tail was not drained: observations=%#v error=%v", got, err)
	}
	cancelCtx, cancelRead := context.WithCancel(context.Background())
	cancelRead()
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	_, err = (&followingFileReader{ctx: cancelCtx, file: reader, processDone: make(chan struct{})}).Read(make([]byte, 1))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("spool reader ignored cancellation: %v", err)
	}

	if err := spool.Truncate(maxMasscanSpoolBytes + 1); err != nil {
		t.Fatal(err)
	}
	limitCtx, limitCancel := context.WithCancel(context.Background())
	limitDone := make(chan struct{})
	limitErr := make(chan error, 1)
	go func() { limitErr <- watchMasscanSpool(limitCtx, spool.Name(), limitDone, limitCancel) }()
	select {
	case err := <-limitErr:
		var taskErr *TaskError
		if !errors.As(err, &taskErr) || taskErr.Retryable || taskErr.FailureClass != "" || !strings.Contains(taskErr.Reason, "spool exceeded") {
			t.Fatalf("spool limit did not fail explicitly: %v", err)
		}
		if !errors.Is(limitCtx.Err(), context.Canceled) {
			t.Fatal("spool limit did not cancel masscan")
		}
	case <-time.After(time.Second):
		t.Fatal("spool limit monitor did not finish")
	}
}

func TestClientCustomCAAndTimeouts(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer join" {
			t.Error("join token was not sent")
		}
		fmt.Fprint(w, `{"worker_id":"worker","worker_token":"token","heartbeat_seconds":10}`)
	}))
	defer server.Close()
	caFile := t.TempDir() + "/ca.crt"
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(server.URL, "join", caFile)
	if err != nil {
		t.Fatal(err)
	}
	if client.control.Timeout != 5*time.Second || client.upload.Timeout != 30*time.Second {
		t.Fatalf("unexpected client timeouts: control=%v upload=%v", client.control.Timeout, client.upload.Timeout)
	}
	response, err := client.Register(context.Background(), RegisterRequest{InstanceID: "i", Hostname: "h", SessionID: "s"})
	if err != nil || response.WorkerID != "worker" {
		t.Fatalf("custom CA registration failed: response=%#v error=%v", response, err)
	}
}

func TestMasscanNetworkValidation(t *testing.T) {
	valid := Config{MasscanInterface: "scan-test0", MasscanRouterMAC: "02:00:00:00:00:01"}
	if err := validateMasscanNetwork(&valid); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []Config{
		{MasscanInterface: "--echo"},
		{MasscanRouterMAC: "01:00:5e:00:00:01"},
		{MasscanRouterMAC: "not-a-mac"},
	} {
		if err := validateMasscanNetwork(&cfg); err == nil {
			t.Fatalf("invalid masscan network config accepted: %#v", cfg)
		}
	}
}

func TestExecutionGuards(t *testing.T) {
	portCtx, cancelPort := context.WithCancelCause(context.Background())
	serviceCtx, cancelService := context.WithCancelCause(context.Background())
	a := &Agent{cfg: Config{MaxTasks: 8}, active: map[string]activeTask{
		"port-task":    {typeName: "port", cancel: cancelPort},
		"service-task": {typeName: "service", cancel: cancelService},
	}}
	if ports, fingerprints := a.activeTypeCounts(); ports != 1 || fingerprints != 1 {
		t.Fatalf("unexpected active task counts: ports=%d fingerprints=%d", ports, fingerprints)
	}
	a.cancelTasks([]string{"service-task"}, fmt.Errorf("selected stop"))
	select {
	case <-serviceCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("selected task was not cancelled")
	}
	select {
	case <-portCtx.Done():
		t.Fatal("unlisted task was cancelled")
	default:
	}

	sentAt := time.Now()
	serverTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := serverTime.Add(time.Minute)
	if got, want := localDeadline(sentAt, serverTime, deadline), sentAt.Add(59*time.Second); !got.Equal(want) {
		t.Fatalf("deadline was not anchored conservatively: got=%v want=%v", got, want)
	}
	expired := Task{requestSentAt: sentAt.Add(-time.Minute), ServerTime: serverTime, LeaseUntil: serverTime.Add(2 * time.Minute), RateUntil: deadline}
	if err := initialAuthorizationError(expired, sentAt); err == nil {
		t.Fatal("expired initial authorization was accepted")
	}
}

func TestAgentConcurrencyAndMasscanRateLimits(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{NmapBinary: executable, ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if a.cfg.MaxTasks != 17 || a.cfg.EndpointConcurrency != 16 || a.cfg.MasscanRateLimitPPS != 20000 || a.cfg.HTTPXMaxProcesses != 2 || a.cfg.HTTPXThreads != 8 {
		t.Fatalf("unexpected defaults: max_tasks=%d endpoints=%d masscan_rate=%d httpx_processes=%d httpx_threads=%d", a.cfg.MaxTasks, a.cfg.EndpointConcurrency, a.cfg.MasscanRateLimitPPS, a.cfg.HTTPXMaxProcesses, a.cfg.HTTPXThreads)
	}
	if _, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", MasscanRateLimitPPS: 20001}); err == nil {
		t.Fatal("unsafe masscan rate limit was accepted")
	}
	if _, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", HTTPXMaxProcesses: 3}); err == nil {
		t.Fatal("unsafe httpx process limit was accepted")
	}
	if a.fingerprintTaskLimit() != 16 {
		t.Fatal("default worker did not reserve one task slot for port scanning")
	}
	a.active = make(map[string]activeTask)
	for i := 0; i < 16; i++ {
		a.active[fmt.Sprint(i)] = activeTask{typeName: "service"}
	}
	if got := fmt.Sprint(a.claimOptions()); got != "[[port]]" {
		t.Fatalf("full fingerprint pool did not preserve the port slot: %s", got)
	}
	a.cfg.MaxTasks = 1
	if a.fingerprintTaskLimit() != 1 {
		t.Fatal("single-task worker disabled fingerprint claims")
	}
	a.active = make(map[string]activeTask)
	if got := fmt.Sprint(a.claimOptions()); got != "[[port] [service http poc]]" {
		t.Fatalf("single-task worker cannot time-share task types: %s", got)
	}
	a.lastTaskType = "port"
	if got := fmt.Sprint(a.claimOptions()); got != "[[service http poc] [port]]" {
		t.Fatalf("single-task worker starves fingerprint tasks: %s", got)
	}
	var taskErr *TaskError
	err = a.runMasscan(context.Background(), portPayload{Ports: "1-65535", RatePPS: 20001}, func(Observation) error { return nil })
	if !errors.As(err, &taskErr) || taskErr.Retryable || !strings.Contains(taskErr.Reason, "exceeds agent limit") {
		t.Fatalf("unsafe task rate was not rejected explicitly: %v", err)
	}
}

func TestStderrBufferDrainsAfterLimit(t *testing.T) {
	reader := strings.NewReader(strings.Repeat("x", 70<<10))
	got := readBoundedAndDrain(reader, 64<<10)
	if reader.Len() != 0 {
		t.Fatalf("stderr was not drained: %d bytes remain", reader.Len())
	}
	if !strings.HasSuffix(got, " [truncated]") || len(got) > (64<<10)+len(" [truncated]") {
		t.Fatalf("unexpected bounded stderr length/suffix: %d", len(got))
	}
	stats := "\nscan_capture: received=65535 dropped=17 if_dropped=0\n"
	got = readBoundedAndDrain(strings.NewReader(strings.Repeat("x", 70<<10)+stats), 64<<10)
	if !strings.Contains(got, strings.TrimSpace(stats)) || captureLossError(got) == nil {
		t.Fatal("capture loss at the end of long stderr was hidden")
	}
	if err := captureLossError("scan_capture: received=65535 dropped=0 if_dropped=0"); err != nil {
		t.Fatal(err)
	}
}

func TestResourceParsers(t *testing.T) {
	total, idle, ok := parseCPUTotals("cpu  100 20 30 400 50 5 3 2 0 0")
	if !ok || total != 610 || idle != 450 {
		t.Fatalf("unexpected CPU totals: total=%d idle=%d ok=%v", total, idle, ok)
	}
	memoryTotal, memoryAvailable := parseMemoryKiB("MemTotal: 2097152 kB\nMemAvailable: 1048576 kB\n")
	if memoryTotal != 2097152 || memoryAvailable != 1048576 {
		t.Fatalf("unexpected memory values: total=%d available=%d", memoryTotal, memoryAvailable)
	}
}

func TestBatchRetryKeepsSequenceAndCompletesContiguously(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer fixture.Close()
	var mu sync.Mutex
	var batchBodies []string
	completeSeq := -99
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/batches"):
			batchBodies = append(batchBodies, string(data))
			if len(batchBodies) == 1 {
				http.Error(w, `{"error":"retry"}`, http.StatusServiceUnavailable)
				return
			}
			fmt.Fprint(w, `{"accepted":true}`)
		case strings.HasSuffix(r.URL.Path, "/complete"):
			var request struct {
				LastBatchSeq int `json:"last_batch_seq"`
			}
			_ = json.Unmarshal(data, &request)
			completeSeq = request.LastBatchSeq
			fmt.Fprint(w, `{"completed":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	a, err := New(Config{ControlURL: control.URL, JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "session", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	a.workerID = "worker"
	a.client.workerToken = "worker-token"
	payload, _ := json.Marshal(httpPayload{Endpoints: []Endpoint{{URL: fixture.URL}}, TimeoutSeconds: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.executeAndReport(ctx, Task{ID: "task", Type: "http", AttemptNo: 1, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(batchBodies) != 2 || batchBodies[0] != batchBodies[1] {
		t.Fatalf("batch retry changed content: %#v", batchBodies)
	}
	if !strings.Contains(batchBodies[0], `"batch_seq":0`) || completeSeq != 0 {
		t.Fatalf("unexpected sequence: batch=%s complete=%d", batchBodies[0], completeSeq)
	}
}

func TestBufferedResultsDrainBeforeComplete(t *testing.T) {
	var batchSizes []int
	completeSeq := -99
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/batches"):
			var request struct {
				BatchSeq int           `json:"batch_seq"`
				Items    []Observation `json:"items"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if request.BatchSeq == 0 {
				time.Sleep(100 * time.Millisecond)
			}
			batchSizes = append(batchSizes, len(request.Items))
			fmt.Fprint(w, `{"accepted":true}`)
		case strings.HasSuffix(r.URL.Path, "/complete"):
			var request struct {
				LastBatchSeq int `json:"last_batch_seq"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			completeSeq = request.LastBatchSeq
			fmt.Fprint(w, `{"completed":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	a, err := New(Config{ControlURL: control.URL, JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "session", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	a.workerID = "worker"
	a.client.workerToken = "worker-token"
	endpoints := make([]Endpoint, maxBatchItems+50)
	payload, _ := json.Marshal(servicePayload{Executor: "builtin", Endpoints: endpoints, TimeoutSeconds: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.executeAndReport(ctx, Task{ID: "task", Type: "service", AttemptNo: 1, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(batchSizes), fmt.Sprint([]int{maxBatchItems, 50}); got != want {
		t.Fatalf("buffered results were not drained in contiguous batches: got=%s want=%s", got, want)
	}
	if completeSeq != 1 {
		t.Fatalf("complete raced buffered results: last_batch_seq=%d", completeSeq)
	}
}

func TestTaskExecutionTimeout(t *testing.T) {
	for input, want := range map[string]time.Duration{
		`{}`:                                   maxTaskExecution,
		`{"execution_timeout_seconds":17}`:     17 * time.Second,
		`{"execution_timeout_seconds":999999}`: maxTaskExecution,
	} {
		got, err := taskExecutionTimeout(json.RawMessage(input))
		if err != nil || got != want {
			t.Fatalf("taskExecutionTimeout(%s) = %v, %v; want %v", input, got, err, want)
		}
	}
}

func TestTargetPolicy(t *testing.T) {
	privateBlocked := newTargetPolicy("http://127.0.0.1:8080", false)
	if _, err := privateBlocked.resolve(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("loopback must be blocked by default")
	}
	privateAllowed := newTargetPolicy("http://127.0.0.1:8080", true)
	if _, err := privateAllowed.resolve(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("explicitly allowed loopback rejected: %v", err)
	}
	if err := privateAllowed.validateEndpoint(context.Background(), "127.0.0.1", "8080"); err == nil {
		t.Fatal("control endpoint must remain blocked")
	}
	if err := privateAllowed.validateEndpoint(context.Background(), "127.0.0.1", "8081"); err != nil {
		t.Fatalf("different loopback port should be usable by controlled tests: %v", err)
	}
	if _, err := privateAllowed.resolve(context.Background(), "100.100.100.200"); err == nil {
		t.Fatal("metadata address must remain blocked")
	}
}

func TestHTTPObservationEvidenceAndTruncation(t *testing.T) {
	body := "<html><head><title> Fixture Site </title></head><body><script src=\"/wp-content/app.js\"></script>" + strings.Repeat("x", maxHTTPBody) + "</body></html>"
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fixture")
		w.Header().Set("X-Powered-By", "PHP/8")
		fmt.Fprint(w, body)
	}))
	defer fixture.Close()
	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	obs := a.fetchHTTP(context.Background(), Endpoint{URL: fixture.URL}, 5*time.Second)
	if obs.Error != "" {
		t.Fatalf("fixture fetch failed: %s", obs.Error)
	}
	if obs.StatusCode != http.StatusOK || obs.Title != "Fixture Site" || !obs.Truncated {
		t.Fatalf("unexpected HTTP observation: status=%d title=%q truncated=%v", obs.StatusCode, obs.Title, obs.Truncated)
	}
	if !strings.Contains(obs.RequestRaw, "GET / HTTP/1.1") || !strings.Contains(obs.ResponseRaw, "HTTP/1.1 200 OK") {
		t.Fatalf("raw evidence missing: request=%q response prefix=%q", obs.RequestRaw, firstN(obs.ResponseRaw, 80))
	}
	names := map[string]bool{}
	for _, technology := range obs.Technologies {
		names[technology.Name] = true
	}
	if !names["WordPress"] || !names["PHP"] {
		t.Fatalf("technology evidence missing: %#v", obs.Technologies)
	}
}

func TestHTTPRedirectUsesFinalRequestAndRemoteIP(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Skipf("loopback alias unavailable: %v", err)
	}
	final := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("unexpected Accept-Encoding: %q", r.Header.Get("Accept-Encoding"))
		}
		fmt.Fprint(w, "<title>redirected</title>")
	}))
	final.Listener = listener
	final.Start()
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/final", http.StatusFound)
	}))
	defer redirect.Close()
	_, initialPort, _ := net.SplitHostPort(redirect.Listener.Addr().String())
	initialURL := "http://fixture.invalid:" + initialPort + "/start"
	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	obs := a.fetchHTTP(context.Background(), Endpoint{IP: "127.0.0.1", URL: initialURL}, 5*time.Second)
	if obs.Error != "" {
		t.Fatal(obs.Error)
	}
	_, finalPort, _ := net.SplitHostPort(listener.Addr().String())
	wantURL := final.URL + "/final"
	if obs.IP != "127.0.0.2" || obs.URL != wantURL || obs.Protocol != "http" || strconv.Itoa(obs.Port) != finalPort {
		t.Fatalf("observation did not follow final exchange: %#v", obs)
	}
	if !strings.Contains(obs.RequestRaw, "GET /final HTTP/1.1") || strings.Contains(obs.RequestRaw, "/start") || !strings.Contains(obs.RequestRaw, "Accept-Encoding: identity") {
		t.Fatalf("request evidence is not the final request: %q", obs.RequestRaw)
	}
}

func TestHTTPProtocolFallbackSharesEndpointTimeout(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var connections []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
		}
	}()
	defer func() {
		_ = listener.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()

	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	started := time.Now()
	obs := a.fetchHTTP(context.Background(), Endpoint{IP: "127.0.0.1", Port: port}, 200*time.Millisecond)
	elapsed := time.Since(started)
	if obs.Error == "" {
		t.Fatal("silent endpoint unexpectedly returned a response")
	}
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	accepted := len(connections)
	mu.Unlock()
	if accepted != 2 {
		t.Fatalf("protocol fallback opened %d connections; want both protocol attempts", accepted)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("protocol fallback exceeded the shared endpoint budget: %v", elapsed)
	}
}

func TestHTTPProtocolFallbackAfterFastMismatch(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>TLS fallback</title>")
	}))
	fixture.Listener = &dropFirstListener{Listener: listener}
	fixture.StartTLS()
	defer fixture.Close()
	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	obs := a.fetchHTTP(context.Background(), Endpoint{IP: "127.0.0.1", Port: port}, time.Second)
	if obs.Error != "" || obs.StatusCode != http.StatusOK || obs.Protocol != "https" || obs.Title != "TLS fallback" {
		t.Fatalf("fast HTTP mismatch did not fall back to HTTPS: %#v", obs)
	}
}

func TestHTTPResponseSurvivesSlowBodyWithoutProtocolFallback(t *testing.T) {
	var mu sync.Mutex
	connections := 0
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, "hello")
	}))
	fixture.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			connections++
			mu.Unlock()
		}
	}
	fixture.Start()
	defer fixture.Close()
	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(fixture.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	obs := a.fetchHTTP(context.Background(), Endpoint{IP: host, Port: port}, 200*time.Millisecond)
	if obs.StatusCode != http.StatusOK || !strings.Contains(obs.ResponseRaw, "HTTP/1.1 200 OK") || obs.Error == "" {
		t.Fatalf("slow response evidence was not retained: %#v", obs)
	}
	mu.Lock()
	accepted := connections
	mu.Unlock()
	if accepted != 1 {
		t.Fatalf("valid HTTP response triggered %d connections; want no protocol fallback", accepted)
	}
}

func firstN(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n]
}

type dropFirstListener struct {
	net.Listener
	once sync.Once
}

func (l *dropFirstListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		drop := false
		l.once.Do(func() { drop = true })
		if drop {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}
