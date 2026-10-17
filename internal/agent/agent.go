package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
)

const (
	maxBatchItems             = 2000
	maxBatchBytes             = 2 << 20
	maxQueuedResults          = 4096
	maxQueuedResultBytes      = 8 << 20
	maxTaskExecution          = 180 * time.Second
	maxMasscanRatePPS         = 20000
	authorizationSafetyMargin = time.Second
)

type queuedObservation struct {
	observation  Observation
	encodedBytes int
}

type activeTask struct {
	typeName string
	cancel   context.CancelCauseFunc
}

type Config struct {
	ControlURL          string
	JoinToken           string
	CAFile              string
	InstanceID          string
	Hostname            string
	AgentVersion        string
	SessionID           string
	AZ                  string
	Spec                json.RawMessage
	MaxTasks            int
	EndpointConcurrency int
	AllowPrivateTargets bool
	PortExecutor        string
	MasscanRateLimitPPS int
	MasscanInterface    string
	MasscanRouterMAC    string
	MetadataURL         string
	HTTPXBinary         string
	HTTPXMaxProcesses   int
	HTTPXThreads        int
	NucleiBinary        string
	Logger              *slog.Logger
}

type Agent struct {
	cfg                Config
	client             *Client
	policy             targetPolicy
	log                *slog.Logger
	portExecutor       string
	endpointSlots      chan struct{}
	httpxSlots         chan struct{}
	httpTargetMu       sync.Mutex
	httpTargetSlots    map[string]*targetSlots
	resources          *resourceSampler
	ruleSets           *ruleSetCache
	ruleSetFlights     singleflight.Group
	workerID           string
	heartbeatEvery     time.Duration
	draining           atomic.Bool
	mu                 sync.Mutex
	active             map[string]activeTask
	lastTaskType       string
	taskFinished       chan struct{}
	terminationAt      *time.Time
	nucleiOriginalOnce sync.Once
	nucleiOriginalOK   bool
	wg                 sync.WaitGroup
}

func New(cfg Config) (*Agent, error) {
	if cfg.ControlURL == "" || cfg.JoinToken == "" {
		return nil, fmt.Errorf("control URL and join token are required")
	}
	if cfg.InstanceID == "" || cfg.Hostname == "" || cfg.SessionID == "" {
		return nil, fmt.Errorf("instance ID, hostname, and session ID are required")
	}
	if cfg.MaxTasks <= 0 {
		cfg.MaxTasks = 17
	}
	if cfg.EndpointConcurrency <= 0 {
		cfg.EndpointConcurrency = 16
	}
	if cfg.MasscanRateLimitPPS <= 0 {
		cfg.MasscanRateLimitPPS = maxMasscanRatePPS
	}
	if cfg.MasscanRateLimitPPS > maxMasscanRatePPS {
		return nil, fmt.Errorf("masscan rate limit must not exceed %d packets/second", maxMasscanRatePPS)
	}
	if cfg.PortExecutor == "" {
		cfg.PortExecutor = "masscan"
	}
	if cfg.NucleiBinary == "" {
		cfg.NucleiBinary = "nuclei"
	}
	if cfg.HTTPXBinary == "" {
		cfg.HTTPXBinary = "httpx"
	}
	if cfg.HTTPXMaxProcesses <= 0 {
		cfg.HTTPXMaxProcesses = 2
	}
	if cfg.HTTPXMaxProcesses > 2 {
		return nil, fmt.Errorf("httpx max processes must not exceed 2")
	}
	if cfg.HTTPXThreads <= 0 {
		cfg.HTTPXThreads = 8
	}
	if cfg.HTTPXThreads > 16 {
		return nil, fmt.Errorf("httpx threads must not exceed 16")
	}
	if cfg.PortExecutor != "masscan" && cfg.PortExecutor != "connect" {
		return nil, fmt.Errorf("unknown port executor %q", cfg.PortExecutor)
	}
	if len(cfg.Spec) == 0 {
		cfg.Spec = json.RawMessage(`{}`)
	}
	var spec map[string]any
	if err := json.Unmarshal(cfg.Spec, &spec); err != nil || spec == nil {
		return nil, fmt.Errorf("agent spec must be a JSON object")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := validateMasscanNetwork(&cfg); err != nil {
		return nil, err
	}
	client, err := NewClient(cfg.ControlURL, cfg.JoinToken, cfg.CAFile)
	if err != nil {
		return nil, err
	}
	return &Agent{
		cfg: cfg, client: client, policy: newTargetPolicy(cfg.ControlURL, cfg.AllowPrivateTargets),
		log: cfg.Logger, portExecutor: cfg.PortExecutor,
		endpointSlots: make(chan struct{}, cfg.EndpointConcurrency), httpxSlots: make(chan struct{}, cfg.HTTPXMaxProcesses), httpTargetSlots: make(map[string]*targetSlots),
		resources: newResourceSampler(), ruleSets: newRuleSetCache(8), active: make(map[string]activeTask), taskFinished: make(chan struct{}, 1), heartbeatEvery: 10 * time.Second,
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	go a.resources.run(ctx)
	registered, err := a.register(ctx)
	if err != nil {
		return err
	}
	a.workerID = registered.WorkerID
	if registered.HeartbeatSeconds > 0 {
		a.heartbeatEvery = time.Duration(registered.HeartbeatSeconds) * time.Second
	}
	a.log.Info("worker registered", "worker_id", a.workerID, "heartbeat", a.heartbeatEvery)
	go a.heartbeatLoop(ctx, stop)
	if a.cfg.MetadataURL != "" && !strings.EqualFold(a.cfg.MetadataURL, "off") {
		go a.metadataLoop(ctx)
	}

	for {
		if ctx.Err() != nil {
			a.cancelAll(context.Cause(ctx))
			a.wg.Wait()
			if errors.Is(ctx.Err(), context.Canceled) && context.Cause(ctx) == context.Canceled {
				return nil
			}
			return context.Cause(ctx)
		}
		if a.draining.Load() {
			select {
			case <-ctx.Done():
			case <-a.taskFinished:
			}
			continue
		}
		task, err := a.claimAvailable(ctx)
		if err != nil {
			if ctx.Err() == nil {
				a.log.Warn("claim failed", "error", err)
			}
			continue
		}
		if task != nil {
			a.startTask(ctx, *task)
			continue
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-a.taskFinished:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

func (a *Agent) register(ctx context.Context) (RegisterResponse, error) {
	req := RegisterRequest{InstanceID: a.cfg.InstanceID, Hostname: a.cfg.Hostname, AgentVersion: a.cfg.AgentVersion, SessionID: a.cfg.SessionID, AZ: a.cfg.AZ, Spec: a.cfg.Spec}
	for {
		out, err := a.client.Register(ctx, req)
		if err == nil {
			return out, nil
		}
		a.log.Warn("register failed; retrying", "error", err)
		select {
		case <-ctx.Done():
			return out, context.Cause(ctx)
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) claim(ctx context.Context, types []string) (*Task, error) {
	requestID, err := RandomID()
	if err != nil {
		return nil, err
	}
	for {
		task, err := a.client.Claim(ctx, a.workerID, a.cfg.SessionID, requestID, types, a.supportsNucleiOriginal())
		if err == nil {
			return task, nil
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) claimAvailable(ctx context.Context) (*Task, error) {
	for _, types := range a.claimOptions() {
		task, err := a.claim(ctx, types)
		if err != nil || task != nil {
			return task, err
		}
	}
	return nil, nil
}

func (a *Agent) claimOptions() [][]string {
	ports, fingerprints := a.activeTypeCounts()
	if ports+fingerprints >= a.cfg.MaxTasks {
		return nil
	}
	if a.cfg.MaxTasks == 1 {
		a.mu.Lock()
		lastTaskType := a.lastTaskType
		a.mu.Unlock()
		if lastTaskType == "port" {
			return [][]string{{"service", "http", "poc"}, {"port"}}
		}
		return [][]string{{"port"}, {"service", "http", "poc"}}
	}
	var options [][]string
	if ports == 0 {
		options = append(options, []string{"port"})
	}
	if fingerprints < a.fingerprintTaskLimit() {
		types := []string{"service", "http"}
		if a.activePoCCount() == 0 {
			types = append(types, "poc")
		}
		options = append(options, types)
	}
	return options
}

func (a *Agent) activePoCCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	count := 0
	for _, task := range a.active {
		if task.typeName == "poc" {
			count++
		}
	}
	return count
}

func (a *Agent) fingerprintTaskLimit() int {
	if a.cfg.MaxTasks == 1 {
		return 1
	}
	return a.cfg.MaxTasks - 1
}

func (a *Agent) activeTypeCounts() (ports, fingerprints int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, task := range a.active {
		if task.typeName == "port" {
			ports++
		} else {
			fingerprints++
		}
	}
	return ports, fingerprints
}

func (a *Agent) startTask(parent context.Context, task Task) {
	ctx, cancel := context.WithCancelCause(parent)
	a.mu.Lock()
	if _, exists := a.active[task.ID]; exists {
		a.mu.Unlock()
		cancel(fmt.Errorf("duplicate task claim"))
		return
	}
	a.active[task.ID] = activeTask{typeName: task.Type, cancel: cancel}
	a.lastTaskType = task.Type
	a.mu.Unlock()
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer func() {
			a.mu.Lock()
			delete(a.active, task.ID)
			a.mu.Unlock()
			select {
			case a.taskFinished <- struct{}{}:
			default:
			}
		}()
		a.runTask(ctx, cancel, task)
	}()
}

func (a *Agent) runTask(ctx context.Context, cancel context.CancelCauseFunc, task Task) {
	a.log.Info("task started", "task_id", task.ID, "type", task.Type, "attempt", task.AttemptNo)
	if err := initialAuthorizationError(task, time.Now()); err != nil {
		cancel(err)
		a.releaseTask(task, err)
		return
	}
	leaseDone := make(chan struct{})
	go a.renewLoop(ctx, cancel, task, leaseDone)
	executionTimeout, err := taskExecutionTimeout(task.Payload)
	if err == nil {
		executionCtx, stopExecution := context.WithTimeoutCause(ctx, executionTimeout, &TaskError{Reason: fmt.Sprintf("task execution exceeded %s", executionTimeout), Retryable: true, FailureClass: "execution_timeout"})
		err = a.executeAndReport(executionCtx, task)
		if executionCtx.Err() != nil {
			err = context.Cause(executionCtx)
		}
		stopExecution()
	}
	cancel(err)
	<-leaseDone
	if err == nil {
		a.log.Info("task completed", "task_id", task.ID)
		return
	}
	a.releaseTask(task, err)
}

func taskExecutionTimeout(payload json.RawMessage) (time.Duration, error) {
	var limits struct {
		ExecutionTimeoutSeconds int `json:"execution_timeout_seconds"`
	}
	if err := json.Unmarshal(payload, &limits); err != nil {
		return 0, &TaskError{Reason: "invalid task payload: " + err.Error(), Retryable: false}
	}
	if limits.ExecutionTimeoutSeconds <= 0 {
		return maxTaskExecution, nil
	}
	if limits.ExecutionTimeoutSeconds >= int(maxTaskExecution/time.Second) {
		return maxTaskExecution, nil
	}
	return minDuration(time.Duration(limits.ExecutionTimeoutSeconds)*time.Second, maxTaskExecution), nil
}

func (a *Agent) releaseTask(task Task, err error) {
	retryable := true
	failureClass := ""
	var taskErr *TaskError
	if errors.As(err, &taskErr) {
		retryable = taskErr.Retryable
		failureClass = taskErr.FailureClass
	}
	reason := err.Error()
	if len(reason) > 1500 {
		reason = reason[:700] + " ... [truncated] ... " + reason[len(reason)-700:]
	}
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer releaseCancel()
	if releaseErr := a.client.Release(releaseCtx, a.workerID, a.cfg.SessionID, task, reason, retryable, failureClass); releaseErr != nil {
		a.log.Warn("task release failed", "task_id", task.ID, "error", releaseErr)
	} else {
		a.log.Warn("task released", "task_id", task.ID, "reason", reason, "retryable", retryable)
	}
}

func (a *Agent) renewLoop(ctx context.Context, cancel context.CancelCauseFunc, task Task, done chan<- struct{}) {
	defer close(done)
	leaseDeadline := localDeadline(task.requestSentAt, task.ServerTime, task.LeaseUntil)
	rateDeadline := localDeadline(task.requestSentAt, task.ServerTime, task.RateUntil)
	renew := time.NewTicker(15 * time.Second)
	check := time.NewTicker(time.Second)
	defer renew.Stop()
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			if err := authorizationError(time.Now(), leaseDeadline, rateDeadline); err != nil {
				cancel(err)
				return
			}
		case <-renew.C:
			renewCtx, renewCancel := context.WithTimeout(ctx, 10*time.Second)
			out, sentAt, err := a.client.Renew(renewCtx, a.workerID, a.cfg.SessionID, task)
			renewCancel()
			if err != nil {
				a.log.Warn("task renew failed", "task_id", task.ID, "error", err)
				continue
			}
			if out.Action != "continue" {
				reason := out.Reason
				if reason == "" {
					reason = "control requested " + out.Action
				}
				cancel(fmt.Errorf("%s", reason))
				return
			}
			leaseDeadline = localDeadline(sentAt, out.ServerTime, out.LeaseUntil)
			rateDeadline = localDeadline(sentAt, out.ServerTime, out.RateUntil)
			if err := authorizationError(time.Now(), leaseDeadline, rateDeadline); err != nil {
				cancel(err)
				return
			}
		}
	}
}

func localDeadline(sentAt, serverTime, deadline time.Time) time.Time {
	if sentAt.IsZero() || serverTime.IsZero() || deadline.IsZero() {
		return time.Time{}
	}
	return sentAt.Add(deadline.Sub(serverTime) - authorizationSafetyMargin)
}

func authorizationError(now, leaseDeadline, rateDeadline time.Time) error {
	if leaseDeadline.IsZero() || rateDeadline.IsZero() {
		return &TaskError{Reason: "task authorization timestamps are missing", Retryable: true}
	}
	if !now.Before(rateDeadline) {
		return &TaskError{Reason: "task rate permission expired", Retryable: true}
	}
	if !now.Before(leaseDeadline) {
		return &TaskError{Reason: "task lease expired", Retryable: true}
	}
	return nil
}

func initialAuthorizationError(task Task, now time.Time) error {
	return authorizationError(now,
		localDeadline(task.requestSentAt, task.ServerTime, task.LeaseUntil),
		localDeadline(task.requestSentAt, task.ServerTime, task.RateUntil))
}

func (a *Agent) executeAndReport(ctx context.Context, task Task) error {
	results := make(chan queuedObservation, maxQueuedResults)
	resultBudget := semaphore.NewWeighted(maxQueuedResultBytes)
	execDone := make(chan error, 1)
	go func() {
		emit := func(obs Observation) error {
			encoded, err := json.Marshal(obs)
			if err != nil {
				return err
			}
			if len(encoded)+2 > maxBatchBytes-4096 {
				return &TaskError{Reason: "single observation exceeds 2 MiB batch limit", Retryable: false}
			}
			if err := resultBudget.Acquire(ctx, int64(len(encoded))); err != nil {
				return context.Cause(ctx)
			}
			select {
			case results <- queuedObservation{observation: obs, encodedBytes: len(encoded)}:
				return nil
			case <-ctx.Done():
				resultBudget.Release(int64(len(encoded)))
				return context.Cause(ctx)
			}
		}
		var err error
		switch task.Type {
		case "port":
			err = a.runPort(ctx, task, emit)
		case "service":
			err = a.runService(ctx, task, emit)
		case "http":
			err = a.runHTTP(ctx, task, emit)
		case "poc":
			err = a.runPoC(ctx, task, emit)
		default:
			err = &TaskError{Reason: "unsupported task type: " + task.Type, Retryable: false}
		}
		close(results)
		execDone <- err
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	batch := make([]Observation, 0, maxBatchItems)
	batchBytes := 2 // JSON array brackets.
	seq := -1
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		seq++
		items := append([]Observation(nil), batch...)
		for {
			if err := a.client.Batch(ctx, a.workerID, a.cfg.SessionID, task, seq, items); err == nil {
				batch = batch[:0]
				batchBytes = 2
				return nil
			} else {
				a.log.Warn("batch upload failed; retrying same sequence", "task_id", task.ID, "batch_seq", seq, "error", err)
			}
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-time.After(time.Second):
			}
		}
	}
	var execErr error
	for results != nil {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case queued, ok := <-results:
			if !ok {
				results = nil
				execErr = <-execDone
				continue
			}
			resultBudget.Release(int64(queued.encodedBytes))
			delimiterBytes := 0
			if len(batch) > 0 {
				delimiterBytes = 1
			}
			if batchBytes+delimiterBytes+queued.encodedBytes > maxBatchBytes-4096 || len(batch) >= maxBatchItems {
				if err := flush(); err != nil {
					return err
				}
				delimiterBytes = 0
			}
			batch = append(batch, queued.observation)
			batchBytes += delimiterBytes + queued.encodedBytes
			if len(batch) >= maxBatchItems {
				if err := flush(); err != nil {
					return err
				}
			}
		case <-ticker.C:
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if execErr != nil {
		return execErr
	}
	for {
		if err := a.client.Complete(ctx, a.workerID, a.cfg.SessionID, task, seq); err == nil {
			return nil
		} else {
			a.log.Warn("complete failed; retrying", "task_id", task.ID, "error", err)
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(time.Second):
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context, stop context.CancelFunc) {
	ticker := time.NewTicker(a.heartbeatEvery)
	defer ticker.Stop()
	for {
		a.sendHeartbeat(ctx, stop)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context, stop context.CancelFunc) {
	status, current, termination := a.snapshot()
	metrics := a.resources.metrics()
	metrics["active_tasks"] = a.activeCount()
	hbCtx, cancel := context.WithTimeout(ctx, minDuration(a.heartbeatEvery, 8*time.Second))
	defer cancel()
	out, err := a.client.Heartbeat(hbCtx, HeartbeatRequest{
		WorkerID: a.workerID, SessionID: a.cfg.SessionID, CurrentTaskID: current, Status: status,
		TerminationAt: termination, Metrics: metrics,
	})
	if err != nil {
		if ctx.Err() == nil {
			a.log.Warn("heartbeat failed", "error", err)
		}
		return
	}
	if len(out.StopTaskIDs) > 0 {
		reason := out.Reason
		if reason == "" {
			reason = "control requested task stop"
		}
		a.cancelTasks(out.StopTaskIDs, fmt.Errorf("%s", reason))
	}
	switch out.Action {
	case "drain":
		a.setDraining(out.StopDeadline)
	case "stop":
		a.cancelAll(fmt.Errorf("control requested stop: %s", out.Reason))
		stop()
	}
}

func (a *Agent) snapshot() (status, current string, termination *time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.draining.Load() {
		status = "draining"
	} else if len(a.active) > 0 {
		status = "running"
	} else {
		status = "ready"
	}
	for id := range a.active {
		current = id
		break
	}
	if a.terminationAt != nil {
		copied := *a.terminationAt
		termination = &copied
	}
	return
}

func (a *Agent) setDraining(deadline *time.Time) {
	a.draining.Store(true)
	if deadline != nil {
		a.mu.Lock()
		copied := *deadline
		a.terminationAt = &copied
		a.mu.Unlock()
		go func() {
			timer := time.NewTimer(time.Until(copied))
			defer timer.Stop()
			<-timer.C
			a.cancelAll(fmt.Errorf("drain deadline reached"))
		}()
	}
}

func (a *Agent) cancelAll(cause error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, task := range a.active {
		task.cancel(cause)
	}
}

func (a *Agent) cancelTasks(ids []string, cause error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range ids {
		if task, ok := a.active[id]; ok {
			task.cancel(cause)
		}
	}
}

func (a *Agent) activeCount() int { a.mu.Lock(); defer a.mu.Unlock(); return len(a.active) }

func (a *Agent) metadataLoop(ctx context.Context) {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	token, tokenUntil := "", time.Time{}
	for {
		if token == "" || time.Now().After(tokenUntil) {
			if next, err := fetchMetadataToken(ctx, client, a.cfg.MetadataURL); err == nil {
				token, tokenUntil = next, time.Now().Add(5*time.Hour)
			}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.MetadataURL, nil)
		if token != "" {
			req.Header.Set("X-aliyun-ecs-metadata-token", token)
		}
		resp, err := client.Do(req)
		if err == nil {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				token = ""
			}
			if resp.StatusCode == http.StatusOK && strings.TrimSpace(string(data)) != "" {
				raw := strings.Trim(strings.TrimSpace(string(data)), "\"")
				deadline, parseErr := time.Parse(time.RFC3339, raw)
				if parseErr != nil {
					deadline = time.Now().Add(2 * time.Minute)
				}
				a.log.Warn("instance termination metadata detected; draining", "termination_at", deadline)
				a.setDraining(&deadline)
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func fetchMetadataToken(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() != "100.100.100.200" {
		return "", fmt.Errorf("not Alibaba ECS metadata")
	}
	u.Path, u.RawQuery, u.Fragment = "/latest/api/token", "", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aliyun-ecs-metadata-token-ttl-seconds", "21600")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("metadata token status %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("empty metadata token")
	}
	return token, nil
}

func RandomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
