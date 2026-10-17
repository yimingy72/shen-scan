package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const maxMasscanSpoolBytes = 128 << 20

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)

type portPayload struct {
	Targets        []string `json:"targets"`
	Ports          string   `json:"ports"`
	RatePPS        int      `json:"rate_pps"`
	WaitSeconds    int      `json:"wait_seconds"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	TestPorts      []int    `json:"test_ports,omitempty"`
}

func (a *Agent) runPort(ctx context.Context, task Task, emit func(Observation) error) error {
	var payload portPayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return &TaskError{Reason: "invalid port payload: " + err.Error()}
	}
	if len(payload.Targets) == 0 {
		return &TaskError{Reason: "port task has no targets"}
	}
	for _, target := range payload.Targets {
		ip, err := netip.ParseAddr(target)
		if err != nil || !ip.Is4() {
			return &TaskError{Reason: "port target must be an IPv4 address: " + target}
		}
		if err := a.policy.validateIP(ip); err != nil {
			return &TaskError{Reason: err.Error()}
		}
	}
	if _, _, err := parseTCPPortRange(payload.Ports); err != nil {
		return &TaskError{Reason: err.Error(), Retryable: false}
	}
	if a.portExecutor == "connect" {
		return a.runConnectPorts(ctx, payload, emit)
	}
	first, last, _ := parseTCPPortRange(payload.Ports)
	controlPort, _ := strconv.Atoi(a.policy.controlPort)
	for _, target := range payload.Targets {
		if controlPort < first || controlPort > last {
			continue
		}
		if err := a.policy.validateEndpoint(ctx, target, a.policy.controlPort); err != nil {
			return &TaskError{Reason: "full-port scan would include " + err.Error(), Retryable: false}
		}
	}
	return a.runMasscan(ctx, payload, emit)
}

func (a *Agent) runMasscan(ctx context.Context, payload portPayload, emit func(Observation) error) error {
	first, last, err := parseTCPPortRange(payload.Ports)
	if err != nil {
		return &TaskError{Reason: err.Error(), Retryable: false}
	}
	rate := payload.RatePPS
	if rate <= 0 {
		rate = 5000
	}
	if rate > a.cfg.MasscanRateLimitPPS {
		return &TaskError{Reason: fmt.Sprintf("masscan rate %d exceeds agent limit %d packets/second", rate, a.cfg.MasscanRateLimitPPS), Retryable: false}
	}
	if runtime.GOOS != "linux" {
		return &TaskError{Reason: "masscan executor requires Linux", Retryable: false}
	}
	path, err := exec.LookPath("masscan")
	if err != nil {
		return &TaskError{Reason: "masscan executable is required but was not found", Retryable: false}
	}
	wait := payload.WaitSeconds
	if wait <= 0 {
		wait = 15
	}
	timeout := boundedTimeout(payload.TimeoutSeconds, 180*time.Second)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := []string{"-p" + payload.Ports, "--rate", strconv.Itoa(rate), "--wait", strconv.Itoa(wait), "-oL", "-"}
	if a.cfg.MasscanInterface != "" {
		args = append(args, "--adapter", a.cfg.MasscanInterface)
	}
	if a.cfg.MasscanRouterMAC != "" {
		args = append(args, "--router-mac", a.cfg.MasscanRouterMAC)
	}
	args = append(args, payload.Targets...)
	cmd := exec.CommandContext(runCtx, path, args...)
	setProcessGroup(cmd)
	spool, err := os.CreateTemp("", "scanplatform-masscan-*.list")
	if err != nil {
		return err
	}
	spoolPath := spool.Name()
	defer os.Remove(spoolPath)
	defer spool.Close()
	spoolReader, err := os.Open(spoolPath)
	if err != nil {
		return err
	}
	defer spoolReader.Close()
	cmd.Stdout = spool
	stderr := &stderrTail{limit: 64 << 10}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	releaseProcess := a.resources.trackTool(toolMasscan, cmd.Process.Pid)
	defer releaseProcess()
	processDone := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			killProcessGroup(cmd.Process)
		case <-processDone:
		}
	}()
	waitDone := make(chan error, 1)
	go func() {
		waitErr := cmd.Wait()
		releaseProcess()
		waitDone <- waitErr
		_ = spool.Close()
		close(processDone)
	}()
	spoolDone := make(chan error, 1)
	go func() {
		spoolDone <- watchMasscanSpool(runCtx, spoolPath, processDone, cancel)
	}()
	targets := make(map[string]bool, len(payload.Targets))
	for _, target := range payload.Targets {
		targets[target] = true
	}
	scanErr := scanMasscan(&followingFileReader{ctx: runCtx, file: spoolReader, processDone: processDone}, func(obs Observation) error {
		if !targets[obs.IP] || obs.Port < first || obs.Port > last {
			return &TaskError{Reason: "masscan emitted an endpoint outside its assigned range", Retryable: false}
		}
		return emit(obs)
	})
	if scanErr != nil {
		cancel()
	}
	waitErr := <-waitDone
	spoolErr := <-spoolDone
	stderrText := stderr.String()
	if spoolErr != nil {
		return spoolErr
	}
	if scanErr != nil {
		return scanErr
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if stderrText != "" {
			return fmt.Errorf("masscan failed: %s", stderrText)
		}
		return fmt.Errorf("masscan failed: %w", waitErr)
	}
	if err := captureLossError(stderrText); err != nil {
		return err
	}
	return nil
}

type followingFileReader struct {
	ctx         context.Context
	file        *os.File
	processDone <-chan struct{}
	finished    bool
}

func (r *followingFileReader) Read(p []byte) (int, error) {
	for {
		if r.ctx.Err() != nil {
			return 0, context.Cause(r.ctx)
		}
		n, err := r.file.Read(p)
		if n > 0 || (err != nil && !errors.Is(err, io.EOF)) {
			return n, err
		}
		if r.finished {
			return 0, io.EOF
		}
		select {
		case <-r.ctx.Done():
			return 0, context.Cause(r.ctx)
		case <-r.processDone:
			r.finished = true
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func watchMasscanSpool(ctx context.Context, path string, processDone <-chan struct{}, cancel context.CancelFunc) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-processDone:
		case <-ticker.C:
		}
		info, err := os.Stat(path)
		if err == nil && info.Size() <= maxMasscanSpoolBytes {
			select {
			case <-processDone:
				return nil
			default:
				continue
			}
		}
		if err == nil {
			err = &TaskError{Reason: fmt.Sprintf("masscan result spool exceeded %d MiB", maxMasscanSpoolBytes>>20), Retryable: false}
		} else {
			err = fmt.Errorf("inspect masscan result spool: %w", err)
		}
		cancel()
		return err
	}
}

func captureLossError(stderr string) error {
	index := strings.LastIndex(stderr, "scan_capture: received=")
	if index < 0 {
		return &TaskError{Reason: "masscan capture statistics missing; coverage cannot be confirmed (use the bundled patched binary)", Retryable: false}
	}
	var received, dropped, ifDropped uint64
	if n, err := fmt.Sscanf(stderr[index:], "scan_capture: received=%d dropped=%d if_dropped=%d", &received, &dropped, &ifDropped); err != nil || n != 3 {
		return &TaskError{Reason: "invalid packet capture statistics", Retryable: false}
	}
	if dropped > 0 || ifDropped > 0 {
		return &TaskError{Reason: fmt.Sprintf("packet capture lost packets: dropped=%d interface_dropped=%d; scan coverage is incomplete", dropped, ifDropped), Retryable: false}
	}
	return nil
}

type stderrTail struct {
	data      []byte
	limit     int
	truncated bool
}

func (tail *stderrTail) Write(p []byte) (int, error) {
	n := len(p)
	if len(tail.data)+n > tail.limit {
		tail.truncated = true
		if n >= tail.limit {
			tail.data = append(tail.data[:0], p[n-tail.limit:]...)
			return n, nil
		}
		drop := len(tail.data) + n - tail.limit
		copy(tail.data, tail.data[drop:])
		tail.data = tail.data[:len(tail.data)-drop]
	}
	tail.data = append(tail.data, p...)
	return n, nil
}

func (tail *stderrTail) String() string {
	text := strings.TrimSpace(string(tail.data))
	if tail.truncated {
		text += " [truncated]"
	}
	return text
}

func readBoundedAndDrain(r io.Reader, limit int64) string {
	// Keep the final error and capture counters even after lengthy progress output.
	tail := stderrTail{limit: int(limit)}
	_, _ = io.Copy(&tail, r)
	return tail.String()
}

func validateMasscanNetwork(cfg *Config) error {
	if cfg.MasscanInterface != "" && !interfaceNamePattern.MatchString(cfg.MasscanInterface) {
		return fmt.Errorf("SCAN_MASSCAN_INTERFACE is not a valid interface name")
	}
	if cfg.MasscanRouterMAC == "" {
		return nil
	}
	mac, err := net.ParseMAC(cfg.MasscanRouterMAC)
	if err != nil || len(mac) != 6 {
		return fmt.Errorf("SCAN_MASSCAN_ROUTER_MAC must be a 48-bit MAC address")
	}
	allZero := true
	for _, value := range mac {
		allZero = allZero && value == 0
	}
	if allZero || mac[0]&1 != 0 {
		return fmt.Errorf("SCAN_MASSCAN_ROUTER_MAC must be a unicast MAC address")
	}
	cfg.MasscanRouterMAC = mac.String()
	return nil
}

func scanMasscan(r io.Reader, emit func(Observation) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) < 4 || fields[0] != "open" || fields[1] != "tcp" {
			return &TaskError{Reason: "invalid masscan list record", Retryable: false}
		}
		port, err := strconv.Atoi(fields[2])
		ip, ipErr := netip.ParseAddr(fields[3])
		if err != nil || port < 1 || port > 65535 || ipErr != nil || !ip.Is4() {
			return &TaskError{Reason: "invalid masscan TCP endpoint", Retryable: false}
		}
		if err := emit(Observation{Kind: "port", Target: fields[3], IP: fields[3], Port: port, Protocol: "tcp"}); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (a *Agent) runConnectPorts(ctx context.Context, payload portPayload, emit func(Observation) error) error {
	if !a.policy.allowPrivate {
		return &TaskError{Reason: "connect test executor requires SCAN_ALLOW_PRIVATE_TARGETS=true", Retryable: false}
	}
	if len(payload.TestPorts) == 0 {
		return &TaskError{Reason: "connect test executor requires payload.test_ports and never substitutes for 1-65535", Retryable: false}
	}
	for _, target := range payload.Targets {
		for _, port := range payload.TestPorts {
			if port < 1 || port > 65535 {
				return &TaskError{Reason: "invalid test port", Retryable: false}
			}
			address := net.JoinHostPort(target, strconv.Itoa(port))
			if err := a.policy.validateEndpoint(ctx, target, strconv.Itoa(port)); err != nil {
				return &TaskError{Reason: err.Error(), Retryable: false}
			}
			conn, err := (&net.Dialer{Timeout: 750 * time.Millisecond}).DialContext(ctx, "tcp", address)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return err
				}
				continue
			}
			_ = conn.Close()
			if err := emit(Observation{Kind: "port", Target: target, IP: target, Port: port, Protocol: "tcp"}); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseTCPPortRange accepts one inclusive interval. The control plane owns the
// manifest whose union is 1..65535; a worker must execute exactly its interval.
func parseTCPPortRange(value string) (first, last int, err error) {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, fmt.Errorf("invalid TCP port range %q", value)
	}
	for _, part := range parts {
		if part == "" {
			return 0, 0, fmt.Errorf("invalid TCP port range %q", value)
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return 0, 0, fmt.Errorf("invalid TCP port range %q", value)
			}
		}
	}
	first, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid TCP port range %q", value)
	}
	last = first
	if len(parts) == 2 {
		last, err = strconv.Atoi(parts[1])
	}
	if err != nil || first < 1 || last > 65535 || last < first {
		return 0, 0, fmt.Errorf("invalid TCP port range %q", value)
	}
	return first, last, nil
}
