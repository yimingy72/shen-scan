package agent

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxNmapXMLBytes = 8 << 20

// A batch is grouped by exact IP, never by the union of different hosts' ports.
// This also pins the connection address rather than asking Nmap to resolve a name.
func (a *Agent) runNmapService(ctx context.Context, payload servicePayload, emit func(Observation) error) error {
	path, err := exec.LookPath(a.cfg.NmapBinary)
	if err != nil {
		return &TaskError{Reason: "nmap executable is required but was not found", Retryable: false}
	}
	groups := make(map[string][]Endpoint)
	var hosts []string
	seen := make(map[string]bool)
	for _, ep := range payload.Endpoints {
		ip, err := netip.ParseAddr(ep.IP)
		if err != nil || !ip.Is4() || ep.Port < 1 || ep.Port > 65535 {
			return &TaskError{Reason: "nmap service endpoints require a pinned IPv4 address and valid TCP port", Retryable: false}
		}
		if err := a.policy.validateIP(ip); err != nil {
			return &TaskError{Reason: err.Error()}
		}
		if err := a.policy.validateEndpoint(ctx, ep.IP, strconv.Itoa(ep.Port)); err != nil {
			return &TaskError{Reason: err.Error()}
		}
		key := ep.IP + ":" + strconv.Itoa(ep.Port)
		if seen[key] {
			return &TaskError{Reason: "duplicate nmap service endpoint", Retryable: false}
		}
		seen[key] = true
		if _, ok := groups[ep.IP]; !ok {
			hosts = append(hosts, ep.IP)
		}
		groups[ep.IP] = append(groups[ep.IP], ep)
	}
	for _, host := range hosts {
		// Keep Nmap's one-process working set bounded even for high-open targets.
		endpoints := groups[host]
		for len(endpoints) > 0 {
			n := min(len(endpoints), 32)
			if err := a.runNmapBatch(ctx, path, endpoints[:n], boundedTimeout(payload.TimeoutSeconds, 90*time.Second), emit); err != nil {
				return err
			}
			endpoints = endpoints[n:]
		}
	}
	return nil
}

func nmapArgs(endpoints []Endpoint, timeout time.Duration) []string {
	ports := make([]int, 0, len(endpoints))
	for _, ep := range endpoints {
		ports = append(ports, ep.Port)
	}
	sort.Ints(ports)
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(port)
	}
	seconds := max(1, int(timeout/time.Second))
	return []string{"-sT", "-sV", "--version-light", "-Pn", "-n", "--max-retries", "1", "--max-parallelism", "4", "--host-timeout", strconv.Itoa(seconds) + "s", "-p", strings.Join(values, ","), "-oX", "-", endpoints[0].IP}
}

func (a *Agent) runNmapBatch(ctx context.Context, path string, endpoints []Endpoint, timeout time.Duration, emit func(Observation) error) error {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, path, nmapArgs(endpoints, timeout)...)
	setProcessGroup(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr := &stderrTail{limit: 64 << 10}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	releaseProcess := a.resources.trackTool(toolNmap, cmd.Process.Pid)
	defer releaseProcess()
	parsed, parseErr := parseNmapXML(io.LimitReader(stdout, maxNmapXMLBytes+1), endpoints, emit)
	if parseErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	releaseProcess()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if parsed.emitErr != nil {
		return parsed.emitErr
	}

	// Completed XML port records remain useful if a sibling endpoint timed out.
	// Missing records get an explicit terminal outcome; no absent record is success.
	problem := ""
	outcome := "error"
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		problem, outcome = "nmap endpoint deadline exceeded", "timeout"
	case parseErr != nil:
		problem = "nmap XML incomplete: " + parseErr.Error()
	case waitErr != nil:
		problem = "nmap failed: " + stderr.String()
	case !parsed.success:
		problem = "nmap did not report successful scan completion"
	default:
		problem = "nmap did not report an endpoint result (host timeout or omitted port)"
	}
	for _, ep := range endpoints {
		if parsed.seen[ep.Port] {
			continue
		}
		obs := nmapObservation(ep)
		obs.Outcome, obs.Coverage, obs.Error, obs.WebCandidate = outcome, "incomplete", problem, true
		// Nmap intentionally excludes raw printing ports from version detection.
		if ep.Port == 9100 {
			obs.Outcome, obs.Error, obs.WebCandidate = "skipped_by_policy", "excluded by nmap version-detection profile", false
		}
		if err := emit(obs); err != nil {
			return err
		}
	}
	return nil
}

type nmapParseResult struct {
	seen    map[int]bool
	success bool
	emitErr error
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	ID       int    `xml:"portid,attr"`
	State    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"state"`
	Service struct {
		Name        string `xml:"name,attr"`
		Product     string `xml:"product,attr"`
		Version     string `xml:"version,attr"`
		Extra       string `xml:"extrainfo,attr"`
		Method      string `xml:"method,attr"`
		Confidence  int    `xml:"conf,attr"`
		Tunnel      string `xml:"tunnel,attr"`
		Fingerprint string `xml:"servicefp,attr"`
	} `xml:"service"`
}

func nmapObservation(ep Endpoint) Observation {
	return Observation{Kind: "service", WorkKey: ep.WorkKey, Target: endpointTarget(ep), IP: ep.IP, Port: ep.Port, Protocol: "tcp", Engine: "nmap"}
}

// Stream complete <port> elements so a truncated trailing document does not
// discard previously parsed results. XML is bounded by the caller.
func parseNmapXML(reader io.Reader, endpoints []Endpoint, emit func(Observation) error) (nmapParseResult, error) {
	result := nmapParseResult{seen: make(map[int]bool)}
	allowed := make(map[int]Endpoint, len(endpoints))
	for _, ep := range endpoints {
		allowed[ep.Port] = ep
	}
	decoder := xml.NewDecoder(reader)
	rootClosed := false
	matchedAddress := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			if !rootClosed {
				return result, io.ErrUnexpectedEOF
			}
			return result, nil
		}
		if err != nil {
			return result, err
		}
		if end, ok := token.(xml.EndElement); ok && end.Name.Local == "nmaprun" {
			rootClosed = true
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "address":
			var value struct {
				Addr string `xml:"addr,attr"`
				Type string `xml:"addrtype,attr"`
			}
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return result, err
			}
			if value.Type == "ipv4" {
				if value.Addr != endpoints[0].IP {
					return result, fmt.Errorf("nmap returned an unassigned IP")
				}
				matchedAddress = true
			}
		case "port":
			if !matchedAddress {
				return result, fmt.Errorf("nmap port result has no assigned host address")
			}
			var value nmapPort
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return result, err
			}
			ep, ok := allowed[value.ID]
			if !ok || value.Protocol != "tcp" || result.seen[value.ID] {
				return result, fmt.Errorf("nmap returned an unassigned or duplicate port")
			}
			obs := nmapObservation(ep)
			obs.ServiceMethod, obs.ServiceTunnel = value.Service.Method, value.Service.Tunnel
			obs.ServiceConfidence = "nmap_" + value.Service.Method
			obs.Coverage = "complete"
			if value.State.State != "open" {
				obs.Outcome, obs.Error = "not_open", "nmap observed "+value.State.State
			} else {
				obs.Service, obs.Product, obs.Version = value.Service.Name, value.Service.Product, value.Service.Version
				obs.Banner = value.Service.Fingerprint
				if len(obs.Banner) > 4096 {
					obs.Banner, obs.Truncated = obs.Banner[:4096], true
				}
				obs.Evidence = strings.TrimSpace(strings.Join([]string{value.Service.Name, value.Service.Product, value.Service.Version, value.Service.Extra, fmt.Sprintf("method=%s conf=%d tunnel=%s", value.Service.Method, value.Service.Confidence, value.Service.Tunnel)}, " "))
				obs.Outcome = "identified"
				if value.Service.Method != "probed" || value.Service.Name == "" || value.Service.Name == "unknown" || value.Service.Name == "tcpwrapped" {
					obs.Outcome, obs.Service, obs.Product, obs.Version = "unknown", "unknown", "", ""
				}
				name := strings.ToLower(value.Service.Name)
				obs.WebCandidate = obs.Outcome == "unknown" || strings.Contains(name, "http") || name == "ssl" || name == "tls"
				if ep.Port == 9100 && value.Service.Method != "probed" {
					obs.Outcome, obs.Coverage, obs.WebCandidate = "skipped_by_policy", "incomplete", false
					obs.Error = "excluded by nmap version-detection profile"
				}
			}
			if err := emit(obs); err != nil {
				result.emitErr = err
				return result, err
			}
			result.seen[value.ID] = true
		case "finished":
			for _, attr := range start.Attr {
				if attr.Name.Local == "exit" {
					result.success = attr.Value == "success"
				}
			}
		}
	}
}
