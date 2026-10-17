package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"scanplatform/internal/rulelib"
)

type servicePayload struct {
	Endpoints      []Endpoint     `json:"endpoints"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Rules          []rulelib.Rule `json:"rules"`
}

func (a *Agent) runService(ctx context.Context, task Task, emit func(Observation) error) error {
	var payload servicePayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return &TaskError{Reason: "invalid service payload: " + err.Error()}
	}
	if len(payload.Endpoints) == 0 {
		return &TaskError{Reason: "service task has no endpoints"}
	}
	if err := validateTaskRules(payload.Rules, "port"); err != nil {
		return &TaskError{Reason: "invalid port rules: " + err.Error(), Retryable: false}
	}
	timeout := boundedTimeout(payload.TimeoutSeconds, 90*time.Second)
	return runEndpointsWithLimit(ctx, payload.Endpoints, a.endpointSlots, 8, func(ctx context.Context, ep Endpoint) Observation {
		obs := a.probeService(ctx, ep, timeout)
		if payload.Rules != nil && obs.Error == "" {
			applyPortRules(payload.Rules, &obs)
		}
		return obs
	}, emit)
}

func applyPortRules(rules []rulelib.Rule, obs *Observation) {
	input := rulelib.Input{Banner: obs.Banner, Service: obs.Service, Product: obs.Product, Version: obs.Version}
	obs.Product, obs.Version = "", ""
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		match, ok := rulelib.Match(rule, input)
		if !ok {
			continue
		}
		if match.Service != "" {
			obs.Service = match.Service
		}
		obs.Product, obs.Version = match.Product, match.Version
		obs.RuleID, obs.RuleName, obs.RuleRevision = rule.ID, rule.Name, rule.Revision
		obs.Engine, obs.Severity, obs.Evidence = rule.Engine, rule.Severity, match.Evidence
		return
	}
}

func (a *Agent) probeService(ctx context.Context, ep Endpoint, taskTimeout time.Duration) Observation {
	obs := Observation{Kind: "service", Target: endpointTarget(ep), IP: ep.IP, Port: ep.Port, Protocol: "tcp"}
	host := ep.IP
	if host == "" {
		host = ep.Host
	}
	if host == "" || ep.Port < 1 || ep.Port > 65535 {
		obs.Error = "invalid service endpoint"
		return obs
	}
	probeTimeout := minDuration(taskTimeout, 5*time.Second)
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if _, err := a.policy.resolve(probeCtx, host); err != nil {
		obs.Error = err.Error()
		return obs
	}
	port := strconv.Itoa(ep.Port)
	if err := a.policy.validateEndpoint(probeCtx, host, port); err != nil {
		obs.Error = err.Error()
		return obs
	}
	address := net.JoinHostPort(host, port)
	if isTLSPort(ep.Port) {
		rawConn, err := a.safeDialer(ep.IP)(probeCtx, "tcp", address)
		if err == nil {
			conn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, ServerName: ep.Host}) // scanner must fingerprint self-signed endpoints
			_ = conn.SetDeadline(contextDeadline(probeCtx, probeTimeout))
			err = conn.HandshakeContext(probeCtx)
			if err != nil {
				_ = conn.Close()
			} else {
				defer conn.Close()
				state := conn.ConnectionState()
				obs.Service, obs.Product = "tls", "TLS"
				obs.Version = tlsVersion(state.Version)
				return obs
			}
		}
	}
	conn, err := a.safeDialer(ep.IP)(probeCtx, "tcp", address)
	if err != nil {
		obs.Error = err.Error()
		return obs
	}
	defer conn.Close()
	_ = conn.SetDeadline(contextDeadline(probeCtx, minDuration(probeTimeout, 2*time.Second)))
	if request := serviceProbe(ep.Port, host); request != "" {
		_, _ = io.WriteString(conn, request)
	}
	banner, _ := io.ReadAll(io.LimitReader(conn, 4096))
	obs.Banner = string(banner)
	obs.Service, obs.Product, obs.Version = identifyService(ep.Port, string(banner))
	return obs
}

func contextDeadline(ctx context.Context, limit time.Duration) time.Time {
	deadline := time.Now().Add(limit)
	if contextLimit, ok := ctx.Deadline(); ok && contextLimit.Before(deadline) {
		return contextLimit
	}
	return deadline
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return fmt.Sprintf("0x%x", v)
}
