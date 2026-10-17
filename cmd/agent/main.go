package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"scanplatform/internal/agent"
)

func main() {
	hostname, _ := os.Hostname()
	sessionID, err := agent.RandomID()
	if err != nil {
		slog.Error("create session ID", "error", err)
		os.Exit(1)
	}
	instanceID := env("AGENT_INSTANCE_ID", hostname)
	cfg := agent.Config{
		ControlURL: env("AGENT_CONTROL_URL", "http://127.0.0.1:8080"), JoinToken: os.Getenv("SCAN_JOIN_TOKEN"),
		CAFile:     os.Getenv("AGENT_CA_FILE"),
		InstanceID: instanceID, Hostname: env("AGENT_HOSTNAME", hostname), AgentVersion: env("AGENT_VERSION", "dev"),
		SessionID: sessionID, AZ: os.Getenv("AGENT_AZ"), Spec: json.RawMessage(env("AGENT_SPEC", "{}")),
		MaxTasks: envInt("AGENT_MAX_TASKS", 17), EndpointConcurrency: envInt("AGENT_ENDPOINT_CONCURRENCY", 16),
		AllowPrivateTargets: envBool("SCAN_ALLOW_PRIVATE_TARGETS"), PortExecutor: env("SCAN_PORT_EXECUTOR", "masscan"),
		MasscanRateLimitPPS: envInt("SCAN_MASSCAN_MAX_RATE_PPS", 20000),
		MasscanInterface:    os.Getenv("SCAN_MASSCAN_INTERFACE"), MasscanRouterMAC: os.Getenv("SCAN_MASSCAN_ROUTER_MAC"),
		MetadataURL:       env("AGENT_METADATA_URL", "http://100.100.100.200/latest/meta-data/instance/spot/termination-time"),
		HTTPXBinary:       env("HTTPX_BINARY", "httpx"),
		HTTPXMaxProcesses: envInt("HTTPX_MAX_PROCESSES", 2),
		HTTPXThreads:      envInt("HTTPX_THREADS", 8),
		NucleiBinary:      env("NUCLEI_BINARY", "nuclei"),
	}
	worker, err := agent.New(cfg)
	if err != nil {
		slog.Error("configure agent", "error", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := worker.Run(ctx); err != nil {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err == nil && value > 0 {
		return value
	}
	return fallback
}

func envBool(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return value == "1" || value == "true" || value == "yes"
}
