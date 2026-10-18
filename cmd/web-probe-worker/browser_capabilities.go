package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"scanplatform/internal/webevidence"
)

func webProbeCapabilities(ctx context.Context) map[string]any {
	capabilities := map[string]any{"web_scan_options_profile": webevidence.WebScanOptionsProfile, "protocol": webevidence.Protocol, "profile": webevidence.Profile, "engine": "httpx-sdk-v1.12.0/bounded-transport+wappalyzergo-v0.2.96", "request_admission": "loopback-v2", "stream_protocol": "jsonl-item-v1", "enrichment_profile": webevidence.EnrichmentProfile, "full_profile": webevidence.FullProfile, "browser_profile": webevidence.BrowserProfile, "browser_engine": browserEngine, "browser_stream_protocol": "jsonl-item-v1", "full_engine": fullEngine, "full_capabilities": "runner,title,headers,tls,redirects,hashes,wappalyzer,favicon", "full_capability_gaps": "wappalyzer-browser-js-dom (when selected CFF requires it)"}
	status := browserCapabilityStatus(ctx)
	capabilities["browser_ready"] = status.Ready
	capabilities["browser_version"] = status.Version
	capabilities["browser_unavailable_reason"] = status.UnavailableReason
	return capabilities
}

// Only inspect the installed runtime: no Chrome launch, profile reuse, socket
// listener or browser download occurs during capability discovery.
func browserCapabilityStatus(parent context.Context) webevidence.BrowserCapability {
	status := webevidence.BrowserCapability{}
	if runtime.GOOS != "linux" {
		status.UnavailableReason = "verified browser egress isolation unavailable on this platform"
		return status
	}
	if os.Geteuid() != 0 {
		status.UnavailableReason = "browser isolation requires root helper with non-root Chrome wrapper"
		return status
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	profile, err := os.MkdirTemp("/tmp", "shen-browser-capability-*")
	if err != nil {
		status.UnavailableReason = err.Error()
		return status
	}
	defer os.RemoveAll(profile)
	// Reuse the exact startup preflight: root-owned wrapper verifies ready marker,
	// installed minimum version and both real UID firewall chains before its proof.
	if _, err = browserIsolatedLauncher(ctx, profile); err != nil {
		status.UnavailableReason = err.Error()
		return status
	}
	raw, err := exec.CommandContext(ctx, "/usr/bin/google-chrome-stable", "--version").Output()
	if err != nil {
		status.UnavailableReason = fmt.Sprintf("system Chrome version query failed: %v", err)
		return status
	}
	version := strings.Join(strings.Fields(string(raw)), " ")
	if !strings.HasPrefix(version, "Google Chrome ") || len(version) > 128 {
		status.UnavailableReason = "system Chrome returned invalid version"
		return status
	}
	status.Ready = true
	status.Version = version
	return status
}
