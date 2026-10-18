package main

import (
	"context"
	"path/filepath"
	"scanplatform/internal/webevidence"
	"strings"
	"testing"
)

func TestWebProbeCapabilitiesWithoutBrowser(t *testing.T) {
	t.Setenv("WEB_BROWSER_EXECUTABLE", filepath.Join(t.TempDir(), "not-installed"))
	capabilities := webProbeCapabilities(context.Background())
	if capabilities["web_scan_options_profile"] != webevidence.WebScanOptionsProfile {
		t.Fatal("independent options profile missing")
	}
	ready, ok := capabilities["browser_ready"].(bool)
	if !ok || ready {
		t.Fatal("missing isolation runtime reported ready")
	}
	reason, _ := capabilities["browser_unavailable_reason"].(string)
	if reason == "" {
		t.Fatal("unavailable reason missing")
	}
	if _, ok := capabilities["browser_version"].(string); !ok {
		t.Fatal("browser version has wrong type")
	}
	full, _ := capabilities["full_capabilities"].(string)
	if !strings.Contains(full, "favicon") || capabilities["request_admission"] != "loopback-v2" {
		t.Fatal("browser absence removed ordinary HTTP capability")
	}
}
