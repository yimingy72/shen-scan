package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"scanplatform/internal/webevidence"
)

// One cheap capability query per Agent lifetime. Browser execution may update
// the cached diagnostic; heartbeat never spawns Chrome or a version subprocess.
func (a *Agent) browserAvailability() webevidence.BrowserCapability {
	a.browserCapabilityOnce.Do(func() {
		status := webevidence.BrowserCapability{UnavailableReason: "browser readiness not advertised by helper"}
		binary, ok := webProbeBinary()
		if !ok {
			status.UnavailableReason = "web browser helper is not installed"
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "--capabilities")
			setProcessGroup(cmd)
			cmd.Env = []string{"NO_COLOR=1", "PATH=/usr/local/bin:/usr/bin:/bin"}
			if runtime.GOOS == "linux" && os.Geteuid() == 0 {
				cmd.Env = append(cmd.Env, "WEB_BROWSER_EXECUTABLE=/usr/local/libexec/shen-browser-chrome")
			}
			var out cappedWebBuffer
			cmd.Stdout = &out
			cmd.Stderr = &stderrTail{limit: 4096}
			var cap struct {
				Ready   *bool  `json:"browser_ready"`
				Version string `json:"browser_version"`
				Reason  string `json:"browser_unavailable_reason"`
			}
			if err := cmd.Run(); err != nil {
				status.UnavailableReason = "browser helper capability check failed"
			} else if !out.overflow && json.Unmarshal(out.Bytes(), &cap) == nil && cap.Ready != nil {
				status.Ready = *cap.Ready
				status.Version = boundedBrowserDiagnostic(cap.Version, 128)
				status.UnavailableReason = boundedBrowserDiagnostic(cap.Reason, 512)
				if status.Ready {
					status.UnavailableReason = ""
				} else if status.UnavailableReason == "" {
					status.UnavailableReason = "system Chrome unavailable"
				}
			}
		}
		a.browserCapabilityMu.Lock()
		a.browserCapability = status
		a.browserCapabilityMu.Unlock()
	})
	a.browserCapabilityMu.Lock()
	defer a.browserCapabilityMu.Unlock()
	return a.browserCapability
}

func boundedBrowserDiagnostic(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func (a *Agent) recordBrowserAvailability(result webevidence.BrowserResult) {
	_ = a.browserAvailability()
	a.browserCapabilityMu.Lock()
	defer a.browserCapabilityMu.Unlock()
	if result.BrowserVersion != "" {
		a.browserCapability.Ready = true
		a.browserCapability.Version = boundedBrowserDiagnostic(result.BrowserVersion, 128)
		a.browserCapability.UnavailableReason = ""
	}
	if result.StopReason == "browser-unavailable" {
		a.browserCapability.Ready = false
		a.browserCapability.UnavailableReason = "browser helper reported system Chrome unavailable"
	}
}
