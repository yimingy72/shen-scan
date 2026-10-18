package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/go-rod/rod/lib/launcher"
)

const browserMacSandbox = `(version 1)(allow default)(deny network-outbound)(allow network-inbound (local ip "localhost:*"))`

// Go owns permitted HTTP sockets. The browser and all its descendants have an
// independent OS-enforced outbound denial; the CDP controller connects inbound.
func browserIsolatedLauncher(ctx context.Context, profile string) (string, error) {
	switch runtime.GOOS {
	case "linux":
		wrapper := os.Getenv("WEB_BROWSER_EXECUTABLE")
		if wrapper == "" {
			wrapper = os.Getenv("SHEN_BROWSER_LAUNCHER")
		}
		if wrapper == "" {
			wrapper = "/usr/local/libexec/shen-browser-chrome"
		}
		if !filepath.IsAbs(wrapper) {
			return "", errors.New("browser isolation launcher must have an absolute path")
		}
		info, err := os.Stat(wrapper)
		if err != nil {
			return "", fmt.Errorf("browser isolation launcher unavailable: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || !info.Mode().IsRegular() {
			return "", errors.New("browser isolation launcher must be root-owned and not writable by group/other")
		}
		checkCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		raw, err := exec.CommandContext(checkCtx, wrapper, "--shen-browser-isolation-check").Output()
		if err != nil {
			return "", fmt.Errorf("browser egress isolation verification failed: %w", err)
		}
		var proof struct {
			Isolation string `json:"isolation"`
			UID       int    `json:"uid"`
			CDPPort   int    `json:"cdp_port"`
			Verified  bool   `json:"verified"`
		}
		// Some iptables backends print the verified matching rule before the
		// wrapper's final proof line. The root-owned wrapper's final JSON is
		// authoritative only when the whole check command exited successfully.
		lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
		proofRaw := lines[len(lines)-1]
		if len(raw) > 4096 || json.Unmarshal(proofRaw, &proof) != nil || !proof.Verified || proof.Isolation != "uid-firewall-v1" || proof.UID <= 0 || proof.CDPPort != browserCDPPort {
			return "", errors.New("browser isolation wrapper returned invalid firewall proof")
		}
		if os.Geteuid() != 0 {
			return "", errors.New("browser isolation launcher requires root helper for controlled Go requests and profile ownership")
		}
		if err = os.Chown(profile, proof.UID, -1); err != nil {
			return "", fmt.Errorf("browser profile ownership: %w", err)
		}
		return wrapper, nil
	case "darwin":
		bin, ok := launcher.LookPath()
		if !ok {
			return "", errors.New("installed Chromium browser unavailable (automatic download disabled)")
		}
		if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
			return "", errors.New("browser OS egress sandbox unavailable")
		}
		wrapper := filepath.Join(profile, "chromium-sandbox-launcher")
		quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
		script := "#!/bin/sh\nexec /usr/bin/sandbox-exec -p " + quote(browserMacSandbox) + " " + quote(bin) + " \"$@\"\n"
		if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
			return "", err
		}
		return wrapper, nil
	default:
		return "", errors.New("browser OS egress isolation unavailable on this platform")
	}
}
