package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
)

// Statistical artifact identity only. Keep the declared port_profile intact:
// it is the independently calibrated startup performance/configuration group.
func (a *Agent) portCostProfile() string {
	if a.portExecutor != "masscan" {
		return ""
	}
	path, err := exec.LookPath("masscan")
	if err != nil {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return ""
	}
	return "masscan-sha256:" + hex.EncodeToString(h.Sum(nil))
}
