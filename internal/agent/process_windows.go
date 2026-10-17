//go:build windows

package agent

import (
	"os"
	"os/exec"
)

func setProcessGroup(cmd *exec.Cmd) {}

func killProcessGroup(process *os.Process) {
	if process != nil {
		_ = process.Kill()
	}
}
