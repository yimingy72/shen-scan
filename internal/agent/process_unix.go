//go:build unix

package agent

import (
	"os"
	"os/exec"
	"syscall"
)

func setProcessGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func killProcessGroup(process *os.Process) {
	if process != nil {
		_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
	}
}
