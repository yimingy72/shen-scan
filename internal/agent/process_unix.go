//go:build unix

package agent

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// CommandContext otherwise kills only the direct child. Kill its process group
	// before Wait returns so release/stop confirmation cannot race descendants.
	if cmd.Cancel != nil {
		cmd.Cancel = func() error {
			if cmd.Process == nil {
				return os.ErrProcessDone
			}
			err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
	}
	cmd.WaitDelay = 2 * time.Second
}

func killProcessGroup(process *os.Process) {
	if process != nil {
		_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
	}
}
