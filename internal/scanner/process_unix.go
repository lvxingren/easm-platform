//go:build linux || darwin

package scanner

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
)

func prepareProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func pauseProcess(cmd *exec.Cmd) error {
	return signalProcessGroup(cmd, syscall.SIGSTOP)
}

func resumeProcess(cmd *exec.Cmd) error {
	return signalProcessGroup(cmd, syscall.SIGCONT)
}

func killProcess(cmd *exec.Cmd) error {
	return signalProcessGroup(cmd, syscall.SIGKILL)
}

func signalProcessGroup(cmd *exec.Cmd, signal syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("naabu 进程尚未启动")
	}
	if err := syscall.Kill(-cmd.Process.Pid, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
