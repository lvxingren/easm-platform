//go:build !linux && !darwin

package scanner

import (
	"fmt"
	"os/exec"
)

func prepareProcess(cmd *exec.Cmd) {}

func pauseProcess(cmd *exec.Cmd) error {
	return fmt.Errorf("当前操作系统不支持暂停 naabu 进程")
}

func resumeProcess(cmd *exec.Cmd) error {
	return fmt.Errorf("当前操作系统不支持恢复 naabu 进程")
}

func killProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("naabu 进程尚未启动")
	}
	return cmd.Process.Kill()
}
