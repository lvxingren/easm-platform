//go:build !linux && !darwin && !windows

package scanner

import (
	"fmt"
	"os/exec"
	"time"
)

func prepareProcess(cmd *exec.Cmd) {}

// afterStartProcess 在无法建立受控作业/进程组的平台上明确返回错误：
// 调用方据此判定“后代进程无法确认”，不得伪报收敛。
func afterStartProcess(*exec.Cmd) error {
	return fmt.Errorf("当前操作系统不支持进程组或作业对象，无法确认 naabu 后代进程已退出")
}

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

// cleanupProcessGroup 在本平台只能终止主进程，无法枚举或确认后代进程是否退出。
// 因此这里一律返回 converged=false：只关闭管道/杀掉主进程不能算“进程组已收敛”，
// 上层据此把批次判为不完整、并且不自动重试（重试只会沉积更多无法追踪的残留进程）。
func cleanupProcessGroup(cmd *exec.Cmd, _ time.Duration) (leftover bool, converged bool) {
	if cmd == nil || cmd.Process == nil {
		return false, true
	}
	_ = killProcess(cmd)
	return false, false
}

// processGroupLimitation 描述本平台确认后代进程的能力边界。
func processGroupLimitation() string {
	return "本平台没有进程组/作业对象，无法枚举后代进程确认退出"
}

// isTransientStartError：本平台不做进程启动重试（保留各平台最小差异）。
func isTransientStartError(error) bool { return false }
