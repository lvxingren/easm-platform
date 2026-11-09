//go:build linux || darwin

package scanner

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func prepareProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// afterStartProcess 在 Unix 上无需额外动作：Setpgid 已在启动前把子进程放进独立进程组，
// 后代进程（naabu 自己拉起的子进程）会继承该进程组，cleanupProcessGroup 用
// kill(-pgid, 0) 就能确认整组是否收敛。
func afterStartProcess(*exec.Cmd) error { return nil }

// processGroupLimitation 描述本平台“确认后代进程已退出”的能力边界，供异常消息直接引用。
func processGroupLimitation() string {
	return "Unix 进程组探活（kill(-pgid, 0)）未在限定时间内确认 ESRCH"
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

const (
	// processGroupProbeWindow 是 EPERM 时组级复探的上界。
	// 子进程刚退出、尚未被 Wait 回收的瞬间，Darwin 对整个进程组发信号会返回 EPERM；
	// 这段时间很短，只有在窗口内始终拿不到 ESRCH，才说明组确实还存在。
	processGroupProbeWindow = 150 * time.Millisecond
	// processGroupProbeInterval 是组级复探的轮询间隔。
	processGroupProbeInterval = 10 * time.Millisecond
)

// groupProbe 是一次进程组级探活（kill(-pgid, 0)）的结论。
// 组级探活是判断“组是否还在”的唯一依据：主 PID 的 Getpgid 只描述单个进程，
// 它在主进程被回收后立即报 ESRCH，即使组内仍有存活成员，因此不能作为证据。
type groupProbe int

const (
	// groupExists 表示组内仍有成员。EPERM 也归入此类：进程组存在但当前进程无权限。
	groupExists groupProbe = iota
	// groupGone 表示组级探活明确返回 ESRCH，进程组已不存在。
	groupGone
	// groupUnknown 表示探活本身失败（既非成功、EPERM 也非 ESRCH），不能作为判定依据。
	groupUnknown
)

// cleanupProcessGroup 主动终止 cmd 所属进程组（含 WaitDelay 强制收尾后仍残留的孙进程），
// 并在 timeout 内轮询确认组内进程全部消失。
// leftover 表示终止前组级探活仍能看到成员（说明主进程退出后遗留了子进程）；
// converged 表示组级探活已明确返回 ESRCH。仅关闭管道不算收敛：遗留 naabu 子进程会继续占用端口/CPU。
// EPERM 不算收敛：它只证明“组还在”，必须继续等待直到探活报 ESRCH 或超时。
func cleanupProcessGroup(cmd *exec.Cmd, timeout time.Duration) (leftover bool, converged bool) {
	if cmd == nil || cmd.Process == nil {
		return false, true
	}
	pid := cmd.Process.Pid
	// 终止前的组级探活：只有 ESRCH 才算“组内已无成员”。
	if probeProcessGroup(pid) != groupGone {
		leftover = true
	}
	_ = killProcess(cmd)
	deadline := time.Now().Add(timeout)
	for {
		switch probeProcessGroup(pid) {
		case groupGone:
			return leftover, true
		case groupUnknown:
			// 探活本身失败时无法证明收敛，不做无根据的成功判定。
			return leftover, false
		}
		if !time.Now().Before(deadline) {
			return leftover, false
		}
		time.Sleep(processGroupProbeInterval)
	}
}

// isTransientStartError 判断进程启动失败是否属于可短暂重试的瞬态错误。
// 工具缺失、无执行权限、参数错误等确定性失败不重试（平台不自动安装工具也不提权）。
func isTransientStartError(err error) bool {
	if err == nil {
		return false
	}
	for _, errno := range []syscall.Errno{syscall.EAGAIN, syscall.EINTR, syscall.ETXTBSY, syscall.EMFILE, syscall.ENFILE, syscall.ENOMEM} {
		if errors.Is(err, errno) {
			return true
		}
	}
	text := strings.ToLower(err.Error())
	for _, marker := range []string{
		"resource temporarily unavailable",
		"text file busy",
		"interrupted system call",
		"too many open files",
		"cannot allocate memory",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func signalProcessGroup(cmd *exec.Cmd, signal syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("naabu 进程尚未启动")
	}
	pid := cmd.Process.Pid
	err := syscall.Kill(-pid, signal)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if errors.Is(err, syscall.EPERM) && ignoreSignalError(err, resolveGroupProbe(pid)) {
		// EPERM 本身不是“组已消失”的证据：只有在同一进程组上重新探活拿到 ESRCH 才忽略。
		return nil
	}
	return err
}

// ignoreSignalError 判断 kill(-pgid, sig) 的错误是否可以安全忽略。
// probe 是同一进程组上重新做的组级探活结论（不是主 PID 的 Getpgid）：
//   - nil：信号已送达；
//   - ESRCH：进程组已不存在，信号的语义已经满足；
//   - EPERM 且组级探活返回 ESRCH（probe == groupGone）：组确实不在了，属正常收尾；
//   - EPERM 且组级探活仍能看到成员（groupExists）、或探活本身失败（groupUnknown）：
//     说明进程组存在但当前进程无权限，这是真实权限错误，必须原样上报。
func ignoreSignalError(err error, probe groupProbe) bool {
	switch {
	case err == nil, errors.Is(err, syscall.ESRCH):
		return true
	case errors.Is(err, syscall.EPERM):
		return probe == groupGone
	default:
		return false
	}
}

// probeProcessGroup 做一次组级探活：kill(-pgid, 0)。
//   - nil：组内仍有成员；
//   - ESRCH：组已不存在；
//   - EPERM：组仍存在但当前进程无权限（不能算作“已消失”）；
//   - 其他错误：探活失败，不能作为证据。
func probeProcessGroup(pid int) groupProbe {
	if pid <= 0 {
		return groupGone
	}
	err := syscall.Kill(-pid, 0)
	switch {
	case err == nil:
		return groupExists
	case errors.Is(err, syscall.ESRCH):
		return groupGone
	case errors.Is(err, syscall.EPERM):
		return groupExists
	default:
		return groupUnknown
	}
}

// resolveGroupProbe 在一个很短的上界内重复做组级探活：
// 只要观察到一次 ESRCH 就返回 groupGone；窗口内始终不是 ESRCH 时返回最后一次结论。
// 这样既能识别“组确实还在”（EPERM 持续），也不会把“子进程刚退出尚未被回收”的瞬态 EPERM 当成权限错误。
func resolveGroupProbe(pid int) groupProbe {
	deadline := time.Now().Add(processGroupProbeWindow)
	for {
		probe := probeProcessGroup(pid)
		if probe == groupGone || !time.Now().Before(deadline) {
			return probe
		}
		time.Sleep(processGroupProbeInterval)
	}
}
