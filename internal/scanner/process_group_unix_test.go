//go:build linux || darwin

package scanner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// idleCommand 返回一个只 sleep 的辅助进程（不经 shell，避免参数拼接），
// 用于构造“存活进程组”与“已回收进程组”两种真实场景。
func idleCommand(t *testing.T, seconds string) *exec.Cmd {
	t.Helper()
	for _, candidate := range []string{"/bin/sleep", "/usr/bin/sleep"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return exec.Command(candidate, seconds)
		}
	}
	if path, err := exec.LookPath("sleep"); err == nil {
		return exec.Command(path, seconds)
	}
	t.Fatal("测试依赖的系统 sleep 工具缺失")
	return nil
}

// 本文件覆盖“进程组探活/终止判定”的最小修复（Darwin 对整组信号的 EPERM）：
//   - 只有组级探活（kill(-pgid, 0)）明确返回 ESRCH 才能判定进程组消失；
//     主 PID 的 Getpgid 只描述单个进程，主进程被回收后即使组内仍有存活成员也会报 ESRCH，
//     因此绝不能拿它当“组已消失”的证据；
//   - EPERM 表示“组存在但当前进程无权限”，必须原样上报，不能被泛化吞掉。

// TestIgnoreSignalErrorDoesNotSwallowRealPermissionErrors 是纯判定表的负向对照：
// EPERM + 组级探活仍能看到成员 必须返回 false，避免“权限不足”被当成“已经终止”；
// 只有组级探活拿到 ESRCH（groupGone）时才能忽略 EPERM。
func TestIgnoreSignalErrorDoesNotSwallowRealPermissionErrors(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		probe groupProbe
		want  bool
	}{
		{name: "信号已送达", err: nil, probe: groupExists, want: true},
		{name: "组级探活-ESRCH", err: syscall.ESRCH, probe: groupExists, want: true},
		{name: "组已消失-EPERM可忽略", err: syscall.EPERM, probe: groupGone, want: true},
		{name: "组仍存在-EPERM必须上报", err: syscall.EPERM, probe: groupExists, want: false},
		{name: "组探活失败-EPERM必须上报", err: syscall.EPERM, probe: groupUnknown, want: false},
		{name: "组仍存在-包装后的EPERM必须上报", err: fmt.Errorf("kill: %w", syscall.EPERM), probe: groupExists, want: false},
		{name: "组已消失-包装后的EPERM", err: fmt.Errorf("kill: %w", syscall.EPERM), probe: groupGone, want: true},
		{name: "其他错误必须上报", err: syscall.EINVAL, probe: groupGone, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ignoreSignalError(tc.err, tc.probe); got != tc.want {
				t.Fatalf("ignoreSignalError(%v, probe=%v)=%v，期望 %v", tc.err, tc.probe, got, tc.want)
			}
		})
	}
}

// TestProbeProcessGroupDistinguishesReap 证明组级探活能区分“组内仍有成员”和“组已回收”，
// 且已回收组的终止/暂停不再返回错误（生产 Stop 不会抛 operation not permitted）。
func TestProbeProcessGroupDistinguishesReap(t *testing.T) {
	cmd := idleCommand(t, "0")
	prepareProcess(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动辅助进程失败: %v", err)
	}
	pid := cmd.Process.Pid
	if probe := probeProcessGroup(pid); probe != groupExists {
		t.Fatalf("刚启动的进程组应判定为存在，实际 probe=%v", probe)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("回收辅助进程失败: %v", err)
	}
	if probe := probeProcessGroup(pid); probe != groupGone {
		t.Fatalf("进程 %d 已回收且无残留成员，组级探活应返回 ESRCH，实际 probe=%v", pid, probe)
	}
	if err := killProcess(cmd); err != nil {
		t.Fatalf("已回收进程组的终止应视为已完成，实际错误: %v", err)
	}
	if err := pauseProcess(cmd); err != nil {
		t.Fatalf("已回收进程组的暂停应视为已完成，实际错误: %v", err)
	}
}

// TestProbeProcessGroupSeesReparentedGrandchild 证明“主 PID 的 Getpgid 报 ESRCH”不足以说明组已消失：
// 主进程退出被回收后，仍留在同一进程组里的孙进程会让组级探活继续看到成员。
// 这是 EPERM 判定必须依赖组级证据的真实依据。
func TestProbeProcessGroupSeesReparentedGrandchild(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	scriptPath := filepath.Join(dir, "linger.sh")
	script := "#!/bin/sh\nsleep 30 &\nprintf '%s\\n' \"$!\" > " + pidFile + "\nexit 0\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("/bin/sh", scriptPath)
	prepareProcess(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动辅助脚本失败: %v", err)
	}
	pid := cmd.Process.Pid
	childPid := waitForPidFile(t, pidFile)
	t.Cleanup(func() {
		_ = syscall.Kill(childPid, syscall.SIGKILL)
		_ = killProcess(cmd)
	})
	// 回收主进程：此刻主 PID 已不存在。
	if err := cmd.Wait(); err != nil {
		t.Fatalf("回收辅助脚本失败: %v", err)
	}
	if _, err := syscall.Getpgid(pid); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("主 PID %d 已回收，Getpgid 应返回 ESRCH，实际 %v", pid, err)
	}
	// 单 PID 证据已经失效，但组级探活必须仍能看到孙进程。
	if probe := probeProcessGroup(pid); probe != groupExists {
		t.Fatalf("组内仍有存活孙进程 %d，组级探活不应判定为消失，实际 probe=%v", childPid, probe)
	}
	if err := syscall.Kill(childPid, 0); err != nil {
		t.Fatalf("孙进程 %d 应仍在运行: %v", childPid, err)
	}
	// 组级终止必须真正生效（这里返回 nil 即证明信号已送达整个进程组）。
	if err := killProcess(cmd); err != nil {
		t.Fatalf("终止仍有成员的进程组失败: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if probeProcessGroup(pid) == groupGone {
			return
		}
		time.Sleep(processGroupProbeInterval)
	}
	t.Fatal("孙进程被终止后进程组未在 5 秒内消失")
}

// TestProbeProcessGroupForLiveProcess 证明存活进程组不会被误判为已回收：
// 暂停/恢复/终止语义保持有效；终止并回收主进程后，组级探活最终收敛到 ESRCH。
//
// 注意“终止”与“组消失”不是同一时刻：信号送达后、主进程尚未被 Wait 回收前，
// 它会以僵尸身份继续留在进程组里，组级探活仍返回 EPERM（groupExists）。
// 因此这里的顺序必须是“终止 → 回收 → 再断言组消失”，否则断言的是回收行为而不是组状态。
func TestProbeProcessGroupForLiveProcess(t *testing.T) {
	cmd := idleCommand(t, "30")
	prepareProcess(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动辅助进程失败: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = killProcess(cmd)
		_ = cmd.Wait()
	})
	if probe := probeProcessGroup(pid); probe != groupExists {
		t.Fatalf("存活进程组被误判为已消失，probe=%v", probe)
	}
	if err := pauseProcess(cmd); err != nil {
		t.Fatalf("暂停存活进程组失败: %v", err)
	}
	if err := resumeProcess(cmd); err != nil {
		t.Fatalf("恢复存活进程组失败: %v", err)
	}
	if probe := probeProcessGroup(pid); probe != groupExists {
		t.Fatalf("暂停/恢复后被误判为已消失，probe=%v", probe)
	}
	if err := killProcess(cmd); err != nil {
		t.Fatalf("终止存活进程组失败: %v", err)
	}
	// 未被回收的主进程仍属于该组：此刻不能宣称组已消失（这正是 EPERM 必须上报的场景）。
	if probe := probeProcessGroup(pid); probe != groupExists {
		t.Fatalf("终止但尚未回收的进程组仍应判为存在，实际 probe=%v", probe)
	}
	var exitErr *exec.ExitError
	if err := cmd.Wait(); err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("回收被终止的辅助进程失败: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if probeProcessGroup(pid) == groupGone {
			return
		}
		time.Sleep(processGroupProbeInterval)
	}
	t.Fatal("终止并回收后进程组未在 5 秒内消失")
}

// waitForPidFile 读取辅助脚本写入的孙进程 PID，直到出现合法值或超时。
func waitForPidFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if pid, convErr := strconv.Atoi(strings.TrimSpace(string(data))); convErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待孙进程 PID 文件 %q 失败", path)
	return 0
}
