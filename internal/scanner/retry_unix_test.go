//go:build linux || darwin

package scanner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"easm-platform/internal/store"
)

// retryThenReadyScript：未创建 ready 文件时始终以非零状态退出（附带 stderr），
// 存在 ready 后正常输出一条结果；count 文件记录进程实际启动次数。
const retryThenReadyScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
n=0
if [ -f count ]; then n=$(cat count); fi
n=$((n + 1))
printf '%s\n' "$n" > count
if [ ! -f ready ]; then
  echo 'naabu: temporary failure while starting scan' >&2
  exit 1
fi
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
`

// TestSecondStartTaskAfterAbnormalExit 验证批次异常退出（重试耗尽）后运行标志被释放，
// 同一任务可以再次通过 StartTask 启动并完整跑完。
func TestSecondStartTaskAfterAbnormalExit(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, retryThenReadyScript)
	firstID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForScanStatus(t, st, firstID, "failed")
	waitForRunnerIdle(t, runner)

	first, _ := st.Scan(firstID)
	if first == nil || !strings.Contains(first.Err, "共 3 次尝试") {
		t.Fatalf("重试耗尽后错误信息未记录尝试次数: %+v", first)
	}
	if got := strings.TrimSpace(readTestFile(t, "count")); got != "3" {
		t.Fatalf("失败批次启动次数=%q，期望 3（首次 + 两次额外尝试）", got)
	}

	if err := os.WriteFile("ready", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	secondID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("异常结束后无法再次启动同一任务: %v", err)
	}
	waitForScanStatus(t, st, secondID, "done")
	waitForRunnerIdle(t, runner)
	results, err := st.ResultsByScan(secondID)
	if err != nil || len(results) != 1 || results[0].Port != 443 {
		t.Fatalf("第二次启动结果不完整: %+v err=%v", results, err)
	}
	if got := strings.TrimSpace(readTestFile(t, "count")); got != "4" {
		t.Fatalf("第二次启动后累计启动次数=%q，期望 4", got)
	}
}

// TestBatchRetryExhaustedKeepsStderr 验证瞬态非零退出会做最多两次额外尝试，
// 且最终失败的 stderr 在有界缓冲下仍能回传给执行记录。
func TestBatchRetryExhaustedKeepsStderr(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, retryThenReadyScript)
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForScanStatus(t, st, scanID, "failed")
	waitForRunnerIdle(t, runner)

	if got := strings.TrimSpace(readTestFile(t, "count")); got != "3" {
		t.Fatalf("重试次数=%q，期望最多两次额外尝试（共 3 次）", got)
	}
	scan, _ := st.Scan(scanID)
	if scan == nil {
		t.Fatal("扫描记录不存在")
	}
	if !strings.Contains(scan.Err, "temporary failure while starting scan") {
		t.Fatalf("失败详情未保留 stderr: %q", scan.Err)
	}
	if !strings.Contains(scan.Err, "共 3 次尝试") {
		t.Fatalf("失败详情未说明重试次数: %q", scan.Err)
	}
	// 失败语义保持：重试耗尽后仍为 failed，且不生成告警。
	if scan.Status != "failed" {
		t.Fatalf("状态=%q，期望 failed", scan.Status)
	}
	alerts, err := st.Alerts(10)
	if err != nil || len(alerts) != 0 {
		t.Fatalf("失败执行不应生成告警: %+v err=%v", alerts, err)
	}
}

// synFallbackScript：SYN 模式下打印权限错误并非零退出，CONNECT 模式下输出结果；
// types.log 记录每次尝试实际使用的 -scan-type 值。
const synFallbackScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
type=''; out=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -scan-type) type="$2"; shift 2;;
    -o) out="$2"; shift 2;;
    *) shift;;
  esac
done
printf '%s\n' "$type" >> types.log
if [ "$type" = "s" ]; then
  echo 'syn scan is not possible (could not setup ip4:tcp: operation not permitted)' >&2
  exit 1
fi
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
`

// TestSynPermissionFailureFallsBackToConnect 验证 stderr 明确属于 SYN/raw socket 权限问题时，
// 后续尝试（以及本次执行后续批次）降级为 naabu CONNECT（-scan-type c）并成功。
func TestSynPermissionFailureFallsBackToConnect(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, synFallbackScript)
	if err := st.SaveSettings(map[string]string{"naabu_scan_type": "s"}); err != nil {
		t.Fatal(err)
	}
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForScanStatus(t, st, scanID, "done")
	waitForRunnerIdle(t, runner)

	if got := strings.TrimSpace(readTestFile(t, "types.log")); got != "s\nc" {
		t.Fatalf("扫描方式序列=%q，期望先 SYN 后降级 CONNECT", got)
	}
	results, err := st.ResultsByScan(scanID)
	if err != nil || len(results) != 1 || results[0].Port != 443 {
		t.Fatalf("降级后结果不完整: %+v err=%v", results, err)
	}
	if !strings.Contains(scanEventMessages(t, st, scanID), "降级为 CONNECT") {
		t.Fatal("未记录 SYN 降级为 CONNECT 的事件")
	}
	// 降级只是本次执行的内存标记，不应改写系统设置。
	if got := st.Setting("naabu_scan_type"); got != "s" {
		t.Fatalf("降级不应改写 naabu_scan_type 设置，当前=%q", got)
	}
}

// pausedChildExitScript：第一批（非 192.0.2.21）长时间 sleep，第二批短暂执行后完成并留下标记。
const pausedChildExitScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -list) list="$2"; shift 2;;
    -o) out="$2"; shift 2;;
    *) shift;;
  esac
done
: > "$out"
first=$(head -n 1 "$list")
if [ "$first" = "192.0.2.21" ]; then
  printf '%s:22\n' "$first" > "$out"
  printf '%s:22\n' "$first"
  touch second_batch_done
  sleep 0.5
  exit 0
fi
printf '%s:443\n' "$first" > "$out"
printf '%s:443\n' "$first"
touch first_batch_started
sleep 30
`

// TestPausedChildrenExitDoesNotBlockRemainingBatches 验证暂停期间活动进程全部异常退出后，
// 待处理批次不会被永久挂起：执行自动解除暂停继续剩余批次，运行标志最终释放。
func TestPausedChildrenExitDoesNotBlockRemainingBatches(t *testing.T) {
	runner, st, scanID, pid := startPausedTwoBatchScan(t)
	// 模拟子进程在暂停期间被外部杀死（SIGSTOP 中的进程无法再 SIGCONT）。
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}

	waitForRunnerIdleWithin(t, runner, 10*time.Second)
	waitForFile(t, "second_batch_done")
	scan, _ := st.Scan(scanID)
	if scan == nil {
		t.Fatal("扫描记录不存在")
	}
	if scan.Status != "partial" && scan.Status != "failed" {
		t.Fatalf("进程异常退出后状态=%q，期望 partial/failed（不应停留在 paused）", scan.Status)
	}
	results, err := st.ResultsByScan(scanID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, result := range results {
		if result.IP == "192.0.2.21" && result.Port == 22 {
			found = true
		}
	}
	if !found {
		t.Fatalf("暂停进程退出后待处理批次未继续执行: %+v", results)
	}
	if !strings.Contains(scanEventMessages(t, st, scanID), "自动解除暂停") {
		t.Fatal("未记录暂停自动解除事件")
	}
}

// TestStopConvergesAfterPausedProcessExit 验证暂停期间进程全部退出后，Stop 仍能在有界时间内收敛。
func TestStopConvergesAfterPausedProcessExit(t *testing.T) {
	runner, st, scanID, pid := startPausedTwoBatchScan(t)
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := runner.Stop(scanID); err != nil {
		t.Fatalf("暂停进程退出后 Stop 未收敛: %v", err)
	}
	waitForScanStatus(t, st, scanID, "stopped")
	waitForRunnerIdleWithin(t, runner, 10*time.Second)
}

// startPausedTwoBatchScan 启动一个 21 目标（2 批、并发度 1）的执行并暂停，
// 返回首个批次的 naabu 进程组 ID，供暂停期子进程异常退出的两个场景复用。
func startPausedTwoBatchScan(t *testing.T) (*Runner, *store.Store, int64, int) {
	t.Helper()
	runner, st, _ := newControlledRunner(t, pausedChildExitScript)
	// 容量估算按 naabu 契约把 -retries 0 视为工具默认 3 轮，21 个目标约需 69s；
	// 这里显式放宽任务超时，本用例关注的是暂停/退出收敛而非容量边界。
	if err := st.SaveSettings(map[string]string{"scan_concurrency": "1", "scan_timeout_min": "10"}); err != nil {
		t.Fatal(err)
	}
	ips := make([]string, 0, 21)
	for i := 1; i <= 21; i++ {
		ips = append(ips, fmt.Sprintf("192.0.2.%d", i))
	}
	taskID, err := st.CreateScanTask(store.ScanTask{Name: "暂停进程退出测试", Mode: "top", TargetType: "manual", IPs: strings.Join(ips, "\n")})
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForFile(t, "first_batch_started")
	if err := runner.Pause(scanID); err != nil {
		t.Fatal(err)
	}
	waitForScanStatus(t, st, scanID, "paused")

	pid := 0
	runner.mu.Lock()
	for cmd := range runner.active.cmds {
		if cmd.Process != nil {
			pid = cmd.Process.Pid
			break
		}
	}
	runner.mu.Unlock()
	if pid == 0 {
		t.Fatal("未捕获到暂停中的 naabu 进程")
	}
	return runner, st, scanID, pid
}

// stderrFloodScript：正常输出一条结果，同时向 stderr 写入大量文本用于验证有界缓冲。
const stderrFloodScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
i=1
while [ "$i" -le 3000 ]; do
  echo "stderr-warning-line-$i" >&2
  i=$((i+1))
done
exit 0
`

// TestRunBatchReturnsBoundedStderr 验证 runBatch 的 stderr 在 defer 中可靠回传（命名返回值），
// 且缓冲有上限、保留的是末尾内容。
func TestRunBatchReturnsBoundedStderr(t *testing.T) {
	runner, st, _ := newControlledRunner(t, stderrFloodScript)
	scanID, err := st.CreateScan(1, "stderr 保留测试", "top")
	if err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.running = true
	runner.scanID = scanID
	runner.active = newExecutionControl()
	runner.mu.Unlock()
	t.Cleanup(func() { runner.setRunning(false) })

	settings := runner.naabuSettings()
	prog := newScanProgress()
	args := settings.args("targets.txt", "stderr.out", "top", "")
	outcome := runner.runBatch(scanID, settings, args, "stderr.out", prog)
	if outcome.runErr != nil {
		t.Fatalf("stderr 输出不应导致进程失败: %v", outcome.runErr)
	}
	if outcome.stderr == "" {
		t.Fatal("runBatch 未返回 stderr（defer 回填丢失）")
	}
	if !strings.Contains(outcome.stderr, "stderr-warning-line-3000") {
		t.Fatalf("stderr 未保留末尾内容: %q", outcome.stderr[maxInt(0, len(outcome.stderr)-200):])
	}
	if len(outcome.stderr) > stderrLimit {
		t.Fatalf("stderr 长度=%d，超过上限 %d", len(outcome.stderr), stderrLimit)
	}
}

// lingeringPipeBound 是“遗留子进程仍持住 stdout/stderr 管道”场景的合理返回上界：
// WaitDelay 与 stdout 收尾宽限之后必须收敛，这里再留足 CI 余量。
const lingeringPipeBound = pipeWaitDelay + 6*time.Second

// lingeringStderrScript：写入结果与一条 stderr 提示后，后台 sleep 持有 stdout/stderr 管道，
// 父进程立即以 0 退出；用于验证 cmd.Wait 不会无限等待 stderr 复制协程 EOF。
const lingeringStderrScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
echo 'naabu: lingering stderr warning kept for diagnostics' >&2
sleep 30 &
printf '%s\n' "$$" > linger_stderr_parent.pid
printf '%s\n' "$!" >> linger_children.pid
exit 0
`

// lingeringStdoutScript：后台子进程只持有 stdout 管道（stderr 指向 /dev/null），
// 父进程退出后 stdout 读协程收不到 EOF，用于验证收尾宽限能让批次有界返回。
const lingeringStdoutScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:8443\n' > "$out"
printf '192.0.2.1:8443\n'
sleep 30 2>/dev/null &
printf '%s\n' "$!" >> linger_children.pid
exit 0
`

// versionLingerScript：-version 输出后立即退出，但遗留下子进程持住 stdout/stderr 管道。
const versionLingerScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then
  echo 'naabu v9.9.9-linger'
  sleep 30 &
  printf '%s\n' "$!" >> version_linger_children.pid
  exit 0
fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
`

// versionHangScript：未创建 version_ready 时 -version 自身长时间卡住，
// 用于验证自检超时能按进程组终止并释放 Runner 运行标志。
const versionHangScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then
  if [ ! -f version_ready ]; then
    touch version_started
    sleep 30
  fi
  echo 'naabu test'
  exit 0
fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
`

// TestRunBatchBoundedWhenChildHoldsStderr 验证：naabu 主进程正常退出，但其子进程继续持有 stderr 管道时，
// runBatch（cmd.Wait 需等待 stderr 复制协程 EOF）必须在有上界的 WaitDelay 内返回，
// 且所需 stderr 仍可从 8 KiB 尾部缓冲取回。
func TestRunBatchBoundedWhenChildHoldsStderr(t *testing.T) {
	runner, st, _ := newControlledRunner(t, lingeringStderrScript)
	t.Cleanup(func() { killRecordedPids(t, "linger_children.pid") })

	outcome, elapsed, scanID := runBatchDirect(t, runner, st, "linger_stderr.out")
	if elapsed > lingeringPipeBound {
		t.Fatalf("runBatch 耗时 %s，超过上界 %s（遗留子进程持住 stderr 导致 Wait 永久阻塞）", elapsed, lingeringPipeBound)
	}
	if outcome.runErr != nil {
		t.Fatalf("主进程正常退出时不应判为失败: %v（stderr=%q）", outcome.runErr, outcome.stderr)
	}
	if !outcome.drainClosed {
		t.Fatal("未标记输出管道被遗留子进程占用并强制关闭")
	}
	if !strings.Contains(outcome.stderr, "lingering stderr warning") {
		t.Fatalf("stderr 未保留（可能丢失了所需错误输出）: %q", outcome.stderr)
	}
	if len(outcome.stderr) > stderrLimit {
		t.Fatalf("stderr 长度=%d，超过上限 %d", len(outcome.stderr), stderrLimit)
	}
	if outcome.streamErr != nil {
		t.Fatalf("管道被强制关闭不应记为实时读取失败: %v", outcome.streamErr)
	}
	if outcome.groupUnreaped {
		t.Fatal("强制收尾后未能确认进程组收敛")
	}
	// 必须在 Cleanup 前确认遗留子进程已被主动终止（仅关闭管道不算收敛）。
	waitRecordedPidGone(t, "linger_children.pid")
	results, err := st.ResultsByScan(scanID)
	if err != nil || len(results) == 0 {
		t.Fatalf("管道收尾后结果未入库: %+v err=%v", results, err)
	}
}

// TestRunBatchBoundedWhenChildHoldsStdout 验证子进程只持住 stdout 时的同类场景同样有界返回。
func TestRunBatchBoundedWhenChildHoldsStdout(t *testing.T) {
	runner, st, _ := newControlledRunner(t, lingeringStdoutScript)
	t.Cleanup(func() { killRecordedPids(t, "linger_children.pid") })

	outcome, elapsed, scanID := runBatchDirect(t, runner, st, "linger_stdout.out")
	if elapsed > lingeringPipeBound {
		t.Fatalf("runBatch 耗时 %s，超过上界 %s（遗留子进程持住 stdout 导致永久阻塞）", elapsed, lingeringPipeBound)
	}
	if outcome.runErr != nil {
		t.Fatalf("主进程正常退出时不应判为失败: %v", outcome.runErr)
	}
	if outcome.streamErr != nil {
		t.Fatalf("管道收尾不应记为实时读取失败: %v", outcome.streamErr)
	}
	if !outcome.drainClosed {
		t.Fatal("主进程退出后仍有子进程持住输出时应标记输出不完整（drainClosed）")
	}
	if outcome.groupUnreaped {
		t.Fatal("强制收尾后未能确认进程组收敛")
	}
	waitRecordedPidGone(t, "linger_children.pid")
	results, err := st.ResultsByScan(scanID)
	if err != nil || len(results) == 0 || results[0].Port != 8443 {
		t.Fatalf("stdout 管道收尾后结果未入库: %+v err=%v", results, err)
	}
}

// TestCheckNaabuBoundedWhenChildHoldsPipes 验证版本自检主进程退出、遗留子进程持住 stdout/stderr 时，
// CheckNaabu（cmd.Run）依靠 WaitDelay 在有界时间返回，并保留版本文本。
func TestCheckNaabuBoundedWhenChildHoldsPipes(t *testing.T) {
	runner, _, _ := newControlledRunner(t, versionLingerScript)
	t.Cleanup(func() { killRecordedPids(t, "version_linger_children.pid") })

	start := time.Now()
	_, version, err := runner.CheckNaabu()
	elapsed := time.Since(start)
	if elapsed > lingeringPipeBound {
		t.Fatalf("CheckNaabu 耗时 %s，超过上界 %s（遗留子进程持住输出管道）", elapsed, lingeringPipeBound)
	}
	if err != nil {
		t.Fatalf("版本命令本身已成功退出，不应判为不可用: %v", err)
	}
	if !strings.Contains(version, "v9.9.9") {
		t.Fatalf("版本自检输出未保留: %q", version)
	}
	// 版本命令退出后的遗留子进程也必须被主动终止并确认收敛。
	waitRecordedPidGone(t, "version_linger_children.pid")
}

// TestCheckNaabuTimeoutReleasesRunner 验证版本自检自身卡住时：超时按进程组终止、
// CheckNaabu 有界返回、StartTask 释放运行标志，随后同一任务可再次启动。
func TestCheckNaabuTimeoutReleasesRunner(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, versionHangScript)
	original := naabuVersionTimeout
	naabuVersionTimeout = 300 * time.Millisecond
	t.Cleanup(func() { naabuVersionTimeout = original })

	start := time.Now()
	if _, err := runner.StartTask(taskID); err == nil {
		t.Fatal("自检卡住时 StartTask 应返回错误")
	} else if !strings.Contains(err.Error(), "版本自检") {
		t.Fatalf("自检超时错误信息不符: %v", err)
	}
	if elapsed := time.Since(start); elapsed > lingeringPipeBound {
		t.Fatalf("自检超时后 StartTask 耗时 %s，超过上界 %s", elapsed, lingeringPipeBound)
	}
	if runner.IsRunning() {
		t.Fatal("自检超时后运行标志未释放，同一任务无法再次启动")
	}

	if err := os.WriteFile("version_ready", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 第二次自检是正常路径，不再受“卡住需在 300ms 内终止”的约束：
	// -race 插桩下 fork/exec 一个刚写入的脚本可能接近或超过 300ms，
	// 继续用紧预算会把“运行标志已释放”的正确行为误判为失败。
	naabuVersionTimeout = original
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("自检超时结束后无法再次启动同一任务: %v", err)
	}
	waitForScanStatus(t, st, scanID, "done")
	waitForRunnerIdle(t, runner)
	results, err := st.ResultsByScan(scanID)
	if err != nil || len(results) != 1 || results[0].Port != 443 {
		t.Fatalf("再次启动结果不完整: %+v err=%v", results, err)
	}
}

// versionExitLingerScript：首次 -version 输出诊断后 exit 1，同时后台子进程持住 stdout/stderr；
// 存在 version_exit_ready 时 -version 正常退出，便于验证 Runner 释放后能再次启动。
const versionExitLingerScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then
  if [ ! -f version_exit_ready ]; then
    echo 'naabu: fatal error while probing version'
    echo 'naabu: failed to initialize scan engine' >&2
    sleep 30 &
    printf '%s\n' "$!" >> version_exit_linger_children.pid
    exit 1
  fi
  echo 'naabu test'
  exit 0
fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
`

// TestCheckNaabuExitErrorStillCleansProcessGroup 覆盖漏分支：版本父进程 exit 1 且后台子进程
// 继续持住 stdout/stderr 时，Cmd.Wait 优先返回 *exec.ExitError（而不是 exec.ErrWaitDelay），
// CheckNaabu 仍必须在返回前终止该进程组并确认收敛：有界返回、保留诊断、Cleanup 前 PID 已消失，
// 且 StartTask 释放 Runner 后同一任务可以再次启动。
func TestCheckNaabuExitErrorStillCleansProcessGroup(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, versionExitLingerScript)
	t.Cleanup(func() { killRecordedPids(t, "version_exit_linger_children.pid") })

	start := time.Now()
	_, version, err := runner.CheckNaabu()
	elapsed := time.Since(start)
	if elapsed > lingeringPipeBound {
		t.Fatalf("CheckNaabu 耗时 %s，超过上界 %s（exit 1 + 孙进程持管道导致阻塞）", elapsed, lingeringPipeBound)
	}
	if err == nil {
		t.Fatal("版本命令 exit 1 时应判定不可用")
	}
	if !strings.Contains(err.Error(), "版本自检") {
		t.Fatalf("错误信息未说明版本自检失败: %v", err)
	}
	// 诊断输出必须保留（有界尾部缓冲），便于定位异常二进制。
	if !strings.Contains(version, "fatal error while probing version") || !strings.Contains(version, "failed to initialize scan engine") {
		t.Fatalf("版本自检诊断输出丢失: %q（错误=%v）", version, err)
	}
	if !strings.Contains(err.Error(), "failed to initialize scan engine") {
		t.Fatalf("错误信息未携带诊断输出: %v", err)
	}
	// 必须在 Cleanup 之前确认遗留子进程已被主动终止。
	waitRecordedPidGone(t, "version_exit_linger_children.pid")

	// StartTask 的自检同样失败，但必须释放运行标志（遗留进程不得拖住 Runner）。
	if _, err := runner.StartTask(taskID); err == nil {
		t.Fatal("版本命令 exit 1 时 StartTask 应返回错误")
	}
	if runner.IsRunning() {
		t.Fatal("自检失败后运行标志未释放，同一任务无法再次启动")
	}
	waitRecordedPidGone(t, "version_exit_linger_children.pid")

	if err := os.WriteFile("version_exit_ready", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("自检失败收敛后无法再次启动同一任务: %v", err)
	}
	waitForScanStatus(t, st, scanID, "done")
	waitForRunnerIdle(t, runner)
	results, err := st.ResultsByScan(scanID)
	if err != nil || len(results) != 1 || results[0].Port != 443 {
		t.Fatalf("再次启动结果不完整: %+v err=%v", results, err)
	}
}

// TestStartTaskAgainAfterLingeringOutputChild 端到端验证：批次遗留子进程持住输出管道时，
// 执行仍有界收敛（partial，不能 done）、不触发完整结果告警，运行标志释放后同一任务可再次启动。
func TestStartTaskAgainAfterLingeringOutputChild(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, lingeringStderrScript)
	t.Cleanup(func() { killRecordedPids(t, "linger_children.pid") })

	for round := 1; round <= 2; round++ {
		start := time.Now()
		scanID, err := runner.StartTask(taskID)
		if err != nil {
			t.Fatalf("第 %d 次启动失败: %v", round, err)
		}
		waitForRunnerIdleWithin(t, runner, lingeringPipeBound)
		if elapsed := time.Since(start); elapsed > lingeringPipeBound {
			t.Fatalf("第 %d 次执行耗时 %s，超过上界 %s", round, elapsed, lingeringPipeBound)
		}
		scan, err := st.Scan(scanID)
		if err != nil || scan == nil {
			t.Fatalf("第 %d 次执行记录缺失: %+v err=%v", round, scan, err)
		}
		if scan.Status != "partial" {
			t.Fatalf("第 %d 次执行状态=%q，期望 partial（无法证明实时输出完整时不得判为 done）: %+v", round, scan.Status, scan)
		}
		if !strings.Contains(scan.Err, "强制关闭管道") {
			t.Fatalf("第 %d 次执行未说明输出管道被强制关闭: %q", round, scan.Err)
		}
		// 输出完整无法证明：终态 partial 的同时，本批目标必须计入异常目标（不能显示为全部正常）。
		if scan.FailedTargets != 1 {
			t.Fatalf("第 %d 次执行异常目标数=%d，期望 1（drainClosed 表示本批输出不完整，应计入 FailedTargets）: %+v", round, scan.FailedTargets, scan)
		}
		if scan.ProcessedTargets != 1 {
			t.Fatalf("第 %d 次执行已处理目标数=%d，期望 1: %+v", round, scan.ProcessedTargets, scan)
		}
		alerts, err := st.Alerts(10)
		if err != nil || len(alerts) != 0 {
			t.Fatalf("第 %d 次执行不完整，不应生成端口风险告警: %+v err=%v", round, alerts, err)
		}
		results, err := st.ResultsByScan(scanID)
		if err != nil || len(results) != 1 || results[0].Port != 443 {
			t.Fatalf("第 %d 次执行结果不完整: %+v err=%v", round, results, err)
		}
		waitRecordedPidGone(t, "linger_children.pid")
	}
}

// timeoutLingerScript：首次运行输出结果后启动后台子进程持住管道，并自身长时间不退出；
// 存在 marker 后的后续执行则立即返回，便于验证超时收敛后能再次启动。
const timeoutLingerScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
if [ ! -f timeout_marker ]; then
  sleep 30 &
  printf '%s\n' "$!" >> timeout_linger_children.pid
  touch timeout_marker
  touch timeout_batch_running
  sleep 30
fi
exit 0
`

// TestScanTimeoutReleasesRunnerWithLingeringChild 验证有效扫描超时与遗留子进程同时发生时，
// 批次仍在有界时间内收敛（进程组被杀 + WaitDelay 收尾），clearProcess 与运行锁及时释放，
// 随后同一任务可再次启动。
func TestScanTimeoutReleasesRunnerWithLingeringChild(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, timeoutLingerScript)
	t.Cleanup(func() { killRecordedPids(t, "timeout_linger_children.pid") })

	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForFile(t, "timeout_batch_running")
	runner.mu.Lock()
	runner.active.deadline = time.Now()
	runner.active.notify()
	runner.mu.Unlock()

	waitForRunnerIdleWithin(t, runner, lingeringPipeBound)
	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
	}
	if scan.Status == "done" {
		t.Fatalf("达到有效扫描超时的执行不应标记为 done: %+v", scan)
	}
	runner.mu.Lock()
	empty := runner.active == nil || len(runner.active.cmds) == 0
	runner.mu.Unlock()
	if !empty {
		t.Fatal("超时收敛后活跃进程表未清空（clearProcess 未释放）")
	}

	secondID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("超时收敛后无法再次启动同一任务: %v", err)
	}
	waitForScanStatus(t, st, secondID, "done")
	waitForRunnerIdle(t, runner)
}

// runBatchDirect 在受控执行状态下直接调用 runBatch（不经过 StartTask 的其他分支），
// 返回批次结果、耗时与执行记录 ID。
func runBatchDirect(t *testing.T, runner *Runner, st *store.Store, outFile string) (batchOutcome, time.Duration, int64) {
	t.Helper()
	scanID, err := st.CreateScan(1, "管道遗留子进程测试", "top")
	if err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.running = true
	runner.scanID = scanID
	runner.active = newExecutionControl()
	runner.mu.Unlock()
	t.Cleanup(func() { runner.setRunning(false) })

	settings := runner.naabuSettings()
	prog := newScanProgress()
	args := settings.args("targets.txt", outFile, "top", "")
	start := time.Now()
	outcome := runner.runBatch(scanID, settings, args, outFile, prog)
	return outcome, time.Since(start), scanID
}

// killRecordedPids 清理脚本后台遗留的 sleep 进程（脚本退出后它们仍在持住管道）。
func killRecordedPids(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, field := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 0 {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// waitRecordedPidGone 断言脚本记录的后台子进程已全部终止（用于确认进程组已收敛）。
// 必须在 t.Cleanup 之前调用：清理钩子会兜底杀进程，掩盖未收敛问题。
func waitRecordedPidGone(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取遗留子进程 pid 文件 %s 失败: %v", path, err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		t.Fatalf("遗留子进程 pid 文件 %s 为空", path)
	}
	pids := make([]int, 0, len(fields))
	for _, field := range fields {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 0 {
			t.Fatalf("遗留子进程 pid 非法: %q", field)
		}
		pids = append(pids, pid)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		alive := 0
		for _, pid := range pids {
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				alive++
			}
		}
		if alive == 0 {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("遗留子进程 %v 中仍有 %d 个在断言时存活（强制收尾后进程组未收敛）", pids, alive)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestStreamReadErrorOnlyIgnoresClosedPipe 验证只忽略能确认由主动关闭管道造成的 os.ErrClosed，
// 真实读取错误必须保留（否则会把不完整的实时输出误判为完整）。
func TestStreamReadErrorOnlyIgnoresClosedPipe(t *testing.T) {
	if err := streamReadError(nil); err != nil {
		t.Fatalf("nil 错误应返回 nil，实际=%v", err)
	}
	closed := &os.PathError{Op: "read", Path: "|0", Err: os.ErrClosed}
	if err := streamReadError(closed); err != nil {
		t.Fatalf("主动关闭管道造成的 os.ErrClosed 应被忽略，实际=%v", err)
	}
	realErr := fmt.Errorf("read |0: input/output error")
	if err := streamReadError(realErr); !errors.Is(err, realErr) {
		t.Fatalf("真实读取错误不得被抹除，实际=%v", err)
	}
	ioErr := &os.PathError{Op: "read", Path: "|0", Err: syscall.EIO}
	if err := streamReadError(ioErr); !errors.Is(err, ioErr) {
		t.Fatalf("EIO 读取错误不得被抹除，实际=%v", err)
	}
}

// TestPauseAfterHealPersistsLatestState 验证暂停自愈（内存已解除暂停、落库尚未完成）与用户新 Pause
// 交错时，迟到的自愈写入不会覆盖用户状态：最终数据库状态必须与内存一致（paused）。
func TestPauseAfterHealPersistsLatestState(t *testing.T) {
	runner, st, _ := newControlledRunner(t, controlledScript)
	scanID, err := st.CreateScan(1, "暂停自愈落库竞态", "top")
	if err != nil {
		t.Fatal(err)
	}
	// 自愈要求“暂停且无活动进程”，用户 Pause 要求“有活动进程”：用真实进程模拟新批次登记。
	helper := exec.Command("sleep", "30")
	prepareProcess(helper)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = killProcess(helper)
		_ = helper.Wait()
	})

	runner.mu.Lock()
	runner.running = true
	runner.scanID = scanID
	runner.active = newExecutionControl()
	runner.active.paused = true
	runner.active.pauseStarted = time.Now()
	runner.active.deadline = time.Now().Add(time.Minute)
	runner.mu.Unlock()
	t.Cleanup(func() { runner.setRunning(false) })
	if err := st.SetScanActiveStatus(scanID, "paused"); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	scanStatusPersistHook = func(gotScanID int64, status string) {
		if gotScanID != scanID || status != "running" {
			return
		}
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	t.Cleanup(func() { scanStatusPersistHook = nil })

	healed := make(chan bool, 1)
	go func() { healed <- runner.healPausedAfterProcessExit(scanID) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("暂停自愈未进入状态落库阶段")
	}

	// 自愈内存转换已完成但落库被阻塞：此时新批次登记进程，用户点击暂停。
	runner.mu.Lock()
	runner.active.cmds[helper] = struct{}{}
	runner.mu.Unlock()
	paused := make(chan error, 1)
	go func() { paused <- runner.Pause(scanID) }()
	time.Sleep(200 * time.Millisecond)
	close(release)
	if !<-healed {
		t.Fatal("暂停自愈未生效")
	}
	if err := <-paused; err != nil {
		t.Fatalf("用户 Pause 失败: %v", err)
	}

	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
	}
	runner.mu.Lock()
	inMemoryPaused := runner.active != nil && runner.active.paused
	runner.mu.Unlock()
	if !inMemoryPaused {
		t.Fatal("内存状态应为暂停")
	}
	if scan.Status != "paused" {
		t.Fatalf("最终数据库状态=%q，期望 paused（自愈的迟到写入覆盖了用户新 Pause）", scan.Status)
	}
}

// deadlineRetryScript：第一次尝试瞬态失败并留下标记；之后尝试直接输出结果，attempts 记录启动次数。
const deadlineRetryScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
n=0
if [ -f attempts ]; then n=$(cat attempts); fi
n=$((n + 1))
printf '%s\n' "$n" > attempts
if [ "$n" -le 1 ]; then
  touch retry_first_attempt
  echo 'naabu: temporary failure while starting scan' >&2
  exit 1
fi
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
`

// TestRetryStopsAtDeadlineWithoutRestart 验证退避期间有效截止时间耗尽时，不再启动任何重试进程，
// 直接按超时收敛（状态非 done 且错误信息说明超时）。
func TestRetryStopsAtDeadlineWithoutRestart(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, deadlineRetryScript)
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForFile(t, "retry_first_attempt")
	// 在 400ms 重试退避期间把有效截止时间推到当前：重试必须被预算检查拦住。
	runner.mu.Lock()
	runner.active.deadline = time.Now()
	runner.active.notify()
	runner.mu.Unlock()

	waitForRunnerIdleWithin(t, runner, lingeringPipeBound)
	if got := strings.TrimSpace(readTestFile(t, "attempts")); got != "1" {
		t.Fatalf("预算耗尽后仍启动了重试：naabu 启动次数=%q，期望 1", got)
	}
	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
	}
	if scan.Status == "done" {
		t.Fatalf("预算耗尽不应判为 done: %+v", scan)
	}
	if !strings.Contains(scan.Err, "超时") {
		t.Fatalf("超时收敛未说明原因: %q", scan.Err)
	}
}

// fallbackPropagationScript：SYN 下报普通瞬态失败（非 SYN 权限错误），CONNECT 下成功；
// types.log 记录每次尝试的 -scan-type。
const fallbackPropagationScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
type=''; out=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -scan-type) type="$2"; shift 2;;
    -o) out="$2"; shift 2;;
    *) shift;;
  esac
done
printf '%s\n' "$type" >> types.log
if [ "$type" = "s" ]; then
  touch first_attempt
  echo 'naabu: temporary failure while starting scan' >&2
  exit 1
fi
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
`

// TestConcurrentConnectFallbackAppliesToRetry 验证：其他并发批次确认 SYN 权限不足后
// （全局 connectOnly 已置位），本批次的下一次尝试必须重新读取该标记并改用 CONNECT，
// 同时总尝试次数仍不超过三次。
func TestConcurrentConnectFallbackAppliesToRetry(t *testing.T) {
	runner, st, _ := newControlledRunner(t, fallbackPropagationScript)
	if err := st.SaveSettings(map[string]string{"naabu_scan_type": "s"}); err != nil {
		t.Fatal(err)
	}
	scanID, err := st.CreateScan(1, "并发降级传播测试", "top")
	if err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	runner.running = true
	runner.scanID = scanID
	runner.active = newExecutionControl()
	runner.mu.Unlock()
	t.Cleanup(func() { runner.setRunning(false) })

	settings := runner.naabuSettings()
	if settings.ScanType != "s" {
		t.Fatalf("测试前置条件错误：扫描方式=%q，期望 s", settings.ScanType)
	}
	prog := newScanProgress()
	// 模拟另一个并发批次在本批次首次失败后确认了 SYN 权限不足。
	go func() {
		for i := 0; i < 1000; i++ {
			if _, err := os.Stat("first_attempt"); err == nil {
				prog.markConnectOnly()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	outcome := runner.runBatchWithRetry(scanID, settings, "top", "", "targets.txt", "fallback.out", 1, prog)
	if outcome.runErr != nil {
		t.Fatalf("读取并发降级标记后重试应成功: %v（stderr=%q）", outcome.runErr, outcome.stderr)
	}
	if outcome.attempts != 2 {
		t.Fatalf("尝试次数=%d，期望 2（首次 SYN + 降级后 CONNECT）", outcome.attempts)
	}
	if got := strings.TrimSpace(readTestFile(t, "types.log")); got != "s\nc" {
		t.Fatalf("扫描方式序列=%q，期望并发批次降级后重试改用 CONNECT", got)
	}
	results, err := st.ResultsByScan(scanID)
	if err != nil || len(results) != 1 || results[0].Port != 443 {
		t.Fatalf("降级后结果不完整: %+v err=%v", results, err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	return string(data)
}

func scanEventMessages(t *testing.T, st *store.Store, scanID int64) string {
	t.Helper()
	events, err := st.ScanEvents(scanID, 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, event := range events {
		b.WriteString(event.Message)
		b.WriteByte('\n')
	}
	return b.String()
}

func waitForRunnerIdleWithin(t *testing.T, runner *Runner, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if !runner.IsRunning() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("扫描运行锁未在限定时间内释放（待处理批次可能永久等待）")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
