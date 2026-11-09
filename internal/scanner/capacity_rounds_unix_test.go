//go:build linux || darwin

package scanner

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 本文件覆盖“同一 Runner 同一任务的连续多轮执行”与异常路径的运行锁释放：
//   - 第 1 轮：瞬态非零退出 + 重试耗尽 → failed；
//   - 第 2 轮：运行中 Stop → stopped；
//   - 第 3 轮：健康执行 → done（每轮独立 scanID）；
//   - 每轮都断言运行锁在 10 秒内释放，并在三轮后断言 goroutine/FD/子 PID 无持续泄漏。
//
// 其余异常路径由既有用例覆盖，本文件保持引用关系便于回归时定位：
//   - 多批暂停超过旧 deadline 后恢复：TestPauseAcrossOldDeadlineResumesAllBatches（capacity_fake_unix_test.go）；
//   - 暂停中 Stop：TestStopConvergesAfterPausedProcessExit（retry_unix_test.go）；
//   - 遗留子进程持住 stdout/stderr 管道：TestRunBatchBoundedWhenChildHoldsStderr / Stdout（retry_unix_test.go）；
//   - 退避中 Stop：TestStopDuringRetryBackoffReleasesLock（本文件）。

// roundLifecycleScript：通过标记文件切换三种行为——重试耗尽失败、长时间 sleep（供 Stop）、健康输出。
const roundLifecycleScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu fake v1'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -list) list="$2"; shift 2;;
    *) shift;;
  esac
done
printf '%s\n' "$$" >> round_pids.log
if [ -f round_fail ]; then
  n=0
  if [ -f round_attempts ]; then n=$(cat round_attempts); fi
  n=$((n + 1))
  printf '%s\n' "$n" > round_attempts
  touch round_failed_attempt
  echo 'naabu: temporary failure while starting scan' >&2
  exit 1
fi
if [ -f round_slow ]; then
  touch round_slow_started
  sleep 30
fi
: > "$out"
while IFS= read -r ip; do
  [ -z "$ip" ] && continue
  printf '{"host":"%s","ip":"%s","port":443,"protocol":"tcp"}\n' "$ip" "$ip" >> "$out"
  printf '{"host":"%s","ip":"%s","port":443,"protocol":"tcp"}\n' "$ip" "$ip"
done < "$list"
`

// roundMetrics 是单轮执行的观测数据，全部通过 t.Log 输出，便于后续任务直接引用。
type roundMetrics struct {
	round     int
	scanID    int64
	status    string
	wall      time.Duration
	release   time.Duration
	runtime   runtimeSnapshot // 轮次结束、GC 后的稳态快照
	peak      runtimeSnapshot // 本轮运行期资源峰值（周期采样）
	samples   int
	dbBytes   int64
	childPIDs []int
}

// TestFakeNaabuThreeRoundsLockReleaseAndNoLeak 验证同一 Runner 同一任务连续三轮 StartTask：
// 每轮独立 scanID、异常路径运行锁 10 秒内释放、健康轮可成功，且三轮后无 goroutine/FD/PID 泄漏。
func TestFakeNaabuThreeRoundsLockReleaseAndNoLeak(t *testing.T) {
	h := newCapacityHarness(t, roundLifecycleScript, map[string]string{"scan_concurrency": "1"})
	ips := []string{"192.0.2.41", "192.0.2.42"}
	taskID := newManualTask(t, h.st, "top", ips)

	baseline := snapshotRuntime(t)
	baselineDB := tempDBSize(t)
	t.Logf("基线：%s；临时库 %s", baseline.String(), humanBytes(baselineDB))

	rounds := make([]roundMetrics, 0, 3)

	// 第 1 轮：瞬态故障 → 重试耗尽 → failed。
	if err := os.WriteFile("round_fail", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 每轮除结算后的稳态快照外，同时采样本轮运行期峰值。
	sampler := startPeakSampler(resourceSampleInterval)
	started := time.Now()
	firstID, err := h.runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("第 1 轮启动失败: %v", err)
	}
	first := h.measureRound(t, 1, firstID, started, "failed")
	firstSampled := sampler.stop()
	first.peak, first.samples = firstSampled.peak, firstSampled.samples
	if got := strings.TrimSpace(readTestFile(t, "round_attempts")); got != "3" {
		t.Fatalf("第 1 轮 naabu 启动次数=%q，期望 3（首次 + 两次额外尝试）", got)
	}
	rounds = append(rounds, first)

	// 第 2 轮：运行中 Stop → stopped。
	if err := os.Remove("round_fail"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("round_slow", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	sampler = startPeakSampler(resourceSampleInterval)
	started = time.Now()
	secondID, err := h.runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("第 1 轮异常收敛后第 2 轮无法启动: %v", err)
	}
	waitForFileWithin(t, "round_slow_started", 20*time.Second)
	if err := h.runner.Stop(secondID); err != nil {
		t.Fatalf("第 2 轮 Stop 失败: %v", err)
	}
	second := h.measureRound(t, 2, secondID, started, "stopped")
	secondSampled := sampler.stop()
	second.peak, second.samples = secondSampled.peak, secondSampled.samples
	rounds = append(rounds, second)

	// 第 3 轮：健康执行 → done，结果完整。
	if err := os.Remove("round_slow"); err != nil {
		t.Fatal(err)
	}
	sampler = startPeakSampler(resourceSampleInterval)
	started = time.Now()
	thirdID, err := h.runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("第 2 轮 Stop 收敛后第 3 轮无法启动: %v", err)
	}
	third := h.measureRound(t, 3, thirdID, started, "done")
	thirdSampled := sampler.stop()
	third.peak, third.samples = thirdSampled.peak, thirdSampled.samples
	rounds = append(rounds, third)

	results, err := h.st.ResultsByScan(thirdID)
	if err != nil || len(results) != len(ips) {
		t.Fatalf("第 3 轮结果=%+v err=%v，期望 %d 条", results, err, len(ips))
	}

	// 每轮 scanID 独立且递增，不允许复用。
	seen := map[int64]bool{}
	previousID := int64(0)
	for _, round := range rounds {
		if seen[round.scanID] {
			t.Fatalf("第 %d 轮复用了 scanID=%d", round.round, round.scanID)
		}
		if round.scanID <= previousID {
			t.Fatalf("scanID 未递增: 第 %d 轮=%d，上一轮=%d", round.round, round.scanID, previousID)
		}
		seen[round.scanID] = true
		previousID = round.scanID
	}

	// 三轮后：记录的子进程全部退出（进程组收敛），goroutine 与 FD 不持续增长。
	waitRecordedPidGone(t, "round_pids.log")

	// 逐轮校验：运行期峰值满足两条彼此独立的约束（总峰值绝对上限 + 相对基线增量上限）；
	// 轮次结束后（GC 稳态）的 goroutine/FD 也必须回到基线附近，证明没有持续累积。
	// 峰值断言必须先有足够的运行期样本，否则读数只反映启动瞬间。
	for _, round := range rounds {
		if round.samples < 2 {
			t.Fatalf("第 %d 轮只采到 %d 次样本：至少需要启动基线 + 一次运行期读数，峰值断言才能成立",
				round.round, round.samples)
		}
		heapDelta := heapAllocBudget.assertPeaks(t, round.peak.HeapAlloc, baseline.HeapAlloc)
		heapSysDelta := heapSysBudget.assertPeaks(t, round.peak.HeapSys, baseline.HeapSys)
		sysDelta := sysBudget.assertPeaks(t, round.peak.Sys, baseline.Sys)
		goroutineDelta := goroutineBudget.assertPeaks(t, u64(round.peak.Goroutines), u64(baseline.Goroutines))
		fdDelta := fdBudget.assertPeaks(t, u64(round.peak.FDs), u64(baseline.FDs))
		t.Logf("第 %d 轮运行期峰值（%d 次采样）：总峰值 %s；相对基线增量 +HeapAlloc=%s +HeapSys=%s +Sys=%s +goroutines=%d +fds=%d",
			round.round, round.samples, round.peak.String(),
			humanBytes(heapDelta), humanBytes(heapSysDelta), humanBytes(sysDelta), goroutineDelta, fdDelta)
		if round.runtime.Goroutines > baseline.Goroutines+4 {
			t.Fatalf("第 %d 轮结束后 goroutine 未回落：基线 %d，当前 %d", round.round, baseline.Goroutines, round.runtime.Goroutines)
		}
		if round.runtime.FDs > baseline.FDs+8 {
			t.Fatalf("第 %d 轮结束后文件描述符未回落：基线 %d，当前 %d", round.round, baseline.FDs, round.runtime.FDs)
		}
	}
	// 峰值不得随轮次递增：若资源随轮次堆积，后一轮峰值会明显高于前一轮。
	for i := 1; i < len(rounds); i++ {
		previous, current := rounds[i-1], rounds[i]
		if current.peak.Goroutines > previous.peak.Goroutines+4 {
			t.Fatalf("第 %d 轮 goroutine 峰值 %d 高于第 %d 轮 %d：资源随轮次持续增长",
				current.round, current.peak.Goroutines, previous.round, previous.peak.Goroutines)
		}
		if current.peak.FDs > previous.peak.FDs+8 {
			t.Fatalf("第 %d 轮 FD 峰值 %d 高于第 %d 轮 %d：资源随轮次持续增长",
				current.round, current.peak.FDs, previous.round, previous.peak.FDs)
		}
	}

	final := snapshotRuntime(t)
	if baseline.Goroutines > 0 && final.Goroutines > baseline.Goroutines+4 {
		t.Fatalf("三轮后 goroutine 持续泄漏：基线 %d，当前 %d", baseline.Goroutines, final.Goroutines)
	}
	if baseline.FDs > 0 && final.FDs > baseline.FDs+8 {
		t.Fatalf("三轮后文件描述符持续泄漏：基线 %d，当前 %d", baseline.FDs, final.FDs)
	}
	t.Logf("三轮后：%s；临时库 %s（基线 %s）", final.String(), humanBytes(tempDBSize(t)), humanBytes(baselineDB))
	h.assertOfflineOnly(t, true)
}

// measureRound 等待运行锁释放（异常路径 10 秒上界），并采集单轮指标与终态。
func (h *capacityHarness) measureRound(t *testing.T, round int, scanID int64, started time.Time, wantStatus string) roundMetrics {
	t.Helper()
	// 所有异常路径（失败/重试耗尽/Stop）必须在 10 秒内释放运行锁。
	waitForRunnerIdleWithin(t, h.runner, 10*time.Second)
	release := time.Since(started)
	if h.runner.IsRunning() || h.runner.CurrentScanID() != 0 {
		t.Fatalf("第 %d 轮运行锁未完全释放: running=%v scanID=%d", round, h.runner.IsRunning(), h.runner.CurrentScanID())
	}
	scan, err := h.st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("第 %d 轮执行记录缺失: %+v err=%v", round, scan, err)
	}
	if scan.Status != wantStatus {
		t.Fatalf("第 %d 轮终态=%q，期望 %q: %+v", round, scan.Status, wantStatus, scan)
	}
	metrics := roundMetrics{
		round:     round,
		scanID:    scanID,
		status:    scan.Status,
		wall:      release,
		release:   release,
		runtime:   snapshotRuntime(t),
		dbBytes:   tempDBSize(t),
		childPIDs: recordedPids(t, "round_pids.log"),
	}
	t.Logf("第 %d 轮：scanID=%d 终态=%s wall=%s 释放运行锁=%s 子PID=%v %s 临时库=%s",
		round, scanID, scan.Status, metrics.wall.Round(time.Millisecond), metrics.release.Round(time.Millisecond),
		metrics.childPIDs, metrics.runtime.String(), humanBytes(metrics.dbBytes))
	return metrics
}

// recordedPids 读取 fake 记录的 naabu 子进程 PID 列表；文件不存在时返回空。
func recordedPids(t *testing.T, path string) []int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(data))
	pids := make([]int, 0, len(fields))
	for _, field := range fields {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 0 {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

// backoffStopScript：首次尝试记录标记后瞬态失败；若退避结束后仍被再次启动则留下 second_attempt 标记。
const backoffStopScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu fake v1'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    *) shift;;
  esac
done
printf '%s\n' "$$" >> backoff_pids.log
n=0
if [ -f backoff_attempts ]; then n=$(cat backoff_attempts); fi
n=$((n + 1))
printf '%s\n' "$n" > backoff_attempts
if [ "$n" -le 1 ]; then
  touch backoff_first_attempt
  echo 'naabu: temporary failure while starting scan' >&2
  exit 1
fi
touch backoff_second_attempt
sleep 30
`

// TestStopDuringRetryBackoffReleasesLock 验证退避中 Stop：不会再启动任何重试进程，
// 批次与运行锁在有界时间内收敛（≤ 10 秒），终态为 stopped。
func TestStopDuringRetryBackoffReleasesLock(t *testing.T) {
	h := newCapacityHarness(t, backoffStopScript, map[string]string{"scan_concurrency": "1"})
	taskID := newManualTask(t, h.st, "top", []string{"192.0.2.51"})

	baseline := snapshotRuntime(t)
	started := time.Now()
	scanID, err := h.runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	// 首次尝试在退出前落标记，随后进入 400ms 退避；在此窗口内终止。
	waitForFileWithin(t, "backoff_first_attempt", 20*time.Second)
	// 首轮进程可能刚好在 Stop 前退出并被回收（Darwin 对只剩僵尸/空进程组的 kill 返回 EPERM，
	// 同时主 PID 的 Getpgid 报 ESRCH）。生产侧只按组级探活（kill(-pgid, 0)）拿到 ESRCH
	// 才忽略这种无害 EPERM，因此这里直接要求 Stop 返回 nil：
	// 若真实权限错误被吞掉或被误上报，用例必须失败。
	if err := h.runner.Stop(scanID); err != nil {
		t.Fatalf("退避期间 Stop 失败（若为已回收进程组的无害 EPERM，说明生产进程组探活判定失效）: %v", err)
	}
	waitForRunnerIdleWithin(t, h.runner, 10*time.Second)
	release := time.Since(started)
	if h.runner.IsRunning() {
		t.Fatal("退避中 Stop 后运行锁未释放")
	}
	scan, err := h.st.Scan(scanID)
	if err != nil || scan == nil || scan.Status != "stopped" {
		t.Fatalf("退避中 Stop 后终态异常: %+v err=%v", scan, err)
	}
	// 等待远超退避窗口，确认没有第二次尝试被启动。
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat("backoff_second_attempt"); !os.IsNotExist(err) {
		t.Fatal("退避中 Stop 后仍启动了重试进程")
	}
	if got := strings.TrimSpace(readTestFile(t, "backoff_attempts")); got != "1" {
		t.Fatalf("naabu 启动次数=%q，期望 1（退避中终止不得再启动）", got)
	}
	waitRecordedPidGone(t, "backoff_pids.log")
	t.Logf("退避中 Stop：wall=%s 释放运行锁=%s；基线 %s；当前 %s",
		release.Round(time.Millisecond), release.Round(time.Millisecond), baseline.String(), snapshotRuntime(t).String())
	h.assertOfflineOnly(t, true)
}
