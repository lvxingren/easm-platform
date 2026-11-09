//go:build linux || darwin

package scanner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"easm-platform/internal/store"
)

// wakeupScript 为每批打上 tag：（1）标记启动并记录 PID；（2）写结果到 -o 与 stdout；
// （3）标记结果就绪；（4）短暂存活，让测试有时间在暂停窗口中从外部杀死其中一个批次。
const wakeupScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -list) list="$2"; shift 2;;
    *) shift;;
  esac
done
tag=0
case "$list" in
  *batch_0001_targets.txt) tag=1;;
  *batch_0002_targets.txt) tag=2;;
  *batch_0003_targets.txt) tag=3;;
  *batch_0004_targets.txt) tag=4;;
esac
if [ "$tag" != "0" ]; then
  touch "batch_${tag}_started"
  printf '%s\n' "$$" > "batch_${tag}.pid"
fi
: > "$out"
while IFS= read -r ip; do
  [ -z "$ip" ] && continue
  printf '%s:443\n' "$ip" >> "$out"
  printf '%s:443\n' "$ip"
done < "$list"
if [ "$tag" != "0" ]; then touch "batch_${tag}_results"; fi
sleep 0.3
`

// TestPausedResumeWakeupIsDeliveredWithoutPolling 用真实 SIGSTOP/SIGCONT 进程做确定性验证：
//   - 暂停期间其中一个批次被外部 SIGKILL（该 worker 结束并要在下一批前等待暂停解除）；
//   - 另一个批次仍在 SIGSTOP 中，因此暂停不会被“进程全部退出”自愈；
//   - 等待者拿到的是“状态 + 代际通道”同锁快照，测试在快照之后立即发起真实 Resume，
//     它关闭的正是等待者持有的通道，因此下一批必须远早于 300ms 巡检间隔就被启动。
func TestPausedResumeWakeupIsDeliveredWithoutPolling(t *testing.T) {
	runner, st, _ := newControlledRunner(t, wakeupScript)
	// 80 目标 / 每批 20 → 4 个真实批次，并发 2：任意时刻都至少有一个 worker 在批内，
	// 另一个 worker 在批次之间进入 waitWhilePaused。
	if err := st.SaveSettings(map[string]string{
		"scan_concurrency": "2",
		"scan_timeout_min": "10",
	}); err != nil {
		t.Fatal(err)
	}
	ips := make([]string, 0, 80)
	for i := 1; i <= 80; i++ {
		ips = append(ips, fmt.Sprintf("192.0.2.%d", i+1))
	}
	taskID, err := st.CreateScanTask(store.ScanTask{Name: "暂停唤醒测试", Mode: "top", TargetType: "manual", IPs: strings.Join(ips, "\n")})
	if err != nil {
		t.Fatal(err)
	}

	var resumedAt atomic.Int64
	var hookOnce sync.Once
	pausedWaitHook = func(scanID int64) {
		hookOnce.Do(func() {
			resumedAt.Store(time.Now().UnixNano())
			// 真实 Resume：SIGCONT 仍在暂停中的批次，并广播新一代通知。
			// 等待者此刻已经持有快照里的旧代通道，唤醒不依赖任何轮询。
			if err := runner.Resume(scanID); err != nil {
				t.Errorf("等待暂停唤醒时真实恢复失败: %v", err)
			}
		})
	}
	t.Cleanup(func() { pausedWaitHook = nil })

	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForFile(t, "batch_1_started")
	waitForFile(t, "batch_2_started")
	// 批 1 的结果已完整写出，随后从外部杀死它不会造成数据缺口。
	waitForFile(t, "batch_1_results")
	if err := runner.Pause(scanID); err != nil {
		t.Fatalf("暂停失败: %v", err)
	}
	waitForScanStatus(t, st, scanID, "paused")

	pid := readBatchPID(t, "batch_1.pid")
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		t.Fatalf("杀死暂停中的批次进程组失败: %v", err)
	}

	// 批 1 worker 收尾后进入 waitWhilePaused，pausedWaitHook 在那里发起真实 Resume；
	// 批 3 的出现时间就是控制通道送达唤醒的时间。
	waitForFile(t, "batch_3_started")
	woke := resumedAt.Load()
	if woke == 0 {
		t.Fatal("pausedWaitHook 未触发：等待者仍在依赖巡检而不是控制通道")
	}
	elapsed := time.Since(time.Unix(0, woke))
	if elapsed >= pauseHealInterval {
		t.Fatalf("恢复后 %s 才启动下一批，已达到/超过巡检间隔 %s：唤醒仍然依赖轮询，控制通道丢失了 Resume",
			elapsed.Round(time.Millisecond), pauseHealInterval)
	}

	waitForFile(t, "batch_4_started")
	waitForRunnerIdleWithin(t, runner, 30*time.Second)
	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
	}
	// 批 1 被 SIGKILL 属于异常退出，终态允许 partial；但不能停留在 paused/running。
	if scan.Status != "partial" && scan.Status != "failed" {
		t.Fatalf("外部杀死暂停进程后终态=%q，期望 partial/failed", scan.Status)
	}
	results, err := st.ResultsByScan(scanID)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(results))
	for _, result := range results {
		seen[result.IP] = true
	}
	for i := 21; i <= 80; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		if !seen[ip] {
			t.Fatalf("恢复后未继续执行剩余批次，缺少目标 %s 的结果", ip)
		}
	}
}

// readBatchPID 读取 fake 脚本记录的进程 PID。
func readBatchPID(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		t.Fatalf("%s 内容不是有效 PID: %q", path, string(raw))
	}
	return pid
}
