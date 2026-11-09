//go:build linux || darwin

package scanner

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"easm-platform/internal/store"
)

// 本文件包含完全隔离的 fake naabu 集成测试：
//   - 工作目录切到 t.TempDir()，只打开 test.db，绝不触碰 data/easm.db；
//   - fake 脚本不联网、不做真实 DNS（只回显读取到的目标行）；
//   - PATH 中放置同名 naabu 绊线，任何回退真实 naabu 的路径都会被发现；
//   - 容量预检的系统探测由 withCapacityEnv 注入固定值，结果与真实 ulimit/磁盘无关。

// newFakeRunner 建立隔离的 Runner：临时工作目录 + 临时 HOME + test.db + fake naabu 脚本，
// 并在 PATH 中放置同名 naabu 绊线，任何回退真实 naabu 的路径都会被立即发现（详见 newCapacityHarness）。
func newFakeRunner(t *testing.T, script string, overrides map[string]string) (*Runner, *store.Store) {
	t.Helper()
	h := newCapacityHarness(t, script, overrides)
	return h.runner, h.st
}

func newManualTask(t *testing.T, st *store.Store, mode string, ips []string) int64 {
	t.Helper()
	taskID, err := st.CreateScanTask(store.ScanTask{
		Name: "fake naabu 容量测试", Mode: mode, TargetType: "manual", IPs: strings.Join(ips, "\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return taskID
}

// docIPv4 生成 n 个互不相同的文档地址（RFC 5737：192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）。
// 测试只用这些文档保留地址作为纯文本目标，fake naabu 不解析、不路由，因此不会产生任何公网流量。
func docIPv4(n int) []string {
	blocks := []string{"192.0.2.", "198.51.100.", "203.0.113."}
	ips := make([]string, 0, n)
	for i := 0; i < n; i++ {
		// 每个 /24 只取 1-254，跳过网络地址与广播地址。
		ips = append(ips, fmt.Sprintf("%s%d", blocks[i/254], i%254+1))
	}
	return ips
}

// peakConcurrency 根据脚本记录的 start/end 行计算并发峰值。
func peakConcurrency(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取并发记录失败: %v", err)
	}
	current, peak := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		switch line {
		case "start":
			current++
			if current > peak {
				peak = current
			}
		case "end":
			current--
		}
	}
	return peak
}

// matrixScript：读取 -list 目标，每个目标输出一行 JSONL（同时写 stdout 与 -o 文件），
// 记录 -p 参数与进程启停，用于验证 25 批、并发峰值与 -p - 全端口参数。
const matrixScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu fake v1'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -list) list="$2"; shift 2;;
    -p) printf 'p=%s\n' "$2" >> args.log; shift 2;;
    -json) printf 'json\n' >> args.log; shift;;
    *) shift;;
  esac
done
printf 'start\n' >> concurrency.log
: > "$out"
while IFS= read -r ip; do
  [ -z "$ip" ] && continue
  printf '{"host":"%s","ip":"%s","port":443,"protocol":"tcp"}\n' "$ip" "$ip" >> "$out"
  printf '{"host":"%s","ip":"%s","port":443,"protocol":"tcp"}\n' "$ip" "$ip"
done < "$list"
sleep 0.12
printf 'end\n' >> concurrency.log
`

// TestFakeNaabu500TargetsFullPortMatrix 验证 500 个唯一目标、固定 20 每批（共 25 批）、
// worker 并发 1/3/16 三种配置下都能完成全端口扫描：
//   - 命令行使用 -p - 全端口且带 -json；
//   - 并发峰值不超过配置的 worker 上限（多个 naabu 进程不会无界放大）；
//   - 结果按条目去重后恰好 500 条，进度与结果计数一致。
func TestFakeNaabu500TargetsFullPortMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("容量矩阵测试在 -short 下跳过")
	}
	ips := docIPv4(500)
	for _, workers := range []string{"1", "3", "16"} {
		t.Run("workers="+workers, func(t *testing.T) {
			runner, st := newFakeRunner(t, matrixScript, map[string]string{"scan_concurrency": workers})
			taskID := newManualTask(t, st, "full", ips)
			scanID, err := runner.StartTask(taskID)
			if err != nil {
				t.Fatalf("500 目标全端口在提高预算后应通过容量预检: %v", err)
			}
			waitForScanStatusWithin(t, st, scanID, "done", 120*time.Second)
			waitForRunnerIdleWithin(t, runner, 30*time.Second)

			scan, err := st.Scan(scanID)
			if err != nil || scan == nil {
				t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
			}
			if scan.Status != "done" || scan.FailedTargets != 0 {
				t.Fatalf("执行状态=%q 异常目标=%d，期望 done/0: %+v", scan.Status, scan.FailedTargets, scan)
			}
			if scan.TargetCount != 500 || scan.ProcessedTargets != 500 {
				t.Fatalf("目标数=%d 已处理=%d，期望均为 500", scan.TargetCount, scan.ProcessedTargets)
			}
			if scan.TotalBatches != 25 || scan.CurrentBatch != 25 {
				t.Fatalf("批次数=%d 已完成=%d，期望 25（500/20）", scan.TotalBatches, scan.CurrentBatch)
			}
			if scan.OpenPorts != 500 || scan.ResultCount != 500 {
				t.Fatalf("开放端口=%d 结果行=%d，期望均为 500", scan.OpenPorts, scan.ResultCount)
			}
			results, err := st.ResultsByScan(scanID)
			if err != nil {
				t.Fatal(err)
			}
			uniq := make(map[string]struct{}, len(results))
			for _, result := range results {
				uniq[fmt.Sprintf("%s:%d/%s", result.IP, result.Port, result.Proto)] = struct{}{}
			}
			if len(results) != 500 || len(uniq) != 500 {
				t.Fatalf("结果条数=%d 唯一键=%d，期望均为 500（stdout 与文件双路径必须去重）", len(results), len(uniq))
			}

			argsLog, err := os.ReadFile("args.log")
			if err != nil {
				t.Fatalf("未记录 naabu 参数: %v", err)
			}
			if !strings.Contains(string(argsLog), "p=-") {
				t.Fatalf("全端口扫描必须使用 -p -（不得自动改端口范围）: %q", string(argsLog))
			}
			if !strings.Contains(string(argsLog), "json") {
				t.Fatalf("未使用 -json 输出 JSONL: %q", string(argsLog))
			}

			peak := peakConcurrency(t, "concurrency.log")
			want := 0
			fmt.Sscanf(workers, "%d", &want)
			if peak < 1 || peak > want {
				t.Fatalf("并发峰值=%d，超过 worker 上限 %d（naabu 进程数必须受预算约束）", peak, want)
			}
			if want > 1 && peak < 2 {
				t.Fatalf("并发峰值=%d，多 worker 配置下未观察到并行执行", peak)
			}
		})
	}
}

// pauseBeyondDeadlineScript：先写出第一个端口结果，再短暂 sleep，最后补写第二个端口结果。
// 输出只写 -o 文件（不写 stdout），同时验证文件补读的流式解析路径。
const pauseBeyondDeadlineScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu fake v1'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -list) list="$2"; shift 2;;
    *) shift;;
  esac
done
: > "$out"
while IFS= read -r ip; do
  [ -z "$ip" ] && continue
  printf '{"host":"%s","ip":"%s","port":443,"protocol":"tcp"}\n' "$ip" "$ip" >> "$out"
done < "$list"
touch batch_ready
sleep 0.7
while IFS= read -r ip; do
  [ -z "$ip" ] && continue
  printf '{"host":"%s","ip":"%s","port":8443,"protocol":"tcp"}\n' "$ip" "$ip" >> "$out"
done < "$list"
`

// TestPauseAcrossOldDeadlineResumesAllBatches 验证并发多批在暂停时间超过旧 deadline 后恢复：
//   - 超时定时器不会在暂停期间误杀进程（触发前复核暂停状态与有效 deadline）；
//   - 恢复后所有批次继续完成，结果完整且不得标记超时。
func TestPauseAcrossOldDeadlineResumesAllBatches(t *testing.T) {
	runner, st := newFakeRunner(t, pauseBeyondDeadlineScript, map[string]string{"scan_concurrency": "3"})
	ips := docIPv4(60)
	taskID := newManualTask(t, st, "top", ips)
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForFileWithin(t, "batch_ready", 20*time.Second)

	// 把有效截止时间压到 1.5 秒后：暂停会持续 2 秒，旧 deadline 必然在暂停期间到期。
	runner.mu.Lock()
	runner.active.deadline = time.Now().Add(1500 * time.Millisecond)
	runner.active.notify()
	runner.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	if err := runner.Pause(scanID); err != nil {
		t.Fatalf("暂停失败: %v", err)
	}
	waitForScanStatus(t, st, scanID, "paused")
	time.Sleep(2 * time.Second) // 旧 deadline 已过：暂停期间不得有任何进程被超时杀掉
	if err := runner.Resume(scanID); err != nil {
		t.Fatalf("恢复失败: %v", err)
	}

	waitForScanStatusWithin(t, st, scanID, "done", 60*time.Second)
	waitForRunnerIdleWithin(t, runner, 30*time.Second)
	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
	}
	if scan.Status != "done" {
		t.Fatalf("恢复后状态=%q，期望 done（暂停时间不计入超时）: %+v", scan.Status, scan)
	}
	if strings.Contains(scan.Err, "总超时") {
		t.Fatalf("暂停超过旧 deadline 不应判定超时: %q", scan.Err)
	}
	if scan.OpenPorts != 120 || scan.ResultCount != 120 {
		t.Fatalf("开放端口=%d 结果行=%d，期望 120（60 目标 × 2 端口，且全部来自文件补读）", scan.OpenPorts, scan.ResultCount)
	}
	results, err := st.ResultsByScan(scanID)
	if err != nil || len(results) != 120 {
		t.Fatalf("结果条数=%d，期望 120（err=%v）", len(results), err)
	}
}

// retryLingerScript：首次尝试瞬态失败（非 SYN 权限问题）留下记录后成功；
// 特殊批次（目标 192.0.2.21）正常输出后由后台子进程持住 stdout 管道，
// 存在 retry_ready / linger_ready 后不再模拟故障。
const retryLingerScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu fake v1'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -list) list="$2"; shift 2;;
    *) shift;;
  esac
done
first=$(head -n 1 "$list")
n=0
if [ -f attempts ]; then n=$(cat attempts); fi
n=$((n + 1))
printf '%s\n' "$n" > attempts
if [ ! -f retry_ready ] && [ "$n" -le 1 ]; then
  echo 'naabu: temporary failure while starting scan' >&2
  exit 1
fi
line=$(printf '{"host":"%s","ip":"%s","port":443,"protocol":"tcp"}' "$first" "$first")
printf '%s\n' "$line" > "$out"
printf '%s\n' "$line"
if [ ! -f linger_ready ] && [ "$first" = "192.0.2.21" ]; then
  sleep 30 &
  printf '%s\n' "$!" >> linger_children.pid
  touch linger_done
  exit 0
fi
`

// TestFakeNaabuFailureLingeringPipeRetryAndRestart 验证同一任务在“瞬态故障 → 有界重试成功 →
// 某批遗留子进程持住管道（drainClosed）→ 再次启动完整成功”的全链路行为：
// 首次执行不得为 done 且必须保留结果，第二次执行必须干净完成。
func TestFakeNaabuFailureLingeringPipeRetryAndRestart(t *testing.T) {
	runner, st := newFakeRunner(t, retryLingerScript, map[string]string{"scan_concurrency": "1"})
	ips := make([]string, 0, 21)
	for i := 1; i <= 21; i++ {
		ips = append(ips, fmt.Sprintf("192.0.2.%d", i))
	}
	taskID := newManualTask(t, st, "top", ips)

	firstID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForRunnerIdleWithin(t, runner, 60*time.Second)
	first, err := st.Scan(firstID)
	if err != nil || first == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", first, err)
	}
	if first.Status == "done" {
		t.Fatalf("存在瞬态故障重试与遗留管道时不得判为 done: %+v", first)
	}
	if !strings.Contains(first.Err, "强制关闭管道") {
		t.Fatalf("未说明输出管道被遗留子进程占用并强制关闭: %q", first.Err)
	}
	if got := strings.TrimSpace(readTestFile(t, "attempts")); got == "1" {
		t.Fatalf("瞬态失败后未做任何重试（attempts=%q）", got)
	}
	if !strings.Contains(scanEventMessages(t, st, firstID), "次尝试成功") {
		t.Fatal("未记录重试成功事件")
	}
	results, err := st.ResultsByScan(firstID)
	if err != nil || len(results) == 0 {
		t.Fatalf("异常执行必须保留已入库结果: %+v err=%v", results, err)
	}
	waitForFileWithin(t, "linger_done", 20*time.Second)

	// 第二次执行：不再模拟故障与遗留管道，必须干净完成。
	if err := os.WriteFile("retry_ready", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("linger_ready", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	secondID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("异常收敛后无法再次启动同一任务: %v", err)
	}
	waitForScanStatusWithin(t, st, secondID, "done", 60*time.Second)
	waitForRunnerIdleWithin(t, runner, 30*time.Second)
	second, _ := st.Scan(secondID)
	if second == nil || second.Status != "done" {
		t.Fatalf("第二次执行未干净完成: %+v", second)
	}
	results, err = st.ResultsByScan(secondID)
	if err != nil || len(results) != 2 {
		t.Fatalf("第二次执行结果=%+v err=%v，期望 2 条（两个批次各 1 条）", results, err)
	}
}

// bulkOutputScript：先产生大量重复行，再产生 100 个唯一端口，全部同时写入 stdout 与 -o 文件，
// 用于验证流式解析、固定批量写库与“重复行不重复计数”。
const bulkOutputScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu fake v1'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -list) list="$2"; shift 2;;
    *) shift;;
  esac
done
tmp=bulk.tmp
: > "$tmp"
i=0
while [ "$i" -lt 5000 ]; do
  printf '{"host":"192.0.2.50","ip":"192.0.2.50","port":443,"protocol":"tcp"}\n' >> "$tmp"
  i=$((i+1))
done
i=1000
while [ "$i" -lt 1100 ]; do
  printf '{"host":"192.0.2.50","ip":"192.0.2.50","port":%d,"protocol":"tcp"}\n' "$i" >> "$tmp"
  i=$((i+1))
done
cat "$tmp" >> "$out"
cat "$tmp"
`

// TestFakeNaabuBulkOutputStreamsAndDeduplicates 验证大输出（5100 行）流式入库：
// stdout 与文件双路径的重复行不会重复计数，结果只保留 101 个唯一端口。
func TestFakeNaabuBulkOutputStreamsAndDeduplicates(t *testing.T) {
	runner, st := newFakeRunner(t, bulkOutputScript, map[string]string{"scan_concurrency": "1"})
	taskID := newManualTask(t, st, "top", []string{"192.0.2.50"})
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForScanStatusWithin(t, st, scanID, "done", 60*time.Second)
	waitForRunnerIdleWithin(t, runner, 30*time.Second)

	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
	}
	if scan.Status != "done" || scan.FailedTargets != 0 {
		t.Fatalf("大输出不应导致异常: %+v", scan)
	}
	if scan.OpenPorts != 101 || scan.ResultCount != 101 {
		t.Fatalf("开放端口=%d 结果行=%d，期望 101（5000 行重复 + 100 个唯一端口去重后）", scan.OpenPorts, scan.ResultCount)
	}
	results, err := st.ResultsByScan(scanID)
	if err != nil || len(results) != 101 {
		t.Fatalf("结果条数=%d，期望 101（err=%v）", len(results), err)
	}
}

// stopAllBatchesScript：登记自身进程号、输出一条结果后长时间 sleep，用于验证 Stop 同时终止所有活跃批次。
const stopAllBatchesScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu fake v1'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -list) list="$2"; shift 2;;
    *) shift;;
  esac
done
printf '%s\n' "$$" >> pids.log
first=$(head -n 1 "$list")
printf '{"host":"%s","ip":"%s","port":443,"protocol":"tcp"}\n' "$first" "$first" > "$out"
printf '{"host":"%s","ip":"%s","port":443,"protocol":"tcp"}\n' "$first" "$first"
touch batches_running
sleep 30
`

// TestConcurrentBatchesAllStopTogether 验证 Stop 会广播到每个活跃批次（代际通道广播），
// 所有 naabu 进程组都被终止，执行在有限时间内收敛为 stopped。
func TestConcurrentBatchesAllStopTogether(t *testing.T) {
	runner, st := newFakeRunner(t, stopAllBatchesScript, map[string]string{"scan_concurrency": "3"})
	taskID := newManualTask(t, st, "top", docIPv4(60))
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForPIDCount(t, "pids.log", 3)
	// 先等到“终止前已有一条结果入库”再 Stop：刷库是 200 行/500ms 触发的固定批量，
	// 若在结果仍在内存 pending 时就终止，入库条数为 0 属于合法行为，却会让
	// “已入库结果应保留”的断言随调度抖动。
	inserted := 0
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if count, err := st.CountResultsByScan(scanID); err == nil && count >= 1 {
			inserted = count
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if inserted < 1 {
		t.Fatal("终止前应有至少一条结果已入库（固定批量刷库 500ms 周期）")
	}
	if err := runner.Stop(scanID); err != nil {
		t.Fatalf("多批并发时 Stop 失败: %v", err)
	}
	waitForScanStatusWithin(t, st, scanID, "stopped", 20*time.Second)
	waitForRunnerIdleWithin(t, runner, 20*time.Second)
	waitRecordedPidGone(t, "pids.log")

	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
	}
	if scan.ProcessedTargets != 0 {
		t.Fatalf("终止后已处理目标=%d，期望 0（被中断批次不计入完成）", scan.ProcessedTargets)
	}
	if scan.OpenPorts < inserted {
		t.Fatalf("终止前已入库结果应保留：入库 %d 条，执行记录开放端口=%d", inserted, scan.OpenPorts)
	}
}

func waitForFileWithin(t *testing.T, path string, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待文件 %s 超时（%s）", path, limit)
}

func waitForScanStatusWithin(t *testing.T, st *store.Store, scanID int64, status string, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		scan, err := st.Scan(scanID)
		if err != nil {
			t.Fatal(err)
		}
		if scan != nil && scan.Status == status {
			return
		}
		if scan != nil && terminalScanStatus(scan.Status) {
			// 已经进入其他终态：不必再等到超时，直接报错并带上完整执行详情（含首条错误原因）。
			t.Fatalf("执行意外进入终态 %q（期望 %s）: %+v", scan.Status, status, scan)
		}
		time.Sleep(10 * time.Millisecond)
	}
	scan, _ := st.Scan(scanID)
	t.Fatalf("等待执行状态 %s 超时（%s）: %+v", status, limit, scan)
}

// terminalScanStatus 判断执行状态是否已是终态；用于等待循环提前失败，避免跑满超时。
func terminalScanStatus(status string) bool {
	switch status {
	case "done", "partial", "failed", "stopped":
		return true
	}
	return false
}

func waitForPIDCount(t *testing.T, path string, count int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && len(strings.Fields(string(data))) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待 %s 中出现 %d 个 naabu 进程超时", path, count)
}

// TestCapacityPlanRateReachesNaabuArgv 验证“执行使用容量计划同一设置快照”：
// 平台总速率预算 2000/s 小于并发 3 × 单进程速率 5000/s 时，容量计划把每进程速率收敛为 666/s，
// 实际 naabu argv 的 -rate 必须是 plan.PerRate，而不是用户配置的原始 5000。
func TestCapacityPlanRateReachesNaabuArgv(t *testing.T) {
	h := newCapacityHarness(t, matrixScript, map[string]string{
		"naabu_rate":       "5000",
		"naabu_total_rate": "2000",
		"scan_concurrency": "3",
		"scan_timeout_min": "60",
	})
	taskID := newManualTask(t, h.st, "top", docIPv4(60))
	scanID, err := h.runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("总速率收敛后应允许启动: %v", err)
	}
	waitForScanStatusWithin(t, h.st, scanID, "done", 60*time.Second)
	waitForRunnerIdleWithin(t, h.runner, 30*time.Second)

	scans := 0
	for _, line := range h.invocations(t) {
		parsed := h.parseInvocation(t, line)
		if parsed.version {
			continue
		}
		h.assertScanArgv(t, parsed, line)
		scans++
		if rate := parsed.flags["-rate"]; rate != "666" {
			t.Fatalf("naabu argv 的 -rate=%q，期望容量计划的 666（用户配置 5000 必须被平台总速率预算收敛）: %q", rate, line)
		}
	}
	if scans != 3 {
		t.Fatalf("扫描调用次数=%d，期望 3（60 目标 / 每批 20）", scans)
	}
	events := scanEventMessages(t, h.st, scanID)
	if !strings.Contains(events, "每进程速率 666/s") {
		t.Fatalf("执行事件未记录容量计划的每进程速率: %s", events)
	}
	h.assertOfflineOnly(t, true)
}
