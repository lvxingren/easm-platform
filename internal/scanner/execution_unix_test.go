//go:build linux || darwin

package scanner

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"easm-platform/internal/config"
	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

func newControlledRunner(t *testing.T, script string) (*Runner, *store.Store, int64) {
	t.Helper()
	t.Chdir(t.TempDir())
	st, err := store.Open("test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := os.WriteFile("fake-naabu.sh", []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSettings(map[string]string{
		"naabu_path": "./fake-naabu.sh", "naabu_rate": "1000", "naabu_retries": "0",
		"naabu_workers": "25", "naabu_timeout": "1s", "scan_timeout_min": "1",
		"naabu_scan_type": "c", "naabu_verify": "0", "resource_monitor": "0",
	}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{NaabuPath: "naabu", NaabuRate: "1000", RealertDays: 7}
	runner := New(st, cfg, engine.New(st, cfg))
	t.Cleanup(runner.Shutdown)
	taskID, err := st.CreateScanTask(store.ScanTask{Name: "进程控制测试", Mode: "top", TargetType: "manual", IPs: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	return runner, st, taskID
}

const controlledScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
touch started
sleep 0.4
printf '192.0.2.1:8443\n' >> "$out"
printf '192.0.2.1:8443\n'
touch second
`

func TestRealtimePauseAndResume(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, controlledScript)
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForFile(t, "started")
	runner.mu.Lock()
	originalDeadline := time.Now().Add(500 * time.Millisecond)
	runner.active.deadline = originalDeadline
	runner.mu.Unlock()
	if err := runner.Pause(scanID); err != nil {
		t.Fatal(err)
	}
	waitForScanStatus(t, st, scanID, "paused")
	if _, err := runner.StartTask(taskID); err == nil {
		t.Fatal("暂停期间全局扫描锁被释放，允许了并发任务")
	}
	time.Sleep(700 * time.Millisecond)
	if _, err := os.Stat("second"); !os.IsNotExist(err) {
		t.Fatal("暂停期间 naabu 仍继续推进")
	}
	results, err := st.ResultsAfter(scanID, 0, 10)
	if err != nil || len(results) != 1 || results[0].Port != 443 {
		t.Fatalf("扫描未结束时首条结果未实时入库: %+v err=%v", results, err)
	}
	if err := runner.Resume(scanID); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	extendedDeadline := runner.active.deadline
	runner.mu.Unlock()
	if extendedDeadline.Sub(originalDeadline) < 600*time.Millisecond {
		t.Fatalf("暂停时长未计入有效扫描截止时间的顺延: 原截止时间=%v 新截止时间=%v", originalDeadline, extendedDeadline)
	}
	waitForScanStatus(t, st, scanID, "done")
	waitForRunnerIdle(t, runner)
	results, err = st.ResultsByScan(scanID)
	if err != nil || len(results) != 2 {
		t.Fatalf("恢复后结果不完整: %+v err=%v", results, err)
	}
}

const stopScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:443\n' > "$out"
printf '192.0.2.1:443\n'
touch started
sleep 30
printf '192.0.2.1:8443\n' >> "$out"
printf '192.0.2.1:8443\n'
touch should-not-exist
`

func TestStopKillsProcessGroupAndKeepsResults(t *testing.T) {
	runner, st, taskID := newControlledRunner(t, stopScript)
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForFile(t, "started")
	waitForResultCount(t, st, scanID, 1)
	runner.mu.Lock()
	var pid int
	for cmd := range runner.active.cmds {
		if cmd.Process != nil {
			pid = cmd.Process.Pid
			break
		}
	}
	runner.mu.Unlock()
	if pid == 0 {
		t.Fatal("未捕获到活跃 naabu 进程")
	}
	if err := runner.Stop(scanID); err != nil {
		t.Fatal(err)
	}
	waitForScanStatus(t, st, scanID, "stopped")
	waitForRunnerIdle(t, runner)
	if err := syscall.Kill(-pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("naabu 进程组仍残留: %v", err)
	}
	scan, _ := st.Scan(scanID)
	if scan.OpenPorts != 1 || scan.ProcessedTargets != 0 || scan.RemainingTargets() != 1 {
		t.Fatalf("终止后的进度或结果计数错误: %+v", scan)
	}
	if _, err := os.Stat("should-not-exist"); !os.IsNotExist(err) {
		t.Fatal("终止后 naabu 仍继续输出")
	}
	alerts, err := st.Alerts(10)
	if err != nil || len(alerts) != 0 {
		t.Fatalf("终止执行不应生成端口风险告警: %+v err=%v", alerts, err)
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	for range 500 {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待文件 %s 超时", path)
}

func waitForScanStatus(t *testing.T, st *store.Store, scanID int64, status string) {
	t.Helper()
	for range 500 {
		scan, err := st.Scan(scanID)
		if err != nil {
			t.Fatal(err)
		}
		if scan != nil && scan.Status == status {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	scan, _ := st.Scan(scanID)
	t.Fatalf("等待执行状态 %s 超时: %+v", status, scan)
}

func waitForResultCount(t *testing.T, st *store.Store, scanID int64, count int) {
	t.Helper()
	for range 500 {
		results, err := st.ResultsAfter(scanID, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(results) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("等待实时结果入库超时")
}

func waitForRunnerIdle(t *testing.T, runner *Runner) {
	t.Helper()
	for range 500 {
		if !runner.IsRunning() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("扫描运行锁未释放")
}

// parallelScript 读 -list 目标文件，为每个目标输出 <ip>:80（同时写 stdout 与 -o 文件），
// 末尾短暂 sleep 以制造多批次时间重叠，充分 exercise 并行共享状态。
const parallelScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
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
  printf '%s:80\n' "$ip" >> "$out"
  printf '%s:80\n' "$ip"
done < "$list"
sleep 0.2
`

// TestParallelBatchesAggregateResults 验证并发度>1 时多批 naabu 并行执行，
// 共享状态（去重集/开放端口/已处理）在加锁下正确聚合，无重复计数。
func TestParallelBatchesAggregateResults(t *testing.T) {
	runner, st, _ := newControlledRunner(t, parallelScript)
	if err := st.SaveSettings(map[string]string{"scan_concurrency": "3"}); err != nil {
		t.Fatal(err)
	}
	ips := make([]string, 0, 45)
	for i := 1; i <= 45; i++ {
		ips = append(ips, fmt.Sprintf("192.0.2.%d", i))
	}
	taskID, err := st.CreateScanTask(store.ScanTask{Name: "并行测试", Mode: "top", TargetType: "manual", IPs: strings.Join(ips, "\n")})
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForScanStatus(t, st, scanID, "done")
	waitForRunnerIdle(t, runner)

	scan, _ := st.Scan(scanID)
	if scan == nil {
		t.Fatal("扫描记录不存在")
	}
	if scan.OpenPorts != 45 {
		t.Fatalf("并行聚合开放端口=%d，期望 45", scan.OpenPorts)
	}
	if scan.ProcessedTargets != 45 {
		t.Fatalf("已处理目标=%d，期望 45", scan.ProcessedTargets)
	}
	results, err := st.ResultsByScan(scanID)
	if err != nil {
		t.Fatal(err)
	}
	uniq := map[string]bool{}
	for _, r := range results {
		uniq[r.IP] = true
	}
	if len(results) != 45 || len(uniq) != 45 {
		t.Fatalf("结果条数=%d 唯一IP=%d，期望均为 45（stdout 与文件双路径应去重）", len(results), len(uniq))
	}
}
