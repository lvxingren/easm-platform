//go:build linux || darwin

package scanner

import (
	"errors"
	"os"
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
	pid := runner.active.cmd.Process.Pid
	runner.mu.Unlock()
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
