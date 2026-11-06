package store

import (
	"database/sql"
	"strings"
	"testing"
)

// TestWhitelistBusinessFieldAndLegacyMigration 验证白名单 business 字段读写，
// 以及旧库（无 business 列）自动补列后以 COALESCE 兜底为空可读。
func TestWhitelistBusinessFieldAndLegacyMigration(t *testing.T) {
	path := t.TempDir() + "/legacy-wl.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// 旧版 whitelist 表（无 business 列）+ 一条旧行
	if _, err := db.Exec(`CREATE TABLE whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_spec TEXT, port_spec TEXT, proto TEXT DEFAULT '*', service TEXT DEFAULT '', owner TEXT DEFAULT '', remark TEXT DEFAULT '', created_at TEXT);
INSERT INTO whitelist(ip_spec,port_spec,proto,service,owner,remark,created_at) VALUES('10.0.0.1','22','tcp','ssh','ops','旧行','2026-01-01T00:00:00Z');`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("旧库迁移失败: %v", err)
	}
	defer st.Close()

	// 旧行 business 应兜底为空
	wl, err := st.Whitelist()
	if err != nil {
		t.Fatalf("迁移后读取失败: %v", err)
	}
	if len(wl) != 1 || wl[0].Business != "" {
		t.Fatalf("旧行 business 应为空: %+v", wl)
	}

	// 新增带 business 的条目并读回
	if _, err := st.AddWhitelist(WLEntry{IPSpec: "192.0.2.1", PortSpec: "443", Proto: "tcp", Service: "https", Owner: "baseline", Business: "核心业务", Remark: "基线生成"}); err != nil {
		t.Fatal(err)
	}
	wl, _ = st.Whitelist()
	var found bool
	for _, e := range wl {
		if e.IPSpec == "192.0.2.1" && e.PortSpec == "443" {
			found = true
			if e.Business != "核心业务" || e.Owner != "baseline" {
				t.Fatalf("business/owner 未正确保存: %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("新增白名单条目未读到")
	}
}

// TestScanTaskCustomPorts 验证自定义端口任务的读写与 normalize（非 custom 模式清空 custom_ports）。
func TestScanTaskCustomPorts(t *testing.T) {
	st, err := Open(t.TempDir() + "/tasks.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	id, err := st.CreateScanTask(ScanTask{Name: "自定义端口任务", Mode: "custom", CustomPorts: "22,80,8000-9000", TargetType: "all"})
	if err != nil {
		t.Fatal(err)
	}
	task, err := st.ScanTask(id)
	if err != nil || task == nil {
		t.Fatalf("读取任务失败: %v", err)
	}
	if task.Mode != "custom" || task.CustomPorts != "22,80,8000-9000" {
		t.Fatalf("自定义端口未正确保存: %+v", task)
	}
	// 列表读取也应带出 custom_ports
	tasks, _ := st.ScanTasks()
	if len(tasks) != 1 || tasks[0].CustomPorts != "22,80,8000-9000" {
		t.Fatalf("列表读取自定义端口错误: %+v", tasks)
	}
	// 改为 top 模式后 custom_ports 应被 normalize 清空
	task.Mode = "top"
	if err := st.UpdateScanTask(*task); err != nil {
		t.Fatal(err)
	}
	task, _ = st.ScanTask(id)
	if task.Mode != "top" || task.CustomPorts != "" {
		t.Fatalf("非 custom 模式应清空 custom_ports: %+v", task)
	}
}

// TestHealStaleScansAndForceStop 验证启动自愈与手动同步：仅修正 running/paused，幂等且不影响已结束执行。
func TestHealStaleScansAndForceStop(t *testing.T) {
	st, err := Open(t.TempDir() + "/heal.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	runningID, _ := st.CreateScan(1, "悬空运行", "top") // status=running
	pausedID, _ := st.CreateScan(1, "悬空暂停", "top")
	if err := st.SetScanActiveStatus(pausedID, "paused"); err != nil {
		t.Fatal(err)
	}
	doneID, _ := st.CreateScan(1, "已完成", "top")
	if err := st.FinishScanStatus(doneID, "done", 3, ""); err != nil {
		t.Fatal(err)
	}

	healed, err := st.HealStaleScans()
	if err != nil {
		t.Fatal(err)
	}
	if healed != 2 {
		t.Fatalf("自愈条数=%d，期望 2（running+paused）", healed)
	}
	for _, id := range []int64{runningID, pausedID} {
		sc, _ := st.Scan(id)
		if sc == nil || sc.Status != "stopped" || sc.FinishedAt == "" {
			t.Fatalf("悬空执行 %d 未修正为 stopped: %+v", id, sc)
		}
		if !strings.Contains(sc.Err, "重启") {
			t.Fatalf("修正说明缺失: %q", sc.Err)
		}
	}
	doneScan, _ := st.Scan(doneID)
	if doneScan.Status != "done" {
		t.Fatalf("已完成执行不应被自愈改动: %+v", doneScan)
	}

	// ForceStopScanIfActive 幂等：对已 stopped 的执行再调用不改状态、不报错
	newRun, _ := st.CreateScan(1, "待手动同步", "top")
	if err := st.ForceStopScanIfActive(newRun, "手动同步状态"); err != nil {
		t.Fatal(err)
	}
	sc, _ := st.Scan(newRun)
	if sc.Status != "stopped" || sc.Err != "手动同步状态" {
		t.Fatalf("手动同步未生效: %+v", sc)
	}
	if err := st.ForceStopScanIfActive(newRun, "再次同步"); err != nil {
		t.Fatal(err)
	}
	sc, _ = st.Scan(newRun)
	if sc.Err != "手动同步状态" {
		t.Fatalf("已 stopped 的执行不应被再次覆盖: %+v", sc)
	}
	// 自愈再次执行应为 0 条
	again, _ := st.HealStaleScans()
	if again != 0 {
		t.Fatalf("无悬空执行时自愈条数=%d，期望 0", again)
	}
}
