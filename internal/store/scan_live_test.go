package store

import (
	"database/sql"
	"testing"
)

func TestLegacyMigrationActiveStatesAndIncrementalQueries(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER DEFAULT 0,
		name TEXT DEFAULT '',
		mode TEXT,
		status TEXT,
		started_at TEXT,
		finished_at TEXT,
		open_ports INTEGER DEFAULT 0,
		error TEXT DEFAULT '',
		target_count INTEGER DEFAULT 0,
		command TEXT DEFAULT ''
	);
	CREATE TABLE scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER,
		ip TEXT,
		port INTEGER,
		proto TEXT DEFAULT 'tcp',
		service TEXT DEFAULT '',
		status INTEGER DEFAULT 1,
		UNIQUE(scan_id, ip, port, proto)
	);
	INSERT INTO scans(task_id,name,mode,status,started_at) VALUES(1,'旧库执行','top','running','2026-01-01T00:00:00Z');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("旧数据库迁移失败: %v", err)
	}
	defer st.Close()
	scan, err := st.Scan(1)
	if err != nil || scan == nil || scan.Name != "旧库执行" {
		t.Fatalf("迁移后读取旧执行失败: %+v err=%v", scan, err)
	}
	if err := st.SetScanActiveStatus(scan.ID, "paused"); err != nil {
		t.Fatal(err)
	}
	active, err := st.ScansFiltered("active", "", "", 0, 0)
	if err != nil || len(active) != 1 || active[0].Status != "paused" {
		t.Fatalf("活动执行未覆盖 paused: %+v err=%v", active, err)
	}
	latest, err := st.LatestRunningScan()
	if err != nil || latest == nil || latest.ID != scan.ID {
		t.Fatalf("暂停执行未出现在当前活动查询: %+v err=%v", latest, err)
	}

	if err := st.UpdateScanResource(scan.ID, 96.5, 256*1024*1024); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateScanResource(scan.ID, 12, 64*1024*1024); err != nil {
		t.Fatal(err)
	}
	scan, _ = st.Scan(scan.ID)
	if scan.CPUPercent != 12 || scan.MaxCPUPercent != 96.5 || scan.MemoryRSS != 64*1024*1024 || scan.MaxMemoryRSS != 256*1024*1024 {
		t.Fatalf("资源当前值或峰值迁移后记录错误: %+v", scan)
	}
	if err := st.InsertResults(scan.ID, []Result{
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Status: 1},
		{IP: "192.0.2.2", Port: 80, Proto: "tcp", Status: 1},
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Status: 1},
	}); err != nil {
		t.Fatal(err)
	}
	results, err := st.ResultsAfter(scan.ID, 0, 10)
	if err != nil || len(results) != 2 || results[0].ID == 0 {
		t.Fatalf("迁移后的增量结果查询错误: %+v err=%v", results, err)
	}
	remaining, err := st.ResultsAfter(scan.ID, results[0].ID, 10)
	if err != nil || len(remaining) != 1 || remaining[0].Port != 80 {
		t.Fatalf("结果游标查询错误: %+v err=%v", remaining, err)
	}
	if err := st.AddScanEvent(scan.ID, "info", "pause", "暂停"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddScanEvent(scan.ID, "info", "resume", "恢复"); err != nil {
		t.Fatal(err)
	}
	events, err := st.ScanEvents(scan.ID, 0, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("执行事件查询错误: %+v err=%v", events, err)
	}
	events, err = st.ScanEvents(scan.ID, events[0].ID, 10)
	if err != nil || len(events) != 1 || events[0].Type != "resume" {
		t.Fatalf("事件游标查询错误: %+v err=%v", events, err)
	}

	if err := st.FinishScanStatus(scan.ID, "stopped", 2, "用户终止"); err != nil {
		t.Fatal(err)
	}
	stopped, err := st.ScansFiltered("stopped", "", "", 0, 0)
	if err != nil || len(stopped) != 1 {
		t.Fatalf("stopped 状态筛选错误: %+v err=%v", stopped, err)
	}
	active, err = st.ScansFiltered("active", "", "", 0, 0)
	if err != nil || len(active) != 0 {
		t.Fatalf("终止执行仍被视作活动: %+v err=%v", active, err)
	}
}
