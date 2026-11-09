package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// newCapacityStore 在临时目录建库，绝不触碰 data/easm.db。
func newCapacityStore(t *testing.T, name string) *Store {
	t.Helper()
	st, err := Open(t.TempDir() + "/" + name)
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// uniqueResults 构造 n 条互不重复的结果，prefix 用于区分并发写入方。
func uniqueResults(n int, prefix string) []Result {
	out := make([]Result, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Result{
			IP:     fmt.Sprintf("%s.%d.%d", prefix, i/250, i%250),
			Port:   1000 + i%50000,
			Proto:  "tcp",
			Status: 1,
		})
	}
	return out
}

// TestInsertResultsBatchCountsOnlyNewRows 验证大量重复行时「实际新增条数」精确，
// 且 calls 之间与 calls 内部的重复都不计数，result_count 与实际行数一致。
func TestInsertResultsBatchCountsOnlyNewRows(t *testing.T) {
	st := newCapacityStore(t, "batch-count.db")
	scanID, err := st.CreateScan(1, "容量-去重计数", "top")
	if err != nil {
		t.Fatal(err)
	}

	unique := uniqueResults(1000, "10.10")
	rows := make([]Result, 0, 3000)
	for _, r := range unique {
		rows = append(rows, r, r, r) // 调用内重复 3 次
	}
	stats, err := st.InsertResultsBatch(scanID, rows)
	if err != nil {
		t.Fatalf("批量写入失败: %v", err)
	}
	if stats.Submitted != 3000 || stats.Inserted != 1000 {
		t.Fatalf("提交/新增统计错误: %+v（期望 submitted=3000 inserted=1000）", stats)
	}
	if want := 3000 / ResultInsertChunkSize; stats.Chunks != want {
		t.Fatalf("分块数=%d，期望 %d", stats.Chunks, want)
	}
	if n, err := st.CountResultsByScan(scanID); err != nil || n != 1000 {
		t.Fatalf("库内行数=%d err=%v，期望 1000", n, err)
	}

	// 再次写入：1000 条已存在 + 500 条新增，只有 500 条应计入
	second := append(append([]Result(nil), unique...), uniqueResults(500, "10.20")...)
	stats, err = st.InsertResultsBatch(scanID, second)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Inserted != 500 {
		t.Fatalf("第二次新增=%d，期望 500: %+v", stats.Inserted, stats)
	}
	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("读取执行失败: %v", err)
	}
	if scan.ResultCount != 1500 {
		t.Fatalf("result_count=%d，期望 1500（应与实际行数一致）", scan.ResultCount)
	}

	// 旧接口保持兼容：不报错、不重复计数
	if err := st.InsertResults(scanID, unique); err != nil {
		t.Fatalf("旧接口插入失败: %v", err)
	}
	if n, _ := st.CountResultsByScan(scanID); n != 1500 {
		t.Fatalf("旧接口重复写入后行数=%d，期望 1500", n)
	}
}

// TestInsertResultsBatchHardLimits 验证单次调用硬上限、分块规避超大 SQL、
// 空输入与非法 scan_id 的边界行为。
func TestInsertResultsBatchHardLimits(t *testing.T) {
	st := newCapacityStore(t, "batch-limit.db")
	scanID, err := st.CreateScan(1, "容量-上限", "full")
	if err != nil {
		t.Fatal(err)
	}

	tooMany := make([]Result, ResultInsertMaxBatch+1)
	for i := range tooMany {
		tooMany[i] = Result{IP: "192.0.2.1", Port: i, Proto: "tcp", Status: 1}
	}
	if _, err := st.InsertResultsBatch(scanID, tooMany); !errors.Is(err, ErrResultBatchTooLarge) {
		t.Fatalf("超过硬上限应返回 ErrResultBatchTooLarge，实际: %v", err)
	}
	if n, _ := st.CountResultsByScan(scanID); n != 0 {
		t.Fatalf("被拒绝的批量写入不应落库，实际 %d 行", n)
	}

	// 6000 行远超单条多值 INSERT 的绑定变量上限（6 参数/行），
	// 只有真正分块 + 逐行 Exec 才能成功，可据此确认没有构造超大 SQL。
	big := uniqueResults(6000, "172.16")
	stats, err := st.InsertResultsBatch(scanID, big)
	if err != nil {
		t.Fatalf("分块写入 6000 行失败: %v", err)
	}
	if stats.Inserted != 6000 || stats.Chunks != 12 {
		t.Fatalf("6000 行统计错误: %+v（期望 inserted=6000 chunks=12）", stats)
	}

	// 空输入：不开事务、零值统计、无错误
	if stats, err := st.InsertResultsBatch(scanID, nil); err != nil || stats.Chunks != 0 || stats.Inserted != 0 {
		t.Fatalf("空输入处理错误: %+v err=%v", stats, err)
	}
	// 非法 scan_id
	if _, err := st.InsertResultsBatch(0, []Result{{IP: "1.1.1.1", Port: 80, Proto: "tcp", Status: 1}}); !errors.Is(err, ErrScanIDRequired) {
		t.Fatalf("scan_id=0 应返回 ErrScanIDRequired，实际: %v", err)
	}
	if _, err := st.ResultsPage(0, 0, 10); !errors.Is(err, ErrScanIDRequired) {
		t.Fatalf("分页 scan_id=0 应返回 ErrScanIDRequired，实际: %v", err)
	}
}

// TestResultsPageNoGapNoDup 验证键集分页无遗漏无重复，且翻页途中并发写入
// 不会让已读过的行重复出现、也不会漏掉翻页前已存在的行。
func TestResultsPageNoGapNoDup(t *testing.T) {
	st := newCapacityStore(t, "page.db")
	scanID, err := st.CreateScan(1, "容量-分页", "full")
	if err != nil {
		t.Fatal(err)
	}
	const total = 1237
	initial := uniqueResults(total, "10.30")
	if _, err := st.InsertResultsBatch(scanID, initial); err != nil {
		t.Fatal(err)
	}

	seen := make(map[int64]int, total)
	cursor := int64(0)
	pages := 0
	insertedDuring := false
	for {
		page, err := st.ResultsPage(scanID, cursor, 100)
		if err != nil {
			t.Fatalf("第 %d 页读取失败: %v", pages, err)
		}
		for _, r := range page.Results {
			seen[r.ID]++
			if r.ID <= cursor {
				t.Fatalf("分页返回了不大于游标的行: id=%d cursor=%d", r.ID, cursor)
			}
		}
		pages++
		cursor = page.NextCursor
		if pages == 5 && !insertedDuring {
			// 翻页途中追加数据：游标之后的新行允许出现一次，已读行不得重复
			insertedDuring = true
			if _, err := st.InsertResultsBatch(scanID, uniqueResults(300, "10.40")); err != nil {
				t.Fatal(err)
			}
		}
		if !page.HasMore {
			break
		}
		if pages > 100 {
			t.Fatal("分页未收敛，疑似 HasMore 永真")
		}
	}
	if !insertedDuring {
		t.Fatal("并发写入用例未执行")
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("结果 id=%d 出现 %d 次，分页重复", id, n)
		}
	}
	// 翻页前已存在的行必须全部被读到（用一次全量查询取回基准 ID 集合）
	baseline, err := st.ResultsByScan(scanID)
	if err != nil {
		t.Fatal(err)
	}
	var baselineCount int
	for _, r := range baseline {
		baselineCount++
		if len(r.IP) >= 5 && r.IP[:5] == "10.30" {
			if seen[r.ID] != 1 {
				t.Fatalf("翻页前已存在的初始行 id=%d 被遗漏或重复（seen=%d）", r.ID, seen[r.ID])
			}
		}
	}
	if baselineCount != total+300 {
		t.Fatalf("基准行数=%d，期望 %d（初始 %d + 翻页期间新增 300）", baselineCount, total+300, total)
	}

	// 页大小硬上限与默认值
	clamped, err := st.ResultsPage(scanID, 0, ResultPageMaxLimit+5000)
	if err != nil {
		t.Fatal(err)
	}
	if len(clamped.Results) > ResultPageMaxLimit {
		t.Fatalf("页大小未截断到 %d，实际 %d", ResultPageMaxLimit, len(clamped.Results))
	}
	def, err := st.ResultsPage(scanID, 0, 0)
	if err != nil || len(def.Results) != ResultPageDefaultLimit {
		t.Fatalf("默认页大小错误: len=%d err=%v", len(def.Results), err)
	}

	// 空页语义
	empty, err := st.ResultsPage(scanID, 1<<40, 10)
	if err != nil {
		t.Fatal(err)
	}
	if empty.HasMore || len(empty.Results) != 0 || empty.NextCursor != 1<<40 {
		t.Fatalf("无数据分页语义错误: %+v", empty)
	}
}

// TestApplyScanProgressMonotonic 验证进度单调合并：乱序/迟到的旧快照不得覆盖更高值。
func TestApplyScanProgressMonotonic(t *testing.T) {
	st := newCapacityStore(t, "progress.db")
	scanID, err := st.CreateScan(1, "容量-进度", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartScanExecution(scanID, 1000, 20); err != nil {
		t.Fatal(err)
	}

	snapshots := []ScanProgress{
		{Processed: 120, Failed: 3, CurrentBatch: 6, OpenPorts: 400, Results: 400, Command: "naabu -top-ports 100"},
		{Processed: 40, Failed: 1, CurrentBatch: 2, OpenPorts: 100, Results: 100},
		{Processed: 300, Failed: 7, CurrentBatch: 15, OpenPorts: 900, Results: 950, Command: "naabu -p 1-1000"},
		{Processed: 200, Failed: 2, CurrentBatch: 10, OpenPorts: 700, Results: 700},
	}
	for _, snap := range snapshots {
		if err := st.ApplyScanProgress(scanID, snap); err != nil {
			t.Fatalf("合并进度失败: %v", err)
		}
	}
	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("读取执行失败: %v", err)
	}
	if scan.ProcessedTargets != 300 || scan.FailedTargets != 7 || scan.CurrentBatch != 15 ||
		scan.OpenPorts != 900 || scan.ResultCount != 950 {
		t.Fatalf("单调合并结果错误: %+v", scan)
	}
	if scan.Command != "naabu -p 1-1000" {
		t.Fatalf("command 应保留最后一次非空快照: %q", scan.Command)
	}

	// 旧快照再次写入不得回退
	if err := st.ApplyScanProgress(scanID, ScanProgress{Processed: 1, Failed: 0, CurrentBatch: 1, OpenPorts: 1, Results: 1}); err != nil {
		t.Fatal(err)
	}
	// 旧签名接口同样单调
	if err := st.UpdateScanProgress(scanID, 2, 0, 0, 2, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateScanOpenPorts(scanID, 3); err != nil {
		t.Fatal(err)
	}
	scan, _ = st.Scan(scanID)
	if scan.ProcessedTargets != 300 || scan.FailedTargets != 7 || scan.CurrentBatch != 15 ||
		scan.OpenPorts != 900 || scan.ResultCount != 950 {
		t.Fatalf("旧快照/旧接口把进度写回去了: %+v", scan)
	}
	if scan.Command != "naabu -p 1-1000" {
		t.Fatalf("空 command 快照不应清空已有命令文本: %q", scan.Command)
	}
}

// TestApplyScanProgressConcurrentOutOfOrder 并发下发乱序快照，最终值必须等于全局最大值。
func TestApplyScanProgressConcurrentOutOfOrder(t *testing.T) {
	st := newCapacityStore(t, "progress-concurrent.db")
	scanID, err := st.CreateScan(1, "容量-并发进度", "top")
	if err != nil {
		t.Fatal(err)
	}

	const workers, rounds = 8, 40
	maxP, maxF, maxB, maxO, maxR := 0, 0, 0, 0, 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				// 每个 worker 生成的数值高低交错，制造「旧快照后到」的场景
				step := (i*7 + worker*3) % rounds
				snap := ScanProgress{
					Processed:    step * 10,
					Failed:       step % 5,
					CurrentBatch: step,
					OpenPorts:    step * 20,
					Results:      step * 25,
				}
				mu.Lock()
				if snap.Processed > maxP {
					maxP = snap.Processed
				}
				if snap.Failed > maxF {
					maxF = snap.Failed
				}
				if snap.CurrentBatch > maxB {
					maxB = snap.CurrentBatch
				}
				if snap.OpenPorts > maxO {
					maxO = snap.OpenPorts
				}
				if snap.Results > maxR {
					maxR = snap.Results
				}
				mu.Unlock()
				if err := st.ApplyScanProgress(scanID, snap); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发合并进度失败: %v", err)
	}
	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("读取执行失败: %v", err)
	}
	if scan.ProcessedTargets != maxP || scan.FailedTargets != maxF || scan.CurrentBatch != maxB ||
		scan.OpenPorts != maxO || scan.ResultCount != maxR {
		t.Fatalf("并发乱序快照后进度=%+v，期望 processed=%d failed=%d batch=%d open=%d results=%d",
			scan, maxP, maxF, maxB, maxO, maxR)
	}
}

// TestFinishScanStatusTerminalCompat 验证终态更新兼容：done 归位到 target_count 且
// 固化 result_count，终态之后的旧进度快照不得回退。
func TestFinishScanStatusTerminalCompat(t *testing.T) {
	st := newCapacityStore(t, "terminal.db")
	doneID, err := st.CreateScan(1, "容量-终态", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartScanExecution(doneID, 100, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertResultsBatch(doneID, uniqueResults(120, "10.50")); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyScanProgress(doneID, ScanProgress{Processed: 5, Failed: 2, CurrentBatch: 1, OpenPorts: 120, Results: 120}); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScanStatus(doneID, "done", 120, ""); err != nil {
		t.Fatal(err)
	}
	scan, _ := st.Scan(doneID)
	if scan.Status != "done" || scan.FinishedAt == "" {
		t.Fatalf("终态字段缺失: %+v", scan)
	}
	if scan.ProcessedTargets != 100 || scan.FailedTargets != 0 || scan.CurrentBatch != 10 {
		t.Fatalf("done 终态进度错误: %+v", scan)
	}
	if scan.ResultCount != 120 || scan.OpenPorts != 120 {
		t.Fatalf("done 终态结果计数错误: %+v", scan)
	}
	// 终态后迟到的旧快照不得回退
	if err := st.ApplyScanProgress(doneID, ScanProgress{Processed: 3, Failed: 1, CurrentBatch: 1, OpenPorts: 3, Results: 3}); err != nil {
		t.Fatal(err)
	}
	scan, _ = st.Scan(doneID)
	if scan.ProcessedTargets != 100 || scan.ResultCount != 120 {
		t.Fatalf("终态后被旧快照回退: %+v", scan)
	}

	// 非 done 终态保留既有进度，只固化结果计数
	stopID, _ := st.CreateScan(1, "容量-终止", "top")
	if err := st.StartScanExecution(stopID, 50, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertResultsBatch(stopID, uniqueResults(30, "10.60")); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateScanProgress(stopID, 7, 1, 1, 30, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScanStatus(stopID, "stopped", 30, "用户终止"); err != nil {
		t.Fatal(err)
	}
	stopped, _ := st.Scan(stopID)
	if stopped.Status != "stopped" || stopped.Err != "用户终止" {
		t.Fatalf("stopped 终态错误: %+v", stopped)
	}
	if stopped.ProcessedTargets != 7 || stopped.FailedTargets != 1 || stopped.ResultCount != 30 {
		t.Fatalf("非 done 终态不应改写进度: %+v", stopped)
	}
}

// TestLegacyScanSchemaResultCountMigration 验证旧库（无 result_count 列）可正常打开，
// 新接口在旧库上可用且不破坏已有数据。
func TestLegacyScanSchemaResultCountMigration(t *testing.T) {
	path := t.TempDir() + "/legacy-capacity.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER DEFAULT 0, name TEXT DEFAULT '',
		mode TEXT, status TEXT, started_at TEXT, finished_at TEXT, open_ports INTEGER DEFAULT 0,
		error TEXT DEFAULT '', target_count INTEGER DEFAULT 0, command TEXT DEFAULT '');
	CREATE TABLE scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, ip TEXT,
		port INTEGER, proto TEXT DEFAULT 'tcp', service TEXT DEFAULT '', status INTEGER DEFAULT 1,
		UNIQUE(scan_id, ip, port, proto));
	INSERT INTO scans(task_id,name,mode,status,started_at,target_count) VALUES(1,'旧执行','top','done','2026-01-01T00:00:00Z',10);
	INSERT INTO scan_results(scan_id,ip,port,proto,service,status) VALUES(1,'192.0.2.1',443,'tcp','https',1);`); err != nil {
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

	scan, err := st.Scan(1)
	if err != nil || scan == nil {
		t.Fatalf("迁移后读取旧执行失败: %+v err=%v", scan, err)
	}
	if scan.Name != "旧执行" || scan.TargetCount != 10 || scan.ResultCount != 0 {
		t.Fatalf("旧行读取错误: %+v", scan)
	}
	page, err := st.ResultsPage(1, 0, 10)
	if err != nil || len(page.Results) != 1 || page.Results[0].Port != 443 {
		t.Fatalf("旧库分页读取失败: %+v err=%v", page, err)
	}
	if _, err := st.InsertResultsBatch(1, uniqueResults(3, "192.0.2")); err != nil {
		t.Fatalf("旧库批量写入失败: %v", err)
	}
	if err := st.ApplyScanProgress(1, ScanProgress{Processed: 10, Results: 4}); err != nil {
		t.Fatalf("旧库进度合并失败: %v", err)
	}
	scan, _ = st.Scan(1)
	if scan.ResultCount != 4 {
		t.Fatalf("旧库 result_count=%d，期望 4（1 旧行 + 3 新增）", scan.ResultCount)
	}
	if n, err := st.CountResultsByScan(1); err != nil || n != 4 {
		t.Fatalf("旧库行数=%d err=%v，期望 4", n, err)
	}
}

// TestConcurrentInsertAndProgress 并发批量写入 + 并发进度更新，验证新增计数准确
// 且进度不回退（配合 -race 运行）。
func TestConcurrentInsertAndProgress(t *testing.T) {
	st := newCapacityStore(t, "concurrent.db")
	scanID, err := st.CreateScan(1, "容量-并发写入", "full")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartScanExecution(scanID, 1200, 3); err != nil {
		t.Fatal(err)
	}

	const writers, perWriter = 6, 200
	var wg sync.WaitGroup
	errCh := make(chan error, writers*2)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			// 每个 worker 有一半行与其他 worker 重复（同一 IP 段），用于校验去重计数
			rows := uniqueResults(perWriter, fmt.Sprintf("10.70.%d", worker%3))
			if _, err := st.InsertResultsBatch(scanID, rows); err != nil {
				errCh <- err
			}
		}(w)
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 1; i <= 20; i++ {
				if err := st.ApplyScanProgress(scanID, ScanProgress{Processed: i, OpenPorts: i * 10}); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发操作失败: %v", err)
	}

	count, err := st.CountResultsByScan(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 600 {
		t.Fatalf("并发写入去重后行数=%d，期望 600（6 个 worker × 200 行，其中 3 组完全重复）", count)
	}
	scan, _ := st.Scan(scanID)
	if scan.ResultCount != count {
		t.Fatalf("result_count=%d 与实际行数 %d 不一致", scan.ResultCount, count)
	}
	if scan.ProcessedTargets != 20 || scan.OpenPorts != 200 {
		t.Fatalf("并发进度回退: %+v", scan)
	}
}
