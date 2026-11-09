package store

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

// 本文件用 SQLite 自身的故障能力（触发器 RAISE 与延迟外键）在真实事务路径上
// 注入「块中途 Exec 失败 / result_count UPDATE 失败 / Commit 失败」三类故障：
//   - 不使用任何测试专用生产钩子，故障发生在 insertResultChunk 的真实 SQL 上；
//   - 全部使用临时目录建库（newCapacityStore），绝不触碰 data/easm.db。

// mustExecRaw 在临时库上执行建触发器/建表等测试专用 SQL。
func mustExecRaw(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.Exec(query); err != nil {
		t.Fatalf("故障注入初始化失败: %v\nSQL: %s", err, query)
	}
}

// newFaultStore 建临时库并创建一条执行记录，供故障注入用例复用。
func newFaultStore(t *testing.T, name string) (*Store, int64) {
	t.Helper()
	st := newCapacityStore(t, name)
	scanID, err := st.CreateScan(1, "容量-故障注入", "top")
	if err != nil {
		t.Fatalf("创建执行记录失败: %v", err)
	}
	return st, scanID
}

// wantBatchState 描述一次分块写入结束后的期望状态：
// 返回统计、scan_results 实际行数与 scans.result_count 必须完全一致。
type wantBatchState struct {
	inserted int // 已成功 Commit 的实际新增行数
	chunks   int // 已成功 Commit 的分块数
	rows     int // scan_results 实际行数（故障用例均从空表开始，故等于 inserted）
}

// assert 校验统计、库内行数、result_count 三者一致，且已提交数据未被失败块污染。
func (w wantBatchState) assert(t *testing.T, st *Store, scanID int64, stats ResultInsertStats, submitted int) {
	t.Helper()
	if stats.Submitted != submitted {
		t.Fatalf("Submitted=%d，期望 %d（始终为本次提交总行数）", stats.Submitted, submitted)
	}
	if stats.Inserted != w.inserted || stats.Chunks != w.chunks {
		t.Fatalf("统计=%+v，期望 inserted=%d chunks=%d", stats, w.inserted, w.chunks)
	}
	rows, err := st.CountResultsByScan(scanID)
	if err != nil {
		t.Fatalf("统计库内行数失败: %v", err)
	}
	if rows != w.rows {
		t.Fatalf("scan_results 实际行数=%d，期望 %d（失败块必须整块回滚）", rows, w.rows)
	}
	if stats.Inserted != rows {
		t.Fatalf("返回 Inserted=%d 与库内实际行数 %d 不一致", stats.Inserted, rows)
	}
	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("读取执行记录失败: %v", err)
	}
	if scan.ResultCount != w.rows {
		t.Fatalf("result_count=%d 与实际行数 %d 不一致（前序块应保留、失败块应回滚）", scan.ResultCount, w.rows)
	}
}

// TestInsertResultsBatchChunkFailuresIsolateCommittedChunks 验证第二个分块在
// Exec / 计数 UPDATE / Commit 三个环节失败时：失败块整块回滚且返回 inserted=0 贡献，
// 第一个已提交分块的数据与 result_count 保留，统计与 DB 状态完全一致。
func TestInsertResultsBatchChunkFailuresIsolateCommittedChunks(t *testing.T) {
	const total = 2 * ResultInsertChunkSize // 恰好两个分块
	rows := uniqueResults(total, "10.80")
	// 第 750 行位于第二个分块内部（偏移 250），确保故障发生在块中途而非块首。
	if rows[750].IP != "10.80.3.0" {
		t.Fatalf("测试数据前提变化：rows[750].IP=%q", rows[750].IP)
	}
	// 第一个分块已提交后的期望状态：500 行、result_count=500。
	firstChunk := wantBatchState{inserted: ResultInsertChunkSize, chunks: 1, rows: ResultInsertChunkSize}

	t.Run("块中途 Exec 失败", func(t *testing.T) {
		st, scanID := newFaultStore(t, "fault-exec.db")
		mustExecRaw(t, st.db, `CREATE TRIGGER fault_exec AFTER INSERT ON scan_results
			WHEN NEW.ip='10.80.3.0' BEGIN SELECT RAISE(ABORT,'inject-exec'); END;`)
		stats, err := st.InsertResultsBatch(scanID, rows)
		if err == nil || !strings.Contains(err.Error(), "inject-exec") {
			t.Fatalf("期望块内 Exec 注入错误，实际: %v", err)
		}
		firstChunk.assert(t, st, scanID, stats, total)
	})

	t.Run("计数 UPDATE 失败", func(t *testing.T) {
		st, scanID := newFaultStore(t, "fault-count.db")
		// 第二个块的 UPDATE 把 result_count 从 500 加到 1000 时触发失败。
		mustExecRaw(t, st.db, fmt.Sprintf(`CREATE TRIGGER fault_count AFTER UPDATE OF result_count ON scans
			WHEN NEW.result_count > %d BEGIN SELECT RAISE(ABORT,'inject-count'); END;`, ResultInsertChunkSize))
		stats, err := st.InsertResultsBatch(scanID, rows)
		if err == nil || !strings.Contains(err.Error(), "inject-count") {
			t.Fatalf("期望计数 UPDATE 注入错误，实际: %v", err)
		}
		// 第二个块已插入的行与其 result_count 增量都被回滚。
		firstChunk.assert(t, st, scanID, stats, total)
	})

	t.Run("Commit 失败", func(t *testing.T) {
		st, scanID := newFaultStore(t, "fault-commit.db")
		// 延迟外键只在 COMMIT 时校验，可以真实地让 Commit 返回错误；
		// 固定单连接保证 PRAGMA foreign_keys 与事务使用同一个连接。
		st.db.SetMaxOpenConns(1)
		mustExecRaw(t, st.db, `PRAGMA foreign_keys=ON`)
		mustExecRaw(t, st.db, `CREATE TABLE commit_guard(x INTEGER REFERENCES scans(id) DEFERRABLE INITIALLY DEFERRED);
			CREATE TRIGGER fault_commit AFTER INSERT ON scan_results
			WHEN NEW.ip='10.80.3.0' BEGIN INSERT INTO commit_guard(x) VALUES(-1); END;`)
		stats, err := st.InsertResultsBatch(scanID, rows)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
			t.Fatalf("期望 Commit 触发延迟外键错误，实际: %v", err)
		}
		firstChunk.assert(t, st, scanID, stats, total)
	})
}

// TestInsertResultsBatchFirstChunkFailureWritesNothing 验证没有前序成功块时，
// 首块失败必须返回 inserted=0、chunks=0，库内行数与 result_count 都保持为 0。
func TestInsertResultsBatchFirstChunkFailureWritesNothing(t *testing.T) {
	const total = 100
	rows := uniqueResults(total, "10.81")
	mid := rows[50]
	st, scanID := newFaultStore(t, "fault-first.db")
	mustExecRaw(t, st.db, fmt.Sprintf(`CREATE TRIGGER fault_first AFTER INSERT ON scan_results
		WHEN NEW.ip='%s' BEGIN SELECT RAISE(ABORT,'inject-first'); END;`, mid.IP))

	stats, err := st.InsertResultsBatch(scanID, rows)
	if err == nil || !strings.Contains(err.Error(), "inject-first") {
		t.Fatalf("期望首块 Exec 注入错误，实际: %v", err)
	}
	wantBatchState{inserted: 0, chunks: 0, rows: 0}.assert(t, st, scanID, stats, total)
}
