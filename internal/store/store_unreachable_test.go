package store

import (
	"path/filepath"
	"testing"
)

// TestPruneUnreachableDetailsKeepsRecentWindow 验证不可达明细按“最近 N 次执行”裁剪：
// 保留窗口内的明细不动，窗口外与孤儿（扫描已不存在）一并删除，避免定时扫描下表无界增长。
func TestPruneUnreachableDetailsKeepsRecentWindow(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "unreach_prune.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var ids []int64
	for i := 0; i < 3; i++ {
		id, err := st.CreateScan(0, "prune", "top")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		if err := st.RecordUnreachable(id, "old.example.com", ReasonDNSFailure); err != nil {
			t.Fatal(err)
		}
	}
	// 孤儿明细：scan_id 不在 scans 表中，应被任意一次裁剪清理。
	if err := st.RecordUnreachable(9999, "ghost.example.com", ReasonDNSFailure); err != nil {
		t.Fatal(err)
	}

	removed, err := st.PruneUnreachableDetails(2)
	if err != nil {
		t.Fatal(err)
	}
	// 最旧一次执行的 1 条 + 孤儿 1 条被删，最近 2 次各 1 条保留。
	if removed != 2 {
		t.Fatalf("应删除 2 条，实际 %d", removed)
	}
	for i, id := range ids {
		rows, err := st.Unreachables(id)
		if err != nil {
			t.Fatal(err)
		}
		if i < len(ids)-2 {
			if len(rows) != 0 {
				t.Fatalf("窗口外扫描 %d 明细应已清空: %+v", id, rows)
			}
			continue
		}
		if len(rows) != 1 {
			t.Fatalf("窗口内扫描 %d 应保留 1 条: %+v", id, rows)
		}
	}

	// keepRecent 覆盖全部执行时不删任何行。
	if removed, err := st.PruneUnreachableDetails(10); err != nil || removed != 0 {
		t.Fatalf("窗口覆盖全部时应 0 删除: removed=%d err=%v", removed, err)
	}
}

// TestRecordUnreachableBatchDedupes 验证批量写入按 UNIQUE(scan_id,target) 去重且只统计真实新增。
func TestRecordUnreachableBatchDedupes(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "unreach_batch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.CreateScan(0, "batch", "top")
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := st.RecordUnreachableBatch(id, []string{"a.example.com", " a.example.com ", "b.example.com", "", "a.example.com"}, ReasonDNSFailure)
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 2 {
		t.Fatalf("同批去重后应新增 2 条，实际 %d", inserted)
	}
	// 再写一次（与库内重复）：0 新增、无错误。
	inserted, err = st.RecordUnreachableBatch(id, []string{"a.example.com"}, ReasonDNSFailure)
	if err != nil || inserted != 0 {
		t.Fatalf("库内重复应静默忽略: inserted=%d err=%v", inserted, err)
	}
	rows, err := st.Unreachables(id)
	if err != nil || len(rows) != 2 {
		t.Fatalf("明细应为 2 条: %+v err=%v", rows, err)
	}
	// 空输入不开事务、不报错。
	if _, err := st.RecordUnreachableBatch(id, nil, ReasonDNSFailure); err != nil {
		t.Fatal(err)
	}
}
