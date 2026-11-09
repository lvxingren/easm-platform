package store

import (
	"path/filepath"
	"testing"
)

func newTSStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "ts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestTargetStatusLifecycleAndUnfinished(t *testing.T) {
	st := newTSStore(t)
	id, _ := st.CreateScan(1, "ts", "top")
	specs := []TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}, {Raw: "192.0.2.2", Kind: "ip"}, {Raw: "192.0.2.3", Kind: "ip"}, {Raw: "192.0.2.4", Kind: "ip"}}
	if err := st.InitTargetStatus(id, specs, 2); err != nil {
		t.Fatal(err)
	}
	if !st.HasTargetStatus(id) {
		t.Fatal("应已记录目标状态")
	}
	// batch0 (spec1,2) done; batch1 (spec3,4): spec3 running, spec4 pending→failed
	_ = st.MarkBatchTargetStatus(id, 0, TargetDone)
	_ = st.MarkBatchTargetStatus(id, 1, TargetRunning)
	_ = st.MarkTargetStatusByRaw(id, "192.0.2.4", TargetFailed)

	done, pending, running, failed, err := st.TargetStatusCounts(id)
	if err != nil || done != 2 || pending != 0 || running != 1 || failed != 1 {
		t.Fatalf("计数错误: done=%d pending=%d running=%d failed=%d err=%v", done, pending, running, failed, err)
	}
	un, err := st.UnfinishedSpecs(id)
	if err != nil || len(un) != 2 {
		t.Fatalf("未完成应 2（running+failed）: %+v err=%v", un, err)
	}
	if un[0].Raw != "192.0.2.3" || un[1].Raw != "192.0.2.4" {
		t.Fatalf("未完成规格错误: %+v", un)
	}
	rows, _ := st.TargetStatusByScan(id)
	if len(rows) != 4 {
		t.Fatalf("状态行应 4: %d", len(rows))
	}
}

func TestInitTargetStatusIdempotent(t *testing.T) {
	st := newTSStore(t)
	id, _ := st.CreateScan(1, "ts", "top")
	specs := []TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}}
	_ = st.InitTargetStatus(id, specs, 1)
	_ = st.MarkBatchTargetStatus(id, 0, TargetDone)
	// 重复 init 不覆盖已 done 的状态。
	_ = st.InitTargetStatus(id, specs, 1)
	done, _, _, _, _ := st.TargetStatusCounts(id)
	if done != 1 {
		t.Fatalf("重复 init 不应重置状态: done=%d", done)
	}
}

func TestSetScanResumeOf(t *testing.T) {
	st := newTSStore(t)
	parent, _ := st.CreateScan(1, "p", "top")
	child, _ := st.CreateScan(1, "c", "top")
	if err := st.SetScanResumeOf(child, parent); err != nil {
		t.Fatal(err)
	}
	sc, _ := st.Scan(child)
	if sc.ResumeOf != parent {
		t.Fatalf("resume_of 应为 %d: %+v", parent, sc)
	}
}

func TestTargetStatusName(t *testing.T) {
	if TargetStatusName(TargetDone) != "已完成" || TargetStatusName(TargetPending) != "未开始" ||
		TargetStatusName(TargetRunning) != "扫描中" || TargetStatusName(TargetFailed) != "失败" {
		t.Fatal("状态标签错误")
	}
}
