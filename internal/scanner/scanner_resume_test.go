package scanner

import (
	"runtime"
	"testing"
	"time"

	"easm-platform/internal/store"
)

// TestStartResumeIncremental 验证「继续扫描未完成节点」：只扫未完成规格、
// resume_of 关联父执行、父执行已完成结果保留（仅 unix，fake fscan）。
func TestStartResumeIncremental(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	r, st := newFscanRunner(t)
	script := writeFakeFscan(t, t.TempDir())
	_ = st.SetSetting("fscan_path", script)
	taskID, _ := st.CreateScanTask(store.ScanTask{Name: "续扫父", Mode: "top", Engine: "fscan", TargetType: "manual", IPs: "192.0.2.1\n192.0.2.2\n192.0.2.3"})
	parentID, _ := st.CreateScan(taskID, "父执行", "top")
	specs := []store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}, {Raw: "192.0.2.2", Kind: "ip"}, {Raw: "192.0.2.3", Kind: "ip"}}
	_ = st.InitTargetStatus(parentID, specs, 1)
	_ = st.MarkBatchTargetStatus(parentID, 0, store.TargetDone)   // 已完成
	_ = st.MarkBatchTargetStatus(parentID, 2, store.TargetFailed) // 失败→需续扫
	_ = st.FinishScanStatus(parentID, "stopped", 1, "用户终止")

	newID, err := r.StartResume(parentID)
	if err != nil || newID <= 0 {
		t.Fatalf("StartResume 应成功: newID=%d err=%v", newID, err)
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		sc, _ := st.Scan(newID)
		if sc != nil && sc.Status != "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	ns, _ := st.Scan(newID)
	if ns == nil || ns.Status != "done" {
		t.Fatalf("续扫应完成: %+v", ns)
	}
	if ns.ResumeOf != parentID {
		t.Fatalf("resume_of 应关联父执行: %+v", ns)
	}
	if ns.TargetCount != 2 {
		t.Fatalf("续扫应只含 2 个未完成目标: %d", ns.TargetCount)
	}
	// 父执行状态与已完成规格保留。
	ps, _ := st.Scan(parentID)
	if ps.Status != "stopped" {
		t.Fatalf("父执行应保持 stopped: %s", ps.Status)
	}
	pd, _, _, _, _ := st.TargetStatusCounts(parentID)
	if pd != 1 {
		t.Fatalf("父执行已完成规格应保留 1: %d", pd)
	}
}

func TestStartResumeRejectsNoUnfinished(t *testing.T) {
	r, st := newFscanRunner(t)
	parentID, _ := st.CreateScan(0, "全完成", "top")
	_ = st.InitTargetStatus(parentID, []store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}}, 1)
	_ = st.MarkBatchTargetStatus(parentID, 0, store.TargetDone)
	_ = st.FinishScanStatus(parentID, "done", 1, "")
	if _, err := r.StartResume(parentID); err == nil {
		t.Fatal("无未完成目标应拒绝续扫")
	}
}

func TestStartResumeRejectsRunning(t *testing.T) {
	r, st := newFscanRunner(t)
	parentID, _ := st.CreateScan(0, "运行中", "top")
	// 保持 running 状态。
	if _, err := r.StartResume(parentID); err == nil {
		t.Fatal("运行中执行应拒绝续扫")
	}
}
