package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeArtifactFile 写入指定大小的文件，供产物清理测试构造数据。
func writeArtifactFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("创建目录 %q 失败: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), size), 0o644); err != nil {
		t.Fatalf("写入文件 %q 失败: %v", path, err)
	}
}

// setArtifactModTime 调整目录修改时间，用于稳定“最近 N 个目录”的排序断言。
func setArtifactModTime(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatalf("设置 %q 修改时间失败: %v", path, err)
	}
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("路径 %q 应存在: %v", path, err)
	}
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("路径 %q 应已被清理，实际 err=%v", path, err)
	}
}

// TestParseScanArtifactDirNameStrict 验证只有 scan_<正整数> 会被纳入清理范围，
// data 根目录下的其他名字（certs、logs、easm.db 所在目录名等）必须全部跳过。
func TestParseScanArtifactDirNameStrict(t *testing.T) {
	accepted := map[string]int64{"scan_1": 1, "scan_42": 42, "scan_1000": 1000}
	for name, want := range accepted {
		id, ok := parseScanArtifactDirName(name)
		if !ok || id != want {
			t.Fatalf("%q 应被识别为扫描产物目录，得到 (%d, %v)", name, id, ok)
		}
	}
	rejected := []string{"scan_", "scan_0", "scan_abc", "scan_-3", "scan_1x", "certs", "logs", "backup", "easm.db", "scan"}
	for _, name := range rejected {
		if id, ok := parseScanArtifactDirName(name); ok {
			t.Fatalf("%q 不应被识别为扫描产物目录，却得到 id=%d", name, id)
		}
	}
}

// TestIsScanArtifactFileName 验证只认定 batch_*.out 与 batch_*_targets.txt 两类平台产物。
func TestIsScanArtifactFileName(t *testing.T) {
	artifacts := []string{"batch_0001.out", "batch_0001_targets.txt", "batch_x.out"}
	for _, name := range artifacts {
		if !isScanArtifactFileName(name) {
			t.Fatalf("%q 应被视为平台产物文件", name)
		}
	}
	others := []string{"notes.txt", "batch_0001.log", "batch_0001_targets", "batch_.tmp", "targets.txt", "easm.db"}
	for _, name := range others {
		if isScanArtifactFileName(name) {
			t.Fatalf("%q 不应被视为平台产物文件（用户数据必须保留）", name)
		}
	}
}

// TestPruneScanArtifactsProtectsUserDataAndCurrentScan 验证清理只删除旧执行目录里的批次文件：
// data 根目录的业务库、证书/日志目录保持原样；当前执行目录与其内用户文件一律不动。
func TestPruneScanArtifactsProtectsUserDataAndCurrentScan(t *testing.T) {
	root := t.TempDir()
	base := time.Now().Add(-24 * time.Hour)

	// 用户既有业务数据：数据库、证书、日志。
	writeArtifactFile(t, filepath.Join(root, "easm.db"), 4096)
	writeArtifactFile(t, filepath.Join(root, "certs", "server.pem"), 128)
	writeArtifactFile(t, filepath.Join(root, "logs", "app.log"), 128)

	oldDir := filepath.Join(root, "scan_1")
	writeArtifactFile(t, filepath.Join(oldDir, "batch_0001.out"), 2048)
	writeArtifactFile(t, filepath.Join(oldDir, "batch_0001_targets.txt"), 64)

	midDir := filepath.Join(root, "scan_2")
	writeArtifactFile(t, filepath.Join(midDir, "batch_0001.out"), 2048)

	currentDir := filepath.Join(root, "scan_3")
	writeArtifactFile(t, filepath.Join(currentDir, "batch_0001.out"), 4096)
	writeArtifactFile(t, filepath.Join(currentDir, "batch_0001_targets.txt"), 64)
	writeArtifactFile(t, filepath.Join(currentDir, "notes.txt"), 32)

	setArtifactModTime(t, oldDir, base.Add(-2*time.Hour))
	setArtifactModTime(t, midDir, base.Add(-time.Hour))
	setArtifactModTime(t, currentDir, base)

	// 预算 1 字节、保留 1 个目录：受保护的只有当前执行目录。
	stats, err := pruneScanArtifactsWith(root, 3, 1, 1)
	if err != nil {
		t.Fatalf("清理扫描产物失败: %v", err)
	}
	if stats.RemovedFiles == 0 || stats.FreedBytes == 0 {
		t.Fatalf("超出预算时应删除旧批次文件，实际 %s", scanArtifactSummary(stats))
	}
	mustNotExist(t, oldDir)
	mustNotExist(t, midDir)

	// 当前执行目录完全保留。
	mustExist(t, filepath.Join(currentDir, "batch_0001.out"))
	mustExist(t, filepath.Join(currentDir, "batch_0001_targets.txt"))
	mustExist(t, filepath.Join(currentDir, "notes.txt"))

	// 用户既有业务数据一个都不能少。
	mustExist(t, filepath.Join(root, "easm.db"))
	mustExist(t, filepath.Join(root, "certs", "server.pem"))
	mustExist(t, filepath.Join(root, "logs", "app.log"))
}

// TestPruneScanArtifactsKeepsRecentDirsEvenOverBudget 验证“保留最近 N 个目录”优先于容量预算。
func TestPruneScanArtifactsKeepsRecentDirsEvenOverBudget(t *testing.T) {
	root := t.TempDir()
	base := time.Now().Add(-24 * time.Hour)

	for index := 1; index <= 4; index++ {
		dir := filepath.Join(root, "scan_"+string(rune('0'+index)))
		writeArtifactFile(t, filepath.Join(dir, "batch_0001.out"), 1024)
		setArtifactModTime(t, dir, base.Add(time.Duration(index)*time.Minute))
	}

	// keepRecent=3：scan_2/scan_3/scan_4 受保护，只有最旧的 scan_1 可清理。
	stats, err := pruneScanArtifactsWith(root, 0, 1, 3)
	if err != nil {
		t.Fatalf("清理扫描产物失败: %v", err)
	}
	if stats.RemovedDirs != 1 || stats.RemovedFiles != 1 {
		t.Fatalf("应只清理 1 个最旧目录，实际 %s", scanArtifactSummary(stats))
	}
	mustNotExist(t, filepath.Join(root, "scan_1"))
	for _, name := range []string{"scan_2", "scan_3", "scan_4"} {
		mustExist(t, filepath.Join(root, name, "batch_0001.out"))
	}
}

// TestPruneScanArtifactsSkipsNonArtifactEntries 验证不会被误删的三类内容：
// 非 scan_<数字> 目录、目录内的用户文件、以及不是 batch_* 产物命名的文件。
func TestPruneScanArtifactsSkipsNonArtifactEntries(t *testing.T) {
	root := t.TempDir()
	base := time.Now().Add(-24 * time.Hour)

	// 非 scan_<数字> 目录：即使内部文件名形似产物也不得进入清理流程。
	backupDir := filepath.Join(root, "backup")
	writeArtifactFile(t, filepath.Join(backupDir, "batch_0001.out"), 1024)
	setArtifactModTime(t, backupDir, base.Add(-2*time.Hour))

	// scan_7 内只有用户文件：目录非空，必须整体保留。
	userDir := filepath.Join(root, "scan_7")
	writeArtifactFile(t, filepath.Join(userDir, "notes.txt"), 32)
	writeArtifactFile(t, filepath.Join(userDir, "batch_0001.log"), 32)
	setArtifactModTime(t, userDir, base.Add(-time.Hour))

	// 当前执行目录提供超预算基数，迫使清理流程真的走一遍。
	currentDir := filepath.Join(root, "scan_8")
	writeArtifactFile(t, filepath.Join(currentDir, "batch_0001.out"), 4096)
	setArtifactModTime(t, currentDir, base)

	stats, err := pruneScanArtifactsWith(root, 8, 0, 0)
	if err != nil {
		t.Fatalf("清理扫描产物失败: %v", err)
	}
	if stats.RemovedFiles != 0 {
		t.Fatalf("没有任何可清理的批次文件，实际 %s", scanArtifactSummary(stats))
	}
	mustExist(t, filepath.Join(backupDir, "batch_0001.out"))
	mustExist(t, filepath.Join(userDir, "notes.txt"))
	mustExist(t, filepath.Join(userDir, "batch_0001.log"))
	mustExist(t, filepath.Join(currentDir, "batch_0001.out"))
}

// TestPruneScanArtifactsWithinBudgetDoesNothing 验证预算充足时不删除任何产物，
// 也验证缺失目录（首次启动）不会报错。
func TestPruneScanArtifactsWithinBudgetDoesNothing(t *testing.T) {
	root := t.TempDir()
	base := time.Now().Add(-24 * time.Hour)

	for index := 1; index <= 3; index++ {
		dir := filepath.Join(root, "scan_"+string(rune('0'+index)))
		writeArtifactFile(t, filepath.Join(dir, "batch_0001.out"), 1024)
		setArtifactModTime(t, dir, base.Add(time.Duration(index)*time.Minute))
	}

	stats, err := pruneScanArtifactsWith(root, 3, 1<<20, 0)
	if err != nil {
		t.Fatalf("清理扫描产物失败: %v", err)
	}
	if stats.RemovedDirs != 0 || stats.RemovedFiles != 0 || stats.FreedBytes != 0 {
		t.Fatalf("预算充足时不应清理任何产物，实际 %s", scanArtifactSummary(stats))
	}
	for _, name := range []string{"scan_1", "scan_2", "scan_3"} {
		mustExist(t, filepath.Join(root, name, "batch_0001.out"))
	}

	missingRoot := filepath.Join(t.TempDir(), "not-created-yet")
	stats, err = pruneScanArtifactsWith(missingRoot, 1, 0, 0)
	if err != nil {
		t.Fatalf("产物根目录不存在时应返回 nil 错误: %v", err)
	}
	if stats != (artifactPruneStats{}) {
		t.Fatalf("根目录不存在时应无任何清理动作，实际 %s", scanArtifactSummary(stats))
	}
}

// TestPruneScanArtifactsCountsAllDirsAndOnlyProtectsRetainedSet 是
// “受保护 1 MiB + 旧 3 MiB + 预算 2 MiB”回归：
//   - 总量必须统计所有 scan_<id> 目录（4 MiB），因此旧的 3 MiB 必须被清理；
//     旧实现只累加受保护目录（1 MiB ≤ 预算）而永不清理，会让旧产物无界堆积；
//   - 受保护目录只决定“不许删”，即使它自己超过预算也不能动。
func TestPruneScanArtifactsCountsAllDirsAndOnlyProtectsRetainedSet(t *testing.T) {
	root := t.TempDir()
	base := time.Now().Add(-24 * time.Hour)

	protectedDir := filepath.Join(root, "scan_2")
	writeArtifactFile(t, filepath.Join(protectedDir, "batch_0001.out"), 1<<20)
	oldDir := filepath.Join(root, "scan_1")
	writeArtifactFile(t, filepath.Join(oldDir, "batch_0001.out"), 3<<20)
	setArtifactModTime(t, oldDir, base.Add(-2*time.Hour))
	setArtifactModTime(t, protectedDir, base)

	// 预算 2 MiB、保留最近 1 个目录：scan_2 受保护，总量 4 MiB 超预算，只能清理 scan_1 的 3 MiB。
	stats, err := pruneScanArtifactsWith(root, 2, 2<<20, 1)
	if err != nil {
		t.Fatalf("清理扫描产物失败: %v", err)
	}
	if stats.FreedBytes != 3<<20 {
		t.Fatalf("释放字节=%d，期望 %d（总量必须统计受保护 1 MiB + 旧 3 MiB）", stats.FreedBytes, 3<<20)
	}
	if stats.RemovedFiles != 1 || stats.RemovedDirs != 1 {
		t.Fatalf("应只清理旧目录的 1 个批次文件与其空目录，实际 %s", scanArtifactSummary(stats))
	}
	mustExist(t, filepath.Join(protectedDir, "batch_0001.out"))
	mustNotExist(t, oldDir)

	// 预算降到 0：受保护目录即使自己超预算也不得被删除（保护集合是唯一豁免）。
	stats, err = pruneScanArtifactsWith(root, 2, 0, 1)
	if err != nil {
		t.Fatalf("清理扫描产物失败: %v", err)
	}
	if stats.RemovedFiles != 0 || stats.FreedBytes != 0 {
		t.Fatalf("受保护目录不得因预算为 0 被删除，实际 %s", scanArtifactSummary(stats))
	}
	mustExist(t, filepath.Join(protectedDir, "batch_0001.out"))
}

// TestPathWithinBase 验证越界路径判断，保证删除动作绝不离开预期目录。
func TestPathWithinBase(t *testing.T) {
	base := t.TempDir()
	if !pathWithinBase(base, filepath.Join(base, "batch_0001.out")) {
		t.Fatal("同目录下的文件应判定为不越界")
	}
	if !pathWithinBase(base, filepath.Join(base, "sub", "batch_0001.out")) {
		t.Fatal("子目录下的文件应判定为不越界")
	}
	if pathWithinBase(base, filepath.Join(base, "..", "easm.db")) {
		t.Fatal("父目录中的文件必须判定为越界")
	}
	if pathWithinBase(base, filepath.Dir(base)) {
		t.Fatal("目录自身之外必须判定为越界")
	}
}
