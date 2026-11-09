package scanner

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 扫描产物（data/scan_<id>/batch_*）的保留策略：
//   - 只清理平台自己生成的固定文件名，绝不触碰用户业务数据（easm.db、证书、日志等）；
//   - 保留最近 keepRecent 个执行目录与当前执行目录；
//   - 其余目录按“保留最近 + 总容量预算”双重约束清理。
const (
	// scanArtifactBudgetBytes 是扫描产物目录允许占用的默认总容量上限（2 GiB）。
	scanArtifactBudgetBytes int64 = 2 << 30
	// scanArtifactKeepRecent 是无论容量如何都保留的最近执行目录数量。
	scanArtifactKeepRecent = 10
)

// artifactPruneStats 记录一次产物清理的结果，便于日志与测试核对。
type artifactPruneStats struct {
	RemovedDirs  int
	RemovedFiles int
	FreedBytes   int64
	SkippedDirs  int
}

type scanArtifactDir struct {
	id      int64
	path    string
	modTime time.Time
	files   []scanArtifactFile
	size    int64
}

type scanArtifactFile struct {
	path string
	size int64
}

// pruneScanArtifacts 使用默认预算清理旧扫描产物；任何错误只记录日志，不影响扫描启动。
func pruneScanArtifacts(root string, currentScanID int64) {
	stats, err := pruneScanArtifactsWith(root, currentScanID, scanArtifactBudgetBytes, scanArtifactKeepRecent)
	if err != nil {
		log.Printf("清理旧扫描产物失败（不影响本次扫描）: %v", err)
		return
	}
	if stats.RemovedDirs > 0 || stats.RemovedFiles > 0 {
		log.Printf("已清理旧扫描产物：目录 %d 个、文件 %d 个，释放 %d KiB（当前执行 #%d 与最近 %d 个目录始终保留）",
			stats.RemovedDirs, stats.RemovedFiles, stats.FreedBytes/1024, currentScanID, scanArtifactKeepRecent)
	}
}

// pruneScanArtifactsWith 按显式预算执行清理，供测试注入小预算验证保护边界。
// 只处理 root 下形如 scan_<数字> 的目录，且只删除 batch_*.out / batch_*_targets.txt 两类文件。
func pruneScanArtifactsWith(root string, currentScanID int64, budget int64, keepRecent int) (artifactPruneStats, error) {
	var stats artifactPruneStats
	root = filepath.Clean(root)
	if root == "" || root == "." {
		root = "data"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return stats, nil
		}
		return stats, err
	}
	if keepRecent < 0 {
		keepRecent = 0
	}

	dirs := make([]scanArtifactDir, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			// 关键保护：data 根目录下的 easm.db、证书目录、日志目录等一律不进入清理流程。
			continue
		}
		id, ok := parseScanArtifactDirName(entry.Name())
		if !ok {
			stats.SkippedDirs++
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := entry.Info()
		if err != nil {
			stats.SkippedDirs++
			continue
		}
		artifact := scanArtifactDir{id: id, path: path, modTime: info.ModTime()}
		files, size, err := listScanArtifactFiles(path)
		if err != nil {
			stats.SkippedDirs++
			continue
		}
		artifact.files = files
		artifact.size = size
		dirs = append(dirs, artifact)
	}
	// 最近的目录排在前面；当前执行目录优先级最高。
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].modTime.After(dirs[j].modTime) })
	protected := map[int64]bool{currentScanID: true}
	for index := 0; index < len(dirs) && index < keepRecent; index++ {
		protected[dirs[index].id] = true
	}

	// 总量必须统计所有 scan_<数字> 目录的批次产物，而不只是受保护目录：
	// 旧实现只累加受保护目录，只要它们本身不超预算就永远不清理，
	// 导致大量旧目录的产物持续堆积（总量早已超预算却不会删除任何东西）。
	// 受保护集合只决定“哪些目录不许删”，不参与总量口径。
	total := int64(0)
	for _, dir := range dirs {
		total += dir.size
	}
	// countedDirs 记录已经计入 RemovedDirs 的目录，避免“删文件”和“删空目录”两步重复计数。
	countedDirs := make(map[string]bool, len(dirs))
	for index := len(dirs) - 1; index >= 0; index-- {
		dir := dirs[index]
		if protected[dir.id] {
			continue
		}
		overBudget := total > budget
		if !overBudget {
			break
		}
		freed, removed := removeScanArtifactFiles(dir, dir.path)
		stats.RemovedFiles += removed
		stats.FreedBytes += freed
		total -= freed
		if removed > 0 {
			stats.RemovedDirs++
			countedDirs[dir.path] = true
		}
	}

	for index := len(dirs) - 1; index >= 0; index-- {
		dir := dirs[index]
		if protected[dir.id] {
			continue
		}
		entries, err := os.ReadDir(dir.path)
		if err != nil {
			continue
		}
		if len(entries) == 0 {
			// 只删除本平台创建且已清空的 scan_<数字> 目录；非空目录（含用户放入的文件）保留。
			if err := os.Remove(dir.path); err == nil && !countedDirs[dir.path] {
				stats.RemovedDirs++
			}
		}
	}
	return stats, nil
}

// parseScanArtifactDirName 严格匹配 scan_<正整数>，其他名字（data/certs、data/logs 等）一律跳过。
func parseScanArtifactDirName(name string) (int64, bool) {
	if !strings.HasPrefix(name, "scan_") {
		return 0, false
	}
	value := strings.TrimPrefix(name, "scan_")
	if value == "" {
		return 0, false
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// listScanArtifactFiles 只统计本平台生成的批次文件，忽略任何其他用户文件。
func listScanArtifactFiles(dir string) ([]scanArtifactFile, int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	files := make([]scanArtifactFile, 0, len(entries))
	total := int64(0)
	for _, entry := range entries {
		if !isScanArtifactFileName(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			// 符号链接或非常规文件不纳入删除范围，避免越界删除。
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if !pathWithinBase(dir, path) {
			continue
		}
		files = append(files, scanArtifactFile{path: path, size: info.Size()})
		total += info.Size()
	}
	return files, total, nil
}

// removeScanArtifactFiles 删除目录内已确认属于本平台的批次文件，返回释放字节数与被删除数量。
func removeScanArtifactFiles(dir scanArtifactDir, fallbackDir string) (int64, int) {
	files := dir.files
	if files == nil {
		listed, _, err := listScanArtifactFiles(fallbackDir)
		if err != nil {
			return 0, 0
		}
		files = listed
	}
	var freed int64
	removed := 0
	for _, file := range files {
		if !pathWithinBase(fallbackDir, file.path) {
			continue
		}
		if err := os.Remove(file.path); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("删除旧扫描产物 %q 失败: %v", file.path, err)
			}
			continue
		}
		freed += file.size
		removed++
	}
	return freed, removed
}

func isScanArtifactFileName(name string) bool {
	if !strings.HasPrefix(name, "batch_") {
		return false
	}
	base := strings.TrimSuffix(name, ".out")
	if base != name {
		return true
	}
	return strings.HasSuffix(name, "_targets.txt")
}

// pathWithinBase 校验最终路径仍位于预期目录内，防止符号链接/相对路径越界。
func pathWithinBase(base, target string) bool {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

// scanArtifactSummary 用于测试与诊断输出。
func scanArtifactSummary(stats artifactPruneStats) string {
	return fmt.Sprintf("目录 %d、文件 %d、释放 %d 字节", stats.RemovedDirs, stats.RemovedFiles, stats.FreedBytes)
}
