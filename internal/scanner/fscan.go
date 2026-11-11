package scanner

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"easm-platform/internal/store"
)

// 本文件封装 fscan 多工具并行扫描引擎（与 naabu 并列，默认不启用，向后兼容）。
// 支持三种子模式：port（纯端口，默认）、vuln（高危 PoC）、mixed（端口+漏洞）。
// fscan 输出约定「IP:Port Service [Vulnerability]」，兼容 [+] / [*] 前缀。
// 端口/服务复用 store.InsertResults 入库；漏洞明细写入附加表 scan_vulns。

// fscan 单目标耗时区间（容量估算），fscan 内部多线程并行，总耗时按线程数摊薄。
const (
	// 纯端口模式单目标约 1-2 分钟。
	fscanPortPerTargetMin = 1 * time.Minute
	fscanPortPerTargetMax = 2 * time.Minute
	// 漏洞/混合模式单目标约 5-10 分钟。
	fscanPerTargetMin = 5 * time.Minute
	fscanPerTargetMax = 10 * time.Minute
	// fscanDefaultWorkers 是 fscan 内部并发线程默认值（-t）。
	fscanDefaultWorkers = 100
	// fscanVersionTimeout 是 fscan 自检（-h）的总时长上界。
	fscanVersionTimeout = 10 * time.Second
	// fscanFullPorts 是未填写自定义端口时的默认全端口探测策略。
	fscanFullPorts = "1-65535"
)

// fscan 子模式。
const (
	FscanModePort  = "port"
	FscanModeVuln  = "vuln"
	FscanModeMixed = "mixed"
)

// normalizeFscanMode 归一化子模式，空/非法回退默认纯端口。
func normalizeFscanMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case FscanModeVuln:
		return FscanModeVuln
	case FscanModeMixed:
		return FscanModeMixed
	default:
		return FscanModePort
	}
}

// engineIsFscan 报告任务引擎是否为 fscan 系列（含旧 mixed 别名）。
func engineIsFscan(engine string) bool {
	switch engine {
	case "fscan", "fscan-vuln", "fscan-mixed", "mixed":
		return true
	}
	return false
}

// engineFscanMode 从引擎值推导 fscan 子模式。
func engineFscanMode(engine string) string {
	switch engine {
	case "fscan-vuln":
		return FscanModeVuln
	case "fscan-mixed", "mixed":
		return FscanModeMixed
	default:
		return FscanModePort
	}
}

// fscanModeLabel 返回子模式中文标签，用于任务/子扫描命名。
func fscanModeLabel(mode string) string {
	switch normalizeFscanMode(mode) {
	case FscanModeVuln:
		return "漏洞检测"
	case FscanModeMixed:
		return "混合"
	default:
		return "纯端口"
	}
}

// FscanSettings 是 fscan 引擎的可配置项（从 settings 表读取）。
type FscanSettings struct {
	Path        string
	Workers     int
	Mode        string // port | vuln | mixed；空时回退 VulnScan 兼容旧配置
	VulnScan    bool   // 旧配置兼容字段（fscan_vuln），Mode 非空时以 Mode 为准
	CustomPorts string // 自定义端口（同 naabu 格式），空则全端口
	Timeout     time.Duration
}

// vulnEnabled 报告是否启用高危 PoC 漏洞检测。
func (s FscanSettings) vulnEnabled() bool {
	if s.Mode != "" {
		return normalizeFscanMode(s.Mode) != FscanModePort
	}
	return s.VulnScan
}

// fscanSettings 读取 fscan 配置，未配置时回退默认值（默认纯端口）。
func (r *Runner) fscanSettings() FscanSettings {
	workers, _ := strconv.Atoi(r.setting("fscan_workers", strconv.Itoa(fscanDefaultWorkers)))
	if workers < 1 {
		workers = fscanDefaultWorkers
	}
	mode := r.setting("fscan_mode", "")
	if mode == "" {
		// 兼容旧 fscan_vuln 开关：显式开启→vuln，否则默认纯端口。
		if r.setting("fscan_vuln", "0") == "1" {
			mode = FscanModeVuln
		} else {
			mode = FscanModePort
		}
	}
	return FscanSettings{
		Path:    r.setting("fscan_path", "fscan"),
		Workers: workers,
		Mode:    normalizeFscanMode(mode),
		Timeout: settingsOverallTimeout(r),
	}
}

func settingsOverallTimeout(r *Runner) time.Duration {
	mins, _ := strconv.Atoi(r.setting("scan_timeout_min", "0"))
	if mins <= 0 {
		return 0 // 0 = 不限制（默认）
	}
	return time.Duration(mins) * time.Minute
}

// fscanArgs 构造 fscan 1.8.x 命令行：-hf 目标文件 -o 输出 -t 线程 -p 端口。
// 注意：fscan 的 -h 是单个主机/网段（不能传文件），目标文件必须用 -hf；
// -nobr 关闭弱口令爆破；纯端口模式追加 -nopoc/-noredis 关闭 PoC 与 Redis 未授权检测。
// -np 在 fscan 中表示「跳过 ping 主机发现」，与 PoC 无关，不能用于关闭漏洞检测。
func fscanArgs(targetsFile, outFile string, s FscanSettings) []string {
	ports := strings.TrimSpace(s.CustomPorts)
	if ports == "" {
		ports = fscanFullPorts
	}
	args := []string{"-hf", targetsFile, "-o", outFile, "-t", strconv.Itoa(s.Workers), "-p", ports, "-nobr"}
	if !s.vulnEnabled() {
		args = append(args, "-nopoc", "-noredis")
	}
	return args
}

// fscanOutputDetail 截取输出尾部用于错误提示，避免把整屏 banner/进度写入数据库。
func fscanOutputDetail(text string, limit int) string {
	text = strings.TrimSpace(text)
	if text == "" || limit <= 0 {
		return text
	}
	if len(text) > limit {
		text = "…" + text[len(text)-limit:]
	}
	return text
}

// fscanErrorDetail 拼接失败原因与实际输出（含 stderr/stdout 尾部），避免只剩「exit status 2」。
func fscanErrorDetail(runErr error, stdout, stderr string) string {
	msg := fmt.Sprintf("fscan 执行失败：%v", runErr)
	if s := fscanOutputDetail(stderr, 1200); s != "" {
		msg += "\n错误输出：\n" + s
	}
	if s := fscanOutputDetail(stdout, 1200); s != "" {
		msg += "\n标准输出：\n" + s
	}
	return msg
}

// checkFscan 自检 fscan 可执行文件（执行 -h），返回路径或错误。
// fscan 1.8.x 的 -h 是字符串参数，单独执行必然以 usage（exit 2）结束，
// 因此以「能输出 fscan/Usage 文本」为自检通过，并识别非 fscan 可执行文件或架构不匹配。
func checkFscan(path string) (string, error) {
	resolved, err := exec.LookPath(path)
	if err != nil {
		return "", fmt.Errorf("fscan 路径不可用：%q（%v）；请在系统设置填写绝对路径或安装 fscan", path, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), fscanVersionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolved, "-h")
	out := newTailBuffer(64 * 1024)
	cmd.Stdout = out
	cmd.Stderr = out
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return resolved, fmt.Errorf("fscan 自检超过 %s 已终止（路径 %q）", fscanVersionTimeout, resolved)
	}
	text := out.String()
	low := strings.ToLower(text)
	// -h 缺少参数时 Go flag 会输出 usage 并以 2 退出，属预期行为。
	usageErr := strings.Contains(low, "usage") || strings.Contains(low, "flag")
	if runErr != nil && !usageErr {
		return resolved, fmt.Errorf("fscan 自检失败：%v；输出：%s", runErr, fscanOutputDetail(text, 400))
	}
	if !strings.Contains(low, "fscan") && !usageErr {
		return resolved, fmt.Errorf("fscan 自检输出异常（可能不是 fscan 可执行文件）：%s", fscanOutputDetail(text, 400))
	}
	return resolved, nil
}

// severityForVuln 依据漏洞名称判定严重级（high/mid/low）。
func severityForVuln(vuln string) string {
	v := strings.ToLower(vuln)
	if v == "" {
		return "low"
	}
	for _, sig := range []string{
		"smbghost", "cve-2020-0796", "ms17-010", "cve-2017-0144", "eternalblue",
		"struts2", "cve-2017-5638", "log4j", "cve-2021-44228", "shiro", "cve-2016-4437",
		"weblogic", "cve-2020-14882", "thinkphp", "rce", "deserialization", "unauthorized",
	} {
		if strings.Contains(v, sig) {
			return "high"
		}
	}
	return "mid"
}

// parseFscanOutput 解析一行 fscan 输出为 store.Result（含 Vuln）。
// 纯端口模式输出「IP:Port Service」，漏洞模式追加漏洞名称。
func parseFscanOutput(line string) (store.Result, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return store.Result{}, false
	}
	if strings.HasPrefix(line, "[") {
		if end := strings.Index(line, "]"); end >= 0 && end <= 3 {
			line = strings.TrimSpace(line[end+1:])
		}
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return store.Result{}, false
	}
	host, port, ok := splitTextHostPort(fields[0])
	if !ok {
		return store.Result{}, false
	}
	ip, ipOK := normalizeIP(host)
	if !ipOK {
		return store.Result{}, false
	}
	res := store.Result{IP: ip, Port: port, Proto: "tcp", Status: 1}
	rest := fields[1:]
	if len(rest) > 0 {
		service := rest[0]
		if strings.EqualFold(service, "open") {
			service = ""
		}
		res.Service = service
	}
	if len(rest) > 1 {
		res.Vuln = strings.Join(rest[1:], " ")
	}
	return res, true
}

// estimateFscanDuration 估算 fscan 总耗时：目标数×单目标时间/内部线程数 + 启动开销。
// mode 可选（port/vuln/mixed），缺省按漏洞模式（兼容旧调用）；纯端口按 1-2 分钟/目标。
func estimateFscanDuration(targets, workers int, mode ...string) time.Duration {
	if targets <= 0 {
		return 0
	}
	if workers < 1 {
		workers = 1
	}
	m := FscanModeVuln
	if len(mode) > 0 {
		m = normalizeFscanMode(mode[0])
	}
	perTarget := (fscanPerTargetMin + fscanPerTargetMax) / 2
	if m == FscanModePort {
		perTarget = (fscanPortPerTargetMin + fscanPortPerTargetMax) / 2
	}
	total := time.Duration(targets) * perTarget / time.Duration(workers)
	return total + capacityStartupOverhead
}

// startFscanTask 完成 fscan 自检与容量预检后启动执行（超阈值自动拆分）。
func (r *Runner) startFscanTask(scanID int64, specs []store.TargetSpec, fs FscanSettings, customPorts string) (int64, error) {
	resolved, err := checkFscan(fs.Path)
	if err != nil {
		r.fail(scanID, err)
		r.setRunning(false)
		return scanID, err
	}
	fs.Path = resolved
	fs.CustomPorts = customPorts

	estimated := estimateFscanDuration(len(specs), fs.Workers, fs.Mode)
	if fs.Timeout > 0 && estimated > fs.Timeout && len(specs) > capacitySmallBatchSpecs {
		// 超阈值且超超时：尝试自动拆分（复用 runSplitTask/runSubTask）。
		if r.shouldAutoSplit() && len(specs) > r.getSplitBatchSize() {
			return r.startFscanSplitTask(scanID, specs, fs)
		}
		err := fmt.Errorf("fscan 容量预检未通过：%d 个目标（%s）按内部线程 %d 预计约 %s，超过任务超时 %s；请提高超时或减少目标数量",
			len(specs), fscanModeLabel(fs.Mode), fs.Workers, estimated.Round(time.Second), fs.Timeout)
		r.fail(scanID, err)
		r.setRunning(false)
		return scanID, err
	}
	_ = r.st.AddScanEvent(scanID, "info", "capacity", fmt.Sprintf("fscan 容量预检：%d 个目标（%s），内部线程 %d，预计耗时 %s，任务超时 %s",
		len(specs), fscanModeLabel(fs.Mode), fs.Workers, estimated.Round(time.Second), fs.Timeout))
	_ = r.st.AddScanEvent(scanID, "info", "engine", "fscan")

	// 目标数超过小批量阈值但未超超时：仍拆分以控制单批规模（可选）。
	if len(specs) > capacitySmallBatchSpecs && r.shouldAutoSplit() && len(specs) > r.getSplitBatchSize() {
		return r.startFscanSplitTask(scanID, specs, fs)
	}

	go r.runFscanScan(scanID, specs, fs)
	return scanID, nil
}

// startFscanSplitTask 创建拆分子任务并启动 runSplitTask（fscan 引擎）。
func (r *Runner) startFscanSplitTask(scanID int64, specs []store.TargetSpec, fs FscanSettings) (int64, error) {
	batchSize := r.getSplitBatchSize()
	batches := CalculateSplitBatches(specs, batchSize)
	if len(batches) == 0 {
		return scanID, fmt.Errorf("拆分批次计算结果为空")
	}
	// 主扫描标记为拆分（复用 scans 拆分字段）。
	if err := r.st.MarkScanSplit(scanID, len(batches)); err != nil {
		log.Printf("扫描 %d 标记拆分失败: %v", scanID, err)
	}
	// 主扫描名称追加 [自动拆分] 后缀，子任务沿用该名称格式。
	if parent, err := r.st.Scan(scanID); err == nil && parent != nil && !strings.Contains(parent.Name, "[自动拆分]") {
		_ = r.st.UpdateScanName(scanID, parent.Name+" [自动拆分]")
	}
	specsJSON := make([]string, len(batches))
	for i, b := range batches {
		specsJSON[i] = EncodeSpecsJSON(b)
	}
	if err := r.st.CreateSubTasks(scanID, specsJSON); err != nil {
		r.fail(scanID, fmt.Errorf("创建子任务记录失败: %v", err))
		r.setRunning(false)
		return scanID, err
	}
	_ = r.st.AddScanEvent(scanID, "info", "split", fmt.Sprintf("fscan 自动拆分为 %d 个子任务（每批最多 %d 个目标，%s）", len(batches), batchSize, fscanModeLabel(fs.Mode)))
	go r.runSplitTask(scanID, batches, "top", fs.CustomPorts, NaabuSettings{}, "fscan", fs)
	return scanID, nil
}

// runFscanScan 非拆分 fscan 执行：核心执行 + 收尾告警与汇总。
func (r *Runner) runFscanScan(scanID int64, specs []store.TargetSpec, fs FscanSettings) {
	defer r.setRunning(false)
	defer func() {
		if rec := recover(); rec != nil {
			_ = r.st.ForceStopScanIfActive(scanID, fmt.Sprintf("fscan 进程异常（panic）：%v；已保留入库结果。", rec))
		}
	}()
	openPorts, _ := r.execFscan(scanID, specs, fs)
	var newAlerts []store.Alert
	scan, _ := r.st.Scan(scanID)
	if scan != nil && (scan.Status == "done" || scan.Status == "stopped") {
		newAlerts = r.eng.AfterScan(scanID)
	}
	status := "done"
	if scan != nil {
		status = scan.Status
	}
	_ = openPorts
	// 网络不可达告警独立于端口告警，不受终态门禁（与 executeScan 收尾一致）。
	r.eng.ProcessUnreachable(scanID)
	r.eng.NotifyScanSummary(scanID, status, newAlerts)
}

// runFscanBatch 拆分子任务的 fscan 执行：只做核心执行与子扫描收尾，不生成告警/汇总（由主任务聚合后统一）。
func (r *Runner) runFscanBatch(subScanID int64, specs []store.TargetSpec, fs FscanSettings) (int, error) {
	return r.execFscan(subScanID, specs, fs)
}

// execFscan 核心执行：写目标→运行→解析→入库端口/漏洞→子扫描收尾，返回开放端口数。
func (r *Runner) execFscan(scanID int64, specs []store.TargetSpec, fs FscanSettings) (int, error) {
	dataDir := filepath.Join("data", fmt.Sprintf("scan_%d", scanID))
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		r.fail(scanID, fmt.Errorf("创建扫描数据目录失败：%v", err))
		return 0, err
	}
	targetsFile := filepath.Join(dataDir, "fscan_targets.txt")
	outFile := filepath.Join(dataDir, "fscan.out")
	// fscan 对域名的支持依赖系统 DNS，且结果以域名作为 host 输出、平台解析器只接受 IP；
	// 因此在平台侧先解析为 IPv4 再写入目标文件，保证域名目标能真正扫描并入结果库。
	effective, failedDomains := r.resolveFscanDomainTargets(scanID, specs)
	if len(effective) == 0 {
		err := fmt.Errorf("fscan 未执行：目标域名均解析不到可扫描的 IPv4 地址，请检查 DNS 或改用 IP 目标")
		r.fail(scanID, err)
		return 0, err
	}
	if err := writeTargets(targetsFile, effective); err != nil {
		r.fail(scanID, fmt.Errorf("写入目标文件失败：%v", err))
		return 0, err
	}
	if err := r.st.StartScanExecution(scanID, len(specs), 1); err != nil {
		r.fail(scanID, err)
		return 0, err
	}
	_ = r.st.InitTargetStatus(scanID, specs, len(specs))
	_ = r.st.MarkBatchTargetStatus(scanID, 0, store.TargetRunning)

	args := fscanArgs(targetsFile, outFile, fs)
	commandText := fs.Path + " " + strings.Join(args, " ")
	_ = r.st.UpdateScanProgress(scanID, 0, 0, 1, 0, commandText)

	ctx := context.Background()
	cancel := func() {}
	if fs.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, fs.Timeout)
	}
	defer cancel()
	cmd := exec.CommandContext(ctx, fs.Path, args...)
	cmd.Cancel = func() error { return killProcess(cmd) }
	cmd.WaitDelay = pipeWaitDelay
	// 保留有界 stdout/stderr：fscan 参数错误只打印到控制台，必须回传到执行记录。
	stdout := newTailBuffer(64 * 1024)
	stderr := newTailBuffer(64 * 1024)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	runErr := cmd.Run()

	results, vulns := collectFscanResults(outFile)
	if len(results) > 0 {
		if _, err := r.st.InsertResultsBatch(scanID, results); err != nil {
			_ = r.st.AddScanEvent(scanID, "error", "store", fmt.Sprintf("fscan 结果入库失败：%v", err))
		}
	}
	// 仅漏洞/混合模式写入 scan_vulns；纯端口模式不产生漏洞明细。
	if fs.vulnEnabled() && len(vulns) > 0 {
		if _, err := r.st.InsertVulns(scanID, vulns); err != nil {
			_ = r.st.AddScanEvent(scanID, "error", "store", fmt.Sprintf("fscan 漏洞入库失败：%v", err))
		}
	}

	status := "done"
	message := fmt.Sprintf("fscan（%s）完成，发现 %d 个开放端口、%d 条漏洞", fscanModeLabel(fs.Mode), len(results), len(vulns))
	domainNote := ""
	if len(failedDomains) > 0 {
		domainNote = fmt.Sprintf("；%d 个域名解析失败未扫描（fscan 仅支持 IPv4，详见执行事件）", len(failedDomains))
		message += domainNote
	}
	if r.isStopped(scanID) {
		status = "stopped"
		message = "fscan 已被停止。已基于已入库结果完成白名单比对与风险告警，结果可能因提前终止而不完整。"
	} else if runErr != nil && len(results) == 0 {
		status = "failed"
		message = fscanErrorDetail(runErr, stdout.String(), stderr.String())
	} else if runErr != nil {
		status = "partial"
		message = fmt.Sprintf("fscan 部分完成（%v），保留已发现结果%s", runErr, domainNote)
		if detail := fscanOutputDetail(stderr.String(), 600); detail != "" {
			message += "\n错误输出：\n" + detail
		}
	}
	// 有域名解析失败时不得虚报 done：已发现的 IP 结果保留，但本次目标范围并不完整。
	if status == "done" && len(failedDomains) > 0 {
		status = "partial"
	}
	_ = r.st.UpdateScanProgress(scanID, len(specs), 0, 1, len(results), commandText)
	if err := r.st.FinishScanStatus(scanID, status, len(results), message); err != nil {
		return len(results), err
	}
	// 记录目标规格终态：done→done，stopped→running（未完成），其余→failed。
	targetStatus := store.TargetFailed
	if status == "done" {
		targetStatus = store.TargetDone
	} else if status == "stopped" {
		targetStatus = store.TargetRunning
	}
	_ = r.st.MarkBatchTargetStatus(scanID, 0, targetStatus)
	return len(results), nil
}

// collectFscanResults 流式读取 fscan 输出文件，返回端口结果与漏洞明细（有界内存）。
func collectFscanResults(path string) ([]store.Result, []store.VulnRecord) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer file.Close()
	var results []store.Result
	var vulns []store.VulnRecord
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64*1024), outputScanBuffer)
	for sc.Scan() {
		res, ok := parseFscanOutput(sc.Text())
		if !ok {
			continue
		}
		results = append(results, res)
		if res.Vuln != "" {
			vulns = append(vulns, store.VulnRecord{
				IP: res.IP, Port: res.Port, Proto: res.Proto,
				Service: res.Service, Vuln: res.Vuln, Severity: severityForVuln(res.Vuln),
			})
		}
	}
	return results, vulns
}
