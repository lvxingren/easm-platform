package scanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"easm-platform/internal/config"
	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

type Runner struct {
	st  *store.Store
	cfg *config.Config
	eng *engine.Engine

	mu      sync.Mutex
	running bool
	scanID  int64
	active  *executionControl
	// stateApplyMu 串行化控制状态转换与其状态落库（Pause/Resume/暂停自愈），
	// 防止迟到的落库覆盖用户刚写入的新状态。
	stateApplyMu sync.Mutex
}

func New(st *store.Store, cfg *config.Config, eng *engine.Engine) *Runner {
	return &Runner{st: st, cfg: cfg, eng: eng}
}

func (r *Runner) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

func (r *Runner) CurrentScanID() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scanID
}

// StartTask 运行一个扫描任务：按全部台账、资产标签或手工目标解析本次范围。
// 接受执行后立即创建记录，依赖、目标或配置检查失败也会留下失败详情。
// Web 手动触发与定时调度共用此入口；任何失败路径必须释放全局锁。
func (r *Runner) StartTask(taskID int64) (int64, error) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return 0, fmt.Errorf("已有扫描任务运行或暂停中，本次未启动；请等待当前任务结束后在执行记录中查看结果")
	}
	r.running = true
	r.mu.Unlock()

	task, err := r.st.ScanTask(taskID)
	if err != nil {
		r.setRunning(false)
		return 0, fmt.Errorf("读取扫描任务失败: %v", err)
	}
	if task == nil {
		r.setRunning(false)
		return 0, fmt.Errorf("任务不存在或已被删除，未创建执行记录")
	}

	mode := task.Mode
	if mode != "full" && mode != "custom" {
		mode = "top"
	}
	customPorts := strings.TrimSpace(task.CustomPorts)
	if mode == "custom" && customPorts == "" {
		r.setRunning(false)
		return 0, fmt.Errorf("自定义端口任务未配置端口范围，请编辑任务补充后再运行")
	}
	name := task.Name
	if name == "" {
		name = fmt.Sprintf("任务#%d", task.ID)
	}
	modeLabel := "常用端口top-1000"
	if mode == "full" {
		modeLabel = "全端口1-65535"
	} else if mode == "custom" {
		modeLabel = "自定义端口"
	}
	name = fmt.Sprintf("%s · %s · %s", name, modeLabel, time.Now().Format("20060102-150405"))
	scanID, err := r.st.CreateScan(task.ID, name, mode)
	if err != nil {
		r.setRunning(false)
		return 0, fmt.Errorf("创建执行记录失败: %v", err)
	}
	r.mu.Lock()
	r.scanID = scanID
	r.active = newExecutionControl()
	r.mu.Unlock()
	failStart := func(err error) (int64, error) {
		r.fail(scanID, err)
		r.setRunning(false)
		return scanID, err
	}

	// 记录本次计划已进入执行流程，避免配置错误时定时器每分钟重复补跑。
	if err := r.st.MarkScanTaskRun(task.ID); err != nil {
		return failStart(fmt.Errorf("更新任务最近执行时间失败: %v", err))
	}
	// 设置快照只读取一次：自检、容量预检与实际执行必须使用同一份设置，
	// 否则执行阶段重新读取可能拿到用户刚改过的值，导致 argv 与容量结论不一致。
	settings := r.naabuSettings()
	if _, _, err := r.checkNaabu(settings); err != nil {
		return failStart(err)
	}
	specs, err := r.resolveSpecs(task)
	if err != nil {
		return failStart(fmt.Errorf("解析扫描目标失败: %v", err))
	}
	if len(specs) == 0 {
		if task.TargetType == "tag" {
			return failStart(fmt.Errorf("目标为空：标签 %q 下没有资产，请调整标签或导入资产后重新执行", task.TargetTag))
		}
		return failStart(fmt.Errorf("目标为空：请先导入资产，或在任务中填写手工目标"))
	}

	if task.AddToLedger && task.TargetType == "manual" && strings.TrimSpace(task.IPs) != "" {
		if _, err := r.st.ImportTargets(specs, "", "任务导入"); err != nil {
			return failStart(fmt.Errorf("手工目标并入资产台账失败，扫描未启动: %v", err))
		}
	}

	// 容量预检：结合并发（1-16）、单进程速率、任务超时、FD 与磁盘预算给出可执行结论。
	// 默认 60 分钟对 500 个目标的全端口扫描必然被截断，这里直接拒绝而不是静默接受；
	// 平台不会自动改目标端口范围，只按预算收敛并发与每进程速率（多进程不得无界放大配置）。
	// 批次数按真实 specs 分批（每 scanBatchSize 条一批），不按展开出的地址数假定额外并行。
	plan, err := r.planScanCapacity(settings, mode, customPorts, specs)
	if err != nil {
		return failStart(fmt.Errorf("容量预检未通过，扫描未启动：%v", err))
	}
	if plan.Capped {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("目标展开数量达到容量估算上限 %d，实际扫描范围不变，但容量与耗时估算可能偏小", capacityTargetCap))
	}
	// 执行必须沿用容量计划生效的每进程速率：argv 的 -rate 就是 plan.PerRate，
	// 保证“并发 × 每进程速率 ≤ 平台总速率预算”的结论在执行时真实成立。
	settings.Rate = strconv.Itoa(plan.PerRate)

	go r.run(scanID, mode, customPorts, specs, settings, plan)
	return scanID, nil
}

// resolveSpecs 返回本次扫描目标，兼容旧任务：有手工 IP 的旧记录按 manual 处理。
func (r *Runner) resolveSpecs(task *store.ScanTask) ([]store.TargetSpec, error) {
	targetType := task.TargetType
	if targetType == "" {
		if strings.TrimSpace(task.IPs) != "" {
			targetType = "manual"
		} else {
			targetType = "all"
		}
	}
	if targetType == "tag" {
		if strings.TrimSpace(task.TargetTag) == "" {
			return nil, fmt.Errorf("标签任务未选择资产标签")
		}
		targets, err := r.st.TargetsByTag(task.TargetTag)
		if err != nil {
			return nil, err
		}
		specs := make([]store.TargetSpec, 0, len(targets))
		for _, t := range targets {
			specs = append(specs, store.TargetSpec{Raw: t.IP, Kind: t.Kind})
		}
		return specs, nil
	}
	raw := strings.TrimSpace(task.IPs)
	if targetType == "manual" {
		if raw == "" {
			return nil, fmt.Errorf("手工目标任务未填写 IP/网段/范围")
		}
		var specs []store.TargetSpec
		seen := map[string]bool{}
		fields := strings.FieldsFunc(raw, func(c rune) bool { return c == '\n' || c == '\r' || c == ',' })
		for _, line := range fields {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}
			kind, ok := engine.ClassifyTarget(line)
			if !ok {
				return nil, fmt.Errorf("任务 IP 非法: %s", line)
			}
			seen[line] = true
			specs = append(specs, store.TargetSpec{Raw: line, Kind: kind})
		}
		return specs, nil
	}
	targets, err := r.st.Targets()
	if err != nil {
		return nil, err
	}
	specs := make([]store.TargetSpec, 0, len(targets))
	for _, t := range targets {
		specs = append(specs, store.TargetSpec{Raw: t.IP, Kind: t.Kind})
	}
	return specs, nil
}

func (r *Runner) setRunning(v bool) {
	r.mu.Lock()
	r.running = v
	if !v {
		r.scanID = 0
		r.active = nil
	}
	r.mu.Unlock()
}

func (r *Runner) naabuPath() string {
	if v := r.st.Setting("naabu_path"); v != "" {
		return v
	}
	return r.cfg.NaabuPath
}

// NaabuSettings 是页面和扫描器共用的参数定义，字符串原样保存便于提示非法值。
type NaabuSettings struct {
	Path            string
	Rate            string
	Retries         string
	Workers         string
	ResponseTimeout string
	OverallTimeout  string
	Concurrency     string
	ScanType        string
	ExcludePorts    string
	Interface       string
	// TotalRate 是平台级总发包速率预算（所有并行 naabu 进程之和），空值取平台默认。
	// ProcessBudget 是平台级 naabu 进程并发预算上限，空值取平台默认。
	// 两者只用于容量预检收敛，不会改写用户配置的目标端口范围。
	TotalRate        string
	ProcessBudget    string
	Verify           bool
	ResourceMonitor  bool
	ResourceCPU      string
	ResourceMemory   string
	ResourceDuration string
}

func (r *Runner) setting(key, fallback string) string {
	if value := strings.TrimSpace(r.st.Setting(key)); value != "" {
		return value
	}
	return fallback
}

func (r *Runner) naabuSettings() NaabuSettings {
	return NaabuSettings{
		Path:             r.naabuPath(),
		Rate:             r.setting("naabu_rate", r.cfg.NaabuRate),
		Retries:          r.setting("naabu_retries", "2"),
		Workers:          r.setting("naabu_workers", "25"),
		ResponseTimeout:  r.setting("naabu_timeout", "1s"),
		OverallTimeout:   r.setting("scan_timeout_min", "60"),
		Concurrency:      r.setting("scan_concurrency", "3"),
		ScanType:         strings.ToLower(r.setting("naabu_scan_type", "c")),
		ExcludePorts:     r.setting("naabu_exclude_ports", ""),
		Interface:        r.setting("naabu_interface", ""),
		TotalRate:        r.setting("naabu_total_rate", strconv.Itoa(defaultTotalRate)),
		ProcessBudget:    r.setting("scan_process_budget", strconv.Itoa(defaultProcessBudget)),
		Verify:           r.st.Setting("naabu_verify") == "1",
		ResourceMonitor:  r.setting("resource_monitor", "1") == "1",
		ResourceCPU:      r.setting("resource_cpu_percent", "90"),
		ResourceMemory:   r.setting("resource_memory_mb", "1024"),
		ResourceDuration: r.setting("resource_duration_sec", "30"),
	}
}

func validateInteger(label, value string, min, max int) error {
	n, err := strconv.Atoi(value)
	if err != nil || n < min || n > max {
		return fmt.Errorf("%s必须是 %d-%d 的整数，当前值为 %q", label, min, max, value)
	}
	return nil
}

func validateExcludedPorts(value string) error {
	if value == "" {
		return nil
	}
	return ValidatePortList(value, "排除端口")
}

// ValidatePortList 校验 "22,80,443,8000-9000" 形式的端口列表（逗号分隔、支持范围）；
// label 用于错误提示。供排除端口与自定义端口扫描复用（web 层保存任务前也会调用）。
func ValidatePortList(value, label string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s不能为空", label)
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return fmt.Errorf("%s格式错误：存在空项；请使用 22,80,8000-9000 这样的格式", label)
		}
		bounds := strings.Split(item, "-")
		if len(bounds) > 2 || bounds[0] == "" {
			return fmt.Errorf("%s格式错误：%q；请使用 22,80,8000-9000 这样的格式", label, item)
		}
		start, err := strconv.Atoi(bounds[0])
		if err != nil || start < 1 || start > 65535 {
			return fmt.Errorf("%s %q 不是 1-65535 的有效端口", label, item)
		}
		if len(bounds) == 2 {
			end, err := strconv.Atoi(bounds[1])
			if err != nil || end < start || end > 65535 {
				return fmt.Errorf("%s范围 %q 无效，结束端口必须不小于开始端口且不超过 65535", label, item)
			}
		}
	}
	return nil
}

func (s NaabuSettings) Validate() error {
	if strings.TrimSpace(s.Path) == "" {
		return fmt.Errorf("naabu 路径不能为空")
	}
	checks := []struct {
		label    string
		value    string
		min, max int
	}{
		{"发包速率", s.Rate, 1, 1000000},
		{"重试次数", s.Retries, 0, 10},
		{"内部并发线程", s.Workers, 1, 1000},
		{"单次任务超时（分钟）", s.OverallTimeout, 1, 1440},
	}
	for _, check := range checks {
		if err := validateInteger(check.label, check.value, check.min, check.max); err != nil {
			return err
		}
	}
	if s.ResourceCPU != "" {
		if err := validateInteger("资源告警 CPU 阈值（%）", s.ResourceCPU, 1, 100); err != nil {
			return err
		}
	}
	if s.ResourceMemory != "" {
		if err := validateInteger("资源告警内存阈值（MiB）", s.ResourceMemory, 1, 1048576); err != nil {
			return err
		}
	}
	if s.ResourceDuration != "" {
		if err := validateInteger("资源告警持续时长（秒）", s.ResourceDuration, 5, 3600); err != nil {
			return err
		}
	}
	if s.Concurrency != "" {
		if err := validateInteger("扫描并发度（同时运行的 naabu 批次数）", s.Concurrency, 1, 16); err != nil {
			return err
		}
	}
	if s.TotalRate != "" {
		if err := validateInteger("平台总速率预算（/秒）", s.TotalRate, 1, 100000000); err != nil {
			return err
		}
	}
	if s.ProcessBudget != "" {
		if err := validateInteger("平台 naabu 进程并发预算", s.ProcessBudget, 1, 64); err != nil {
			return err
		}
	}
	responseTimeout, err := time.ParseDuration(s.ResponseTimeout)
	if err != nil || responseTimeout <= 0 || responseTimeout > 10*time.Minute {
		return fmt.Errorf("响应等待时间格式错误：%q；请使用 500ms、1s、2s 等时长，且不超过 10m", s.ResponseTimeout)
	}
	if s.ScanType != "c" && s.ScanType != "s" {
		return fmt.Errorf("扫描方式只能是 c（CONNECT）或 s（SYN），当前值为 %q", s.ScanType)
	}
	if err := validateExcludedPorts(s.ExcludePorts); err != nil {
		return err
	}
	if len(s.Interface) > 128 || strings.ContainsAny(s.Interface, "\r\n") {
		return fmt.Errorf("网卡名称过长或包含换行，请填写 ifconfig/ip addr 中显示的网卡名")
	}
	return nil
}

func (s NaabuSettings) overallTimeout() time.Duration {
	minutes, _ := strconv.Atoi(s.OverallTimeout)
	return time.Duration(minutes) * time.Minute
}

// concurrency 返回并行执行的 naabu 批次数（1-16）；非法或缺省回退为 1（等价旧的串行行为）。
func (s NaabuSettings) concurrency() int {
	n, err := strconv.Atoi(strings.TrimSpace(s.Concurrency))
	if err != nil || n < 1 {
		return 1
	}
	if n > 16 {
		return 16
	}
	return n
}

func (s NaabuSettings) args(targetsFile, outFile, mode, customPorts string) []string {
	// -json 让 naabu 输出 JSONL（stdout 与 -o 文件同一格式），从而能精确解析
	// hostname、IPv4、IPv6、port、protocol；解析层同时保留普通文本兼容。
	// 域名策略保持 naabu 默认：每个域名取解析结果中的首个 IPv4 与首个 IPv6，
	// 因此这里刻意不加 -scan-all-ips（不扩大扫描范围）。
	args := []string{"-list", targetsFile, "-rate", s.Rate, "-retries", s.Retries,
		"-c", s.Workers, "-timeout", s.ResponseTimeout, "-scan-type", s.ScanType, "-silent", "-json", "-o", outFile}
	switch mode {
	case "full":
		args = append(args, "-p", "-")
	case "custom":
		args = append(args, "-p", customPorts)
	default:
		args = append(args, "-top-ports", "1000")
	}
	if s.ExcludePorts != "" {
		args = append(args, "-exclude-ports", s.ExcludePorts)
	}
	if s.Interface != "" {
		args = append(args, "-interface", s.Interface)
	}
	if s.Verify {
		args = append(args, "-verify")
	}
	return args
}

const naabuInstallHint = `处理方式：
  1) 在“系统设置 → naabu 路径”填写可执行文件绝对路径，不要只填写安装目录；
  2) Ubuntu 可执行 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest，或安装官方预编译包；
  3) macOS 可执行 brew install naabu；
  4) SYN 扫描需要 root 或 CAP_NET_RAW 权限，权限不足时可改用 CONNECT；
  5) 保存配置后点击“检测 naabu”，确认路径、执行权限和版本命令均正常。`

func limitedOutput(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "（无输出）"
	}
	const maxLength = 4000
	if len(value) > maxLength {
		return "（输出过长，仅保留末尾 4000 字节）\n" + value[len(value)-maxLength:]
	}
	return value
}

// naabuVersionTimeout 是 naabu 版本自检的总时长上界（包级变量便于测试缩短）。
// 自检超时后按进程组终止，并由 WaitDelay 强制关闭输出管道，
// 避免遗留子进程持住 stdout/stderr 让 cmd.Run 永久阻塞、进而长期占用 Runner 运行标志。
var naabuVersionTimeout = 10 * time.Second

// CheckNaabu 校验全部参数并实际执行 -version，避免路径存在但权限或二进制异常时误判为可用。
func (r *Runner) CheckNaabu() (string, string, error) {
	return r.checkNaabu(r.naabuSettings())
}

// checkNaabu 使用调用方给定的设置快照做自检：StartTask 与容量预检共用同一份快照，
// 避免自检、容量结论与真实 argv 之间出现设置漂移。
func (r *Runner) checkNaabu(settings NaabuSettings) (string, string, error) {
	if err := settings.Validate(); err != nil {
		return "", "", fmt.Errorf("naabu 配置校验失败：%v", err)
	}
	resolved, err := exec.LookPath(settings.Path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return settings.Path, "", fmt.Errorf("naabu 文件存在但当前账号没有执行权限（路径 %q）：%v。请检查文件执行权限和服务运行账号", settings.Path, err)
		}
		return settings.Path, "", fmt.Errorf("未找到 naabu 可执行文件（当前路径 %q）：%v\n%s", settings.Path, err, naabuInstallHint)
	}

	ctx, cancel := context.WithTimeout(context.Background(), naabuVersionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolved, "-version")
	// 与批次执行一致：Cancel 按进程组终止，WaitDelay 给 I/O 管道一个有界收尾。
	// 输出不是 *os.File，否则 Wait 会一直等复制协程读到 EOF。
	cmd.Cancel = func() error { return killProcess(cmd) }
	cmd.WaitDelay = pipeWaitDelay
	prepareProcess(cmd)
	// 自检输出同样使用有界尾部缓冲，避免异常二进制刷屏占满内存。
	stdout := newTailBuffer(64 * 1024)
	stderr := newTailBuffer(64 * 1024)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// 与批次执行完全一致：Start 后立刻把自检进程纳入受控作业/进程组（Windows Job Object），
	// 否则后续的 cleanupProcessGroup 无法确认后代进程，自检也可能遗留进程。
	err = cmd.Start()
	if err == nil {
		if hookErr := afterStartProcess(cmd); hookErr != nil {
			_ = killProcess(cmd)
			if waitErr := cmd.Wait(); waitErr != nil {
				err = fmt.Errorf("版本命令异常退出（%v），且自检进程未能纳入受控作业/进程组：%v", waitErr, hookErr)
			} else {
				err = fmt.Errorf("版本自检进程未能纳入受控作业/进程组：%v", hookErr)
			}
		} else {
			err = cmd.Wait()
		}
	}
	version := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
	// Cmd.Wait 会优先返回进程自身的 *exec.ExitError（例如版本命令 exit 1），
	// 即使 WaitDelay 已强制关闭被孙进程占住的输出管道，也不会返回 exec.ErrWaitDelay。
	// 因此不能按错误类型分支决定是否清理：无论 Run 返回什么，返回前都必须主动终止
	// 本次自检创建的进程组并确认收敛，否则 StartTask 释放运行标志后遗留子进程仍然存活。
	_, groupConverged := cleanupProcessGroup(cmd, processGroupSettleTimeout)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		// 超时已按进程组 SIGKILL；确认收敛后才返回，避免自检遗留子进程长期挂着。
		if !groupConverged {
			return resolved, version, fmt.Errorf("naabu 版本自检超过 %s 已终止，但遗留子进程未能在 %s 内退出（路径 %q），请检查系统中是否有残留进程", naabuVersionTimeout, processGroupSettleTimeout, resolved)
		}
		return resolved, version, fmt.Errorf("naabu 版本自检超过 %s 已终止（路径 %q）。请检查二进制是否卡住或系统资源是否不足", naabuVersionTimeout, resolved)
	}
	if !groupConverged {
		// 无法证明本次自检的进程组已收敛：直接判定不可用，不能只看版本命令的退出码。
		return resolved, version, fmt.Errorf("naabu 版本自检结束后遗留在输出管道上的子进程未能在 %s 内退出（路径 %q），已判定不可用；请检查系统中是否有残留进程", processGroupSettleTimeout, resolved)
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// 版本命令本身已退出，只是孙进程持住输出管道并被 WaitDelay 强制关闭；
		// 上面已终止该进程组并确认收敛，这里只恢复“版本命令自身成功”的语义。
		err = nil
	}
	if err != nil {
		return resolved, version, fmt.Errorf("naabu 版本自检失败（路径 %q）：%v\n标准输出：%s\n错误输出：%s\n请确认该文件是匹配当前 CPU 架构的 naabu，且服务账号具有执行权限", resolved, err, limitedOutput(stdout.String()), limitedOutput(stderr.String()))
	}
	if version == "" {
		version = "版本命令执行成功，但 naabu 未返回版本文本"
	}
	return resolved, version, nil
}

const scanBatchSize = 20

// writeTargets 把目标规格写入 naabu 的 -list 文件（naabu 原生支持 单IP/CIDR/范围/域名）。
// 域名统一小写并去掉结尾点，IP 统一规范表示；CIDR 与范围原样保留，不扩大扫描范围。
func writeTargets(path string, specs []store.TargetSpec) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, sp := range specs {
		target := sp.Raw
		switch sp.Kind {
		case "domain":
			if normalized := normalizeHostname(target); normalized != "" {
				target = normalized
			}
		case "ip":
			if normalized, ok := normalizeIP(target); ok {
				target = normalized
			}
		}
		if _, err := fmt.Fprintln(w, target); err != nil {
			return err
		}
	}
	return w.Flush()
}

func (r *Runner) fail(scanID int64, err error) {
	log.Printf("扫描 %d 失败: %v", scanID, err)
	if ferr := r.st.FinishScan(scanID, 0, err.Error()); ferr != nil {
		log.Printf("更新扫描状态失败: %v", ferr)
	}
}
