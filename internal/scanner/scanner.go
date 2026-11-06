package scanner

import (
	"bufio"
	"bytes"
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
	if _, _, err := r.CheckNaabu(); err != nil {
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

	go r.run(scanID, mode, customPorts, specs)
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
	Path             string
	Rate             string
	Retries          string
	Workers          string
	ResponseTimeout  string
	OverallTimeout   string
	Concurrency      string
	ScanType         string
	ExcludePorts     string
	Interface        string
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
	args := []string{"-list", targetsFile, "-rate", s.Rate, "-retries", s.Retries,
		"-c", s.Workers, "-timeout", s.ResponseTimeout, "-scan-type", s.ScanType, "-silent", "-o", outFile}
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

// CheckNaabu 校验全部参数并实际执行 -version，避免路径存在但权限或二进制异常时误判为可用。
func (r *Runner) CheckNaabu() (string, string, error) {
	settings := r.naabuSettings()
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolved, "-version")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	version := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
	if ctx.Err() == context.DeadlineExceeded {
		return resolved, version, fmt.Errorf("naabu 版本自检超过 10 秒已终止（路径 %q）。请检查二进制是否卡住或系统资源是否不足", resolved)
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

// writeTargets 把目标规格写入 naabu 的 -list 文件（naabu 原生支持 单IP/CIDR/范围）
func writeTargets(path string, specs []store.TargetSpec) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, sp := range specs {
		if _, err := fmt.Fprintln(w, sp.Raw); err != nil {
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

func parseOutput(path string) ([]store.Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []store.Result
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		out = append(out, store.Result{IP: strings.TrimSpace(parts[0]), Port: port, Proto: "tcp", Status: 1})
	}
	return out, sc.Err()
}
