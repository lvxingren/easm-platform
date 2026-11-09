package scanner

import (
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"easm-platform/internal/store"
)

// 容量预检的固定预算参数。所有数值都是显式常量，避免“多个 naabu 进程无界放大配置”。
const (
	// defaultTotalRate 是平台级总发包速率默认预算（所有并行 naabu 进程之和）。
	// 与调优后单进程速率 5000、默认并发 6 的乘积一致，保证默认配置行为不变。
	defaultTotalRate = 30000
	// defaultProcessBudget 是平台同时运行的 naabu 进程数默认预算（上限）。
	defaultProcessBudget = 16
	// naabuDefaultRetries 是本机 naabu 2.7.0 的 -retries 契约：
	// 传 0 表示“没有设置”，naabu 自身按默认 3 轮执行；传 N>0 时 N 就是实际轮数
	// （不是“额外重试次数”，argv 原样透传）。容量估算必须按这个语义计算发包量。
	naabuDefaultRetries = 3
	// capacityFDChildOverhead 是每个 naabu 子进程除内部 worker 外的固定 FD 开销估算。
	// 注意：naabu 是独立进程，拥有自己的 RLIMIT_NOFILE，这个需求只与“单进程软上限”比较。
	capacityFDChildOverhead = 64
	// capacityFDParentReserve 是父进程（平台自身：SQLite/WAL、监听套接字、日志等）的 FD 余量。
	capacityFDParentReserve = 64
	// capacityFDParentPerChild 是父进程为每个并发 naabu 子进程额外持有的管道/句柄数量。
	capacityFDParentPerChild = 4
	// capacityEstimatedBytesPerResult 是单条 JSONL 结果（含主机名、IPv6、时间戳）的磁盘占用估算。
	capacityEstimatedBytesPerResult int64 = 96
	// capacityOpenPortRatio 是磁盘估算时假设的开放端口比例（未知结果量时避免最坏情况误判）。
	capacityOpenPortRatio = 0.05
	// capacityMinFreeDisk 是执行前要求保留的最小磁盘余量（低于该值直接拒绝启动）。
	capacityMinFreeDisk int64 = 64 << 20
	// capacityWarnRatio 是预计耗时占任务超时的告警比例。
	capacityWarnRatio = 0.8
	// capacitySmallBatchSpecs 是小批量豁免阈值：目标规格数 ≤ 该值时，耗时估算超时只告警不拒绝。
	// 理由：估算模型按最坏情况（所有端口×所有重试轮数）计算，实际 naabu 对开放端口立即响应、
	// 对 RST 端口不重试，真实耗时远低于估算；小批量属常规运维规模，运行时超时仍是安全网。
	capacitySmallBatchSpecs = 500
	// capacityStartupOverhead 是每个批次进程启动、收尾与入库的固定开销估算。
	capacityStartupOverhead = 3 * time.Second
	// capacityTargetCap 是目标展开计数上限，超过后按"至少这么多目标"估算，避免超大网段耗尽内存。
	capacityTargetCap = 1 << 22
	// defaultSplitBatchSize 是自动拆分时每批的目标数量默认值。
	defaultSplitBatchSize = 50
)

// capacityEnvironment 汇总容量预检需要向操作系统查询的信息。
// 以函数字段注入，便于测试在完全隔离（不依赖真实 ulimit / 磁盘）的环境下验证策略。
type capacityEnvironment struct {
	// diskPath 是扫描产物所在的数据根目录（相对工作目录）。
	diskPath string
	// fdSoftLimit 返回父进程的 RLIMIT_NOFILE 软上限（naabu 子进程会继承同一软上限）。
	fdSoftLimit func() (uint64, bool)
	// fdInUse 返回父进程当前已打开的文件描述符数量（用于区分“父进程自身开销”与“子进程需求”）。
	fdInUse  func() (uint64, bool)
	diskFree func(path string) (int64, bool)
}

var capacityEnv = capacityEnvironment{
	diskPath:    "data",
	fdSoftLimit: platformFDSoftLimit,
	fdInUse:     platformFDInUse,
	diskFree:    platformDiskFreeBytes,
}

// capacityInput 是纯函数的容量评估输入，所有平台相关数值都由调用方传入。
type capacityInput struct {
	Mode string
	// BatchWork 是按“真实扫描规格（specs）每 scanBatchSize 条一批”分批后每批的展开目标数。
	// 耗时估算必须以它为准：单个 /24 只有 1 个批次，不能因为展开出 254 个地址
	// 就假定额外并行进程。
	BatchWork   []int64
	Ports       int
	Retries     int
	Workers     int
	Rate        int
	TotalRate   int
	Budget      int
	Concurrency int
	Timeout     time.Duration
	FDKnown     bool
	FDSoft      uint64
	FDInUse     uint64
	DiskKnown   bool
	DiskFree    int64
}

// capacityPlan 是一次执行的容量结论：生效并发、每进程速率、预计耗时与预算余量。
type capacityPlan struct {
	Targets int
	Ports   int
	Probes  int64
	Batches int
	// Capped 表示目标展开计数达到上限，估算可能偏小（实际扫描范围不变）。
	Capped bool
	// NaabuRetries 是本次估算采用的 naabu 轮数（-retries 语义：0 回退工具默认 3）。
	NaabuRetries int
	// PlatformRestarts 是平台自身对“批次异常”允许的启动次数（与 naabu -retries 无关），
	// 单独建模，不计入发包量估算，避免把两种“重试”混为一谈。
	PlatformRestarts int
	Concurrency      int
	Requested        int
	PerRate          int
	TotalRate        int
	TotalBudget      int
	Timeout          time.Duration
	Estimated        time.Duration
	// FDPerProcess 是单个 naabu 子进程（独立 RLIMIT）的估算需求。
	FDPerProcess int
	// FDInUse 是父进程当前已打开的 FD 数量；FDRequired 是父进程（含管道）的预算占用。
	FDInUse            uint64
	FDParentPerProcess int
	FDRequired         uint64
	FDSoftLimit        uint64
	FDKnown            bool
	DiskEstimate       int64
	DiskFree           int64
	DiskKnown          bool
	Warnings           []string
}

// Summary 生成可写入执行事件的容量摘要（不含可能很长的告警列表）。
func (p capacityPlan) Summary() string {
	return fmt.Sprintf("容量预检：%d 个目标（展开估算）× %d 端口，共 %d 个真实批次；生效并发 %d（请求 %d），每进程速率 %d/s（平台总速率上限 %d/s，进程预算 %d）；naabu 轮数 %d；预计耗时 %s，任务超时 %s",
		p.Targets, p.Ports, p.Batches, p.Concurrency, p.Requested, p.PerRate, p.TotalRate, p.TotalBudget, p.NaabuRetries, p.Estimated.Round(time.Second), p.Timeout)
}

// evaluateCapacity 以纯函数方式评估容量：返回可执行计划，或带可操作建议的拒绝原因。
//
// 安全策略：
//   - 批次数只由真实 specs 决定，每批工作量用展开目标数计算，绝不假定额外并行；
//   - 并发同时受请求并发、平台进程预算、总速率预算、FD 预算约束，绝不放大配置；
//   - 每进程速率按平台总速率预算等分，保证 C 个进程之和不超过总预算；
//   - FD 预算区分“父进程自身 FD/管道”与“每个 naabu 子进程的独立 RLIMIT 需求”，
//     不把子进程的 per-process 上限跨进程聚合到父进程软上限上；
//   - 预计耗时超过任务超时时直接拒绝启动（不会静默接受必然被截断的执行）。
func evaluateCapacity(in capacityInput) (capacityPlan, error) {
	plan := capacityPlan{
		Ports: in.Ports, Requested: in.Concurrency,
		TotalRate: in.TotalRate, TotalBudget: in.Budget, Timeout: in.Timeout,
	}
	if len(in.BatchWork) == 0 {
		return plan, fmt.Errorf("容量预检失败：缺少真实批次的展开工作量")
	}
	var targets int64
	for _, work := range in.BatchWork {
		if work > 0 {
			targets += work
		}
	}
	if targets < 1 {
		return plan, fmt.Errorf("容量预检失败：目标数量为 0")
	}
	if in.Ports <= 0 {
		return plan, fmt.Errorf("容量预检失败：待扫描端口数量为 0")
	}
	plan.Targets = int(min64(targets, capacityTargetCap))
	plan.Batches = len(in.BatchWork)

	concurrency := in.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > plan.Batches {
		concurrency = plan.Batches
	}
	if in.Budget > 0 && concurrency > in.Budget {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("请求并发 %d 超过平台进程预算 %d，已按预算收敛为 %d；如需更高并发请调整平台进程预算", concurrency, in.Budget, in.Budget))
		concurrency = in.Budget
	}
	// 总速率预算连一个包/秒都分不到这么多进程时，先收敛进程数：
	// 否则后续 perRate 会被压到 1，导致 concurrency*PerRate 反而超过总预算。
	if in.TotalRate > 0 && concurrency > in.TotalRate {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("平台总速率预算 %d/s 低于请求并发 %d，已先把并发收敛为 %d（保证并发×每进程速率不超过总预算）；如需更高并发请提高平台总速率预算", in.TotalRate, concurrency, in.TotalRate))
		concurrency = in.TotalRate
	}
	if concurrency < 1 {
		concurrency = 1
	}

	// FD 预算：父进程与每个 naabu 子进程分开建模。
	//   - 子进程：naabu 是独立进程，拥有自己的 RLIMIT_NOFILE（继承父进程软上限），
	//     需求 = workers + 固定开销，只与软上限本身比较，不能乘以并发后与同一软上限相加；
	//   - 父进程：当前已打开的 FD + 平台预留 + 每个并发子进程的管道开销。
	plan.FDPerProcess = in.Workers + capacityFDChildOverhead
	plan.FDParentPerProcess = capacityFDParentPerChild
	plan.FDKnown = in.FDKnown
	plan.FDSoftLimit = in.FDSoft
	if in.FDKnown {
		if in.FDSoft < uint64(plan.FDPerProcess) {
			return plan, fmt.Errorf("容量预检未通过：文件描述符软上限 %d 低于单个 naabu 子进程的估算需求 %d（workers=%d + 子进程固定开销 %d）。naabu 子进程继承同一软上限，请提高运行账号的 ulimit -n（建议至少 %d），或降低 naabu 内部并发线程数后重试",
				in.FDSoft, plan.FDPerProcess, in.Workers, capacityFDChildOverhead, plan.FDPerProcess)
		}
		plan.FDInUse = in.FDInUse
		parentNeeded := func(processes int) int64 {
			return int64(in.FDInUse) + capacityFDParentReserve + int64(processes*capacityFDParentPerChild)
		}
		if parentNeeded(1) > int64(in.FDSoft) {
			return plan, fmt.Errorf("容量预检未通过：父进程当前已打开 %d 个文件描述符，加上平台预留 %d 与单批管道开销 %d 后需要 %d，超过软上限 %d。请提高 ulimit -n（建议至少 %d）后重试",
				in.FDInUse, capacityFDParentReserve, capacityFDParentPerChild, parentNeeded(1), in.FDSoft, parentNeeded(1))
		}
		maxByParent := 1
		if int64(in.FDSoft)-int64(in.FDInUse)-capacityFDParentReserve > 0 {
			maxByParent = int((int64(in.FDSoft) - int64(in.FDInUse) - capacityFDParentReserve) / capacityFDParentPerChild)
		}
		if maxByParent < 1 {
			maxByParent = 1
		}
		if maxByParent < concurrency {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("文件描述符软上限 %d（父进程已用 %d）只够并发 %d 个 naabu 进程（请求 %d），已收敛并发；如需更高并发请提高 ulimit -n",
				in.FDSoft, in.FDInUse, maxByParent, concurrency))
			concurrency = maxByParent
		}
		plan.FDRequired = uint64(parentNeeded(concurrency))
	}

	// 总速率预算：多进程发包速率之和不得超过平台预算，按并发等分到每个进程。
	perRate := in.Rate
	if perRate < 1 {
		perRate = 1
	}
	if in.TotalRate > 0 {
		if perRate > in.TotalRate {
			perRate = in.TotalRate
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("单进程速率 %d/s 超过平台总速率预算 %d/s，已按预算收敛；请调整 naabu 速率或平台总速率预算", in.Rate, in.TotalRate))
		}
		if perRate*concurrency > in.TotalRate {
			perRate = in.TotalRate / concurrency
			if perRate < 1 {
				perRate = 1
			}
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("并发 %d × 单进程速率 %d/s 会超过平台总速率预算 %d/s，已将每进程速率收敛为 %d/s；如需更高吞吐请提高平台总速率预算", concurrency, in.Rate, in.TotalRate, perRate))
		}
	}
	plan.Concurrency = concurrency
	plan.PerRate = perRate

	// naabu 轮数按工具契约：0 表示未设置（工具默认 3 轮），>0 即为实际轮数。
	// 平台自身的“批次异常重启”单独建模，不参与发包量估算。
	naabuRetries := in.Retries
	if naabuRetries <= 0 {
		naabuRetries = naabuDefaultRetries
	}
	plan.NaabuRetries = naabuRetries
	plan.PlatformRestarts = batchRetryAttempts
	plan.Probes = targets * int64(in.Ports) * int64(naabuRetries)
	plan.Estimated = estimateCapacityDuration(in.BatchWork, in.Ports, naabuRetries, concurrency, perRate)

	if in.Timeout > 0 && plan.Estimated > in.Timeout {
		// 小批量豁免：≤ capacitySmallBatchSpecs 条规格属常规运维规模，估算为最坏情况，
		// 运行时超时仍会保护（超时后保留已发现结果），不应在预检阶段硬拒绝。
		if plan.Batches*scanBatchSize <= capacitySmallBatchSpecs {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("预计耗时 %s 超过任务超时 %s（最坏情况估算），但目标规模较小（≤%d 条规格），已放行执行；运行时超时仍会保护，超时后保留已发现结果并标记为部分完成",
				plan.Estimated.Round(time.Second), in.Timeout, capacitySmallBatchSpecs))
		} else {
			requiredRate := int(math.Ceil(float64(plan.Probes) / in.Timeout.Seconds()))
			if requiredRate < 1 {
				requiredRate = 1
			}
			requiredMinutes := int(math.Ceil(plan.Estimated.Minutes()))
			return plan, fmt.Errorf("容量预检未通过：%d 个目标（展开估算）× %d 端口 × naabu %d 轮，共 %d 个真实批次，按生效并发 %d、每进程速率 %d/s 预计约 %s，超过任务超时 %s。平台不会自动缩小目标端口范围，也不会静默接受必然被截断的执行。可行调整（任选其一）：1) 把“单次任务超时”提高到至少 %d 分钟；2) 把平台总速率预算提高到至少 %d/s（当前 %d/s）；3) 降低 naabu 重试轮数（当前设置 %d，0 表示工具默认 %d 轮；估算按 %d 轮发包）；4) 减少目标数量。另：平台自身的批次异常重启（最多 %d 次）属于异常兜底，不计入此估算。",
				targets, in.Ports, naabuRetries, plan.Batches, concurrency, perRate, plan.Estimated.Round(time.Second), in.Timeout,
				requiredMinutes, requiredRate, in.TotalRate, in.Retries, naabuDefaultRetries, naabuRetries, plan.PlatformRestarts)
		}
	}
	if in.Timeout > 0 && float64(plan.Estimated) > float64(in.Timeout)*capacityWarnRatio {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("预计耗时 %s 已接近任务超时 %s，建议提高超时或平台总速率预算，否则可能只完成部分批次", plan.Estimated.Round(time.Second), in.Timeout))
	}

	// 磁盘预算：按“开放端口比例 5%”估算 JSONL 产物大小，避免用最坏情况误杀。
	estimatedResults := int64(float64(targets*int64(in.Ports)) * capacityOpenPortRatio)
	if estimatedResults < 1 {
		estimatedResults = 1
	}
	plan.DiskEstimate = estimatedResults * capacityEstimatedBytesPerResult
	plan.DiskKnown = in.DiskKnown
	plan.DiskFree = in.DiskFree
	if in.DiskKnown {
		if in.DiskFree < capacityMinFreeDisk {
			return plan, fmt.Errorf("容量预检未通过：数据目录可用空间仅 %d MiB，低于执行所需的 %d MiB 安全余量。请清理旧扫描产物或扩容磁盘后重试", in.DiskFree/(1<<20), capacityMinFreeDisk/(1<<20))
		}
		if in.DiskFree < plan.DiskEstimate*2 {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("数据目录可用空间 %d MiB，预计本次扫描产物约 %d MiB；空间紧张时请先清理旧产物（平台只清理自己生成的 batch_*.out / batch_*_targets.txt）",
				in.DiskFree/(1<<20), plan.DiskEstimate/(1<<20)))
		}
	}
	return plan, nil
}

// estimateCapacityDuration 用列表调度估算总耗时：
// 每个批次的发包量 = 该批展开目标数 × 端口 × naabu 轮数，时间是 发包量/每进程速率 + 启动开销；
// 只有真实存在的批次才会占用一个并发槽位，因此单个 /24（1 批）不会被当成“很多可并行批次”。
func estimateCapacityDuration(work []int64, ports, attempts, concurrency, perRate int) time.Duration {
	if len(work) == 0 || ports <= 0 || attempts <= 0 || concurrency <= 0 {
		return 0
	}
	if perRate < 1 {
		perRate = 1
	}
	finish := make([]float64, concurrency)
	startup := capacityStartupOverhead.Seconds()
	for _, targets := range work {
		slot := 0
		for index := 1; index < concurrency; index++ {
			if finish[index] < finish[slot] {
				slot = index
			}
		}
		probes := float64(targets) * float64(ports) * float64(attempts)
		finish[slot] += probes/float64(perRate) + startup
	}
	makespan := 0.0
	for _, value := range finish {
		if value > makespan {
			makespan = value
		}
	}
	return time.Duration(makespan * float64(time.Second))
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// planScanCapacity 读取当前设置与平台预算，按真实 specs 计算本次执行的容量计划。
func (r *Runner) planScanCapacity(settings NaabuSettings, mode, customPorts string, specs []store.TargetSpec) (capacityPlan, error) {
	ports, err := modePortCount(mode, customPorts, settings.ExcludePorts)
	if err != nil {
		return capacityPlan{}, err
	}
	work, capped := batchWorkload(specs)
	workers, _ := strconv.Atoi(settings.Workers)
	rate, _ := strconv.Atoi(settings.Rate)
	retries, _ := strconv.Atoi(settings.Retries)
	totalRate := parseSettingInt(settings.TotalRate, defaultTotalRate)
	budget := parseSettingInt(settings.ProcessBudget, defaultProcessBudget)
	fdSoft, fdKnown := capacityEnv.fdSoftLimit()
	var fdInUse uint64
	if capacityEnv.fdInUse != nil {
		if value, ok := capacityEnv.fdInUse(); ok {
			fdInUse = value
		}
	}
	diskFree, diskKnown := capacityEnv.diskFree(capacityEnv.diskPath)
	plan, err := evaluateCapacity(capacityInput{
		Mode: mode, BatchWork: work, Ports: ports, Retries: retries,
		Workers: workers, Rate: rate, TotalRate: totalRate, Budget: budget,
		Concurrency: settings.concurrency(), Timeout: settings.overallTimeout(),
		FDKnown: fdKnown, FDSoft: fdSoft, FDInUse: fdInUse, DiskKnown: diskKnown, DiskFree: diskFree,
	})
	plan.Capped = capped
	return plan, err
}

func parseSettingInt(value string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// batchWorkload 按执行侧完全相同的规则（每 scanBatchSize 条 spec 一批）构造每批展开工作量，
// 返回是否达到展开计数上限。批次数只由 specs 条数决定，与展开地址数无关。
func batchWorkload(specs []store.TargetSpec) ([]int64, bool) {
	if len(specs) == 0 {
		return nil, false
	}
	batches := (len(specs) + scanBatchSize - 1) / scanBatchSize
	work := make([]int64, 0, batches)
	capped := false
	for index := 0; index < batches; index++ {
		end := (index + 1) * scanBatchSize
		if end > len(specs) {
			end = len(specs)
		}
		var sum int64
		for _, spec := range specs[index*scanBatchSize : end] {
			count, hit := expandSpecTargets(spec)
			if hit {
				capped = true
			}
			sum += int64(count)
		}
		work = append(work, sum)
	}
	return work, capped
}

// expandSpecTargets 返回单条扫描规格展开后的目标数量（CIDR/范围只做有界计数，不真正展开）。
// 第二个返回值表示计数是否达到上限（实际扫描范围不变，只是估算可能偏小）。
func expandSpecTargets(spec store.TargetSpec) (int, bool) {
	switch spec.Kind {
	case "cidr":
		if count, ok := countCIDRTargets(spec.Raw); ok {
			return count, count >= capacityTargetCap
		}
	case "range":
		if count, ok := countRangeTargets(spec.Raw); ok {
			return count, count >= capacityTargetCap
		}
	}
	return 1, false
}

// portBitmap 是 1-65535 的端口位图：自定义端口与排除端口都用它精确构造集合，
// 再按集合差集计数（同一端口重复书写、范围重叠都只算一次）。
type portBitmap [1024]uint64

func (b *portBitmap) add(port int) {
	if port < 1 || port > 65535 {
		return
	}
	b[port/64] |= 1 << uint(port%64)
}

func (b *portBitmap) has(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	return b[port/64]&(1<<uint(port%64)) != 0
}

// count 返回 1-65535 内被置位的端口数量。
func (b *portBitmap) count() int {
	total := 0
	for index, word := range b {
		if index == 0 {
			// bit0 对应端口 0（不存在），不计入。
			word &^= 1
		}
		total += popcount(word)
	}
	return total
}

// minus 返回 b 去掉 other 后剩余的端口数量（精确差集）。
func (b *portBitmap) minus(other *portBitmap) int {
	total := 0
	for index, word := range b {
		if index == 0 {
			word &^= 1
		}
		total += popcount(word &^ other[index])
	}
	return total
}

func popcount(word uint64) int {
	count := 0
	for word != 0 {
		word &= word - 1
		count++
	}
	return count
}

var allPorts = func() portBitmap {
	var bitmap portBitmap
	for port := 1; port <= 65535; port++ {
		bitmap.add(port)
	}
	return bitmap
}()

// parsePortBitmap 把 "22,80,8000-9000" 解析为精确的端口集合（自动去重）。
// 空字符串返回空集合；格式错误返回错误。
func parsePortBitmap(value string) (portBitmap, error) {
	var bitmap portBitmap
	value = strings.TrimSpace(value)
	if value == "" {
		return bitmap, nil
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return bitmap, fmt.Errorf("端口列表存在空项")
		}
		bounds := strings.Split(item, "-")
		if len(bounds) > 2 || bounds[0] == "" {
			return bitmap, fmt.Errorf("端口格式错误：%q", item)
		}
		start, err := strconv.Atoi(bounds[0])
		if err != nil || start < 1 || start > 65535 {
			return bitmap, fmt.Errorf("端口 %q 无效", item)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(bounds[1])
			if err != nil || end < start || end > 65535 {
				return bitmap, fmt.Errorf("端口范围 %q 无效", item)
			}
		}
		for port := start; port <= end; port++ {
			bitmap.add(port)
		}
	}
	return bitmap, nil
}

// modePortCount 返回本次扫描单目标探测的端口数（精确差集）；不修改目标端口范围。
// 自定义端口与排除端口都先构造去重集合，再求差集；差集为空时直接报错。
func modePortCount(mode, customPorts, excludePorts string) (int, error) {
	excluded, err := parsePortBitmap(excludePorts)
	if err != nil {
		return 0, fmt.Errorf("容量预检无法解析排除端口：%v", err)
	}
	switch mode {
	case "custom":
		ports, err := parsePortBitmap(customPorts)
		if err != nil {
			return 0, fmt.Errorf("容量预检无法解析自定义端口：%v", err)
		}
		remaining := ports.minus(&excluded)
		if remaining < 1 {
			return 0, fmt.Errorf("容量预检未通过：自定义端口 %q 在排除端口 %q 后为空，没有可扫描的端口", strings.TrimSpace(customPorts), strings.TrimSpace(excludePorts))
		}
		return remaining, nil
	case "full":
		remaining := allPorts.minus(&excluded)
		if remaining < 1 {
			return 0, fmt.Errorf("容量预检未通过：1-65535 全部端口都被排除端口 %q 排除，没有可扫描的端口", strings.TrimSpace(excludePorts))
		}
		return remaining, nil
	default:
		// 常用端口由 naabu 内置 top-1000 列表决定，平台无法精确枚举；
		// 这里只按排除集合大小做保守扣减，并拒绝“排除量已达 1000”的必然空集。
		excludedCount := excluded.count()
		remaining := 1000 - excludedCount
		if remaining < 1 {
			return 0, fmt.Errorf("容量预检未通过：排除端口数量 %d 已达到常用端口 top-1000 的规模，无法保证仍有端口可扫描；请缩小排除端口范围或改用自定义/全端口模式", excludedCount)
		}
		return remaining, nil
	}
}

// countTargets 展开目标规格计数（CIDR/范围只做有界计数，不真正展开），返回是否达到上限。
// 手工目标在执行前已去重；此处只服务于容量估算，不改变实际扫描范围。
func countTargets(specs []store.TargetSpec) (int, bool) {
	total := 0
	capped := false
	for _, spec := range specs {
		count, hit := expandSpecTargets(spec)
		if hit {
			capped = true
			count = capacityTargetCap
		}
		if total >= capacityTargetCap-count {
			return capacityTargetCap, true
		}
		total += count
	}
	if total < 1 {
		total = 1
	}
	return total, capped
}

func countCIDRTargets(raw string) (int, bool) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}
	ones, bits := ipnet.Mask.Size()
	if bits == 0 || ones > bits {
		return 0, false
	}
	if bits-ones > 31 {
		// IPv6 或超大网段：按上限估算，避免移位溢出。
		return capacityTargetCap, true
	}
	n := 1 << (bits - ones)
	if bits == 32 && n > 2 {
		n -= 2 // 去掉网络地址与广播地址
	}
	if n < 1 {
		n = 1
	}
	return n, true
}

func countRangeTargets(raw string) (int, bool) {
	parts := strings.Split(strings.TrimSpace(raw), "-")
	if len(parts) != 2 {
		return 0, false
	}
	start, ok := ipv4ToUint(parts[0])
	if !ok {
		return 0, false
	}
	end, ok := ipv4ToUint(parts[1])
	if !ok || end < start {
		return 0, false
	}
	n := int(end-start) + 1
	if n >= capacityTargetCap {
		return capacityTargetCap, true
	}
	return n, true
}

func ipv4ToUint(value string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

// nearestExistingDir 返回 path 或最近的已存在上级目录，供磁盘余量探测使用。
func nearestExistingDir(path string) string {
	if strings.TrimSpace(path) == "" {
		path = "."
	}
	current := filepath.Clean(path)
	for {
		if info, err := os.Stat(current); err == nil && info.IsDir() {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "."
		}
		current = parent
	}
}

// IsTimeoutError 判断容量预检错误是否因预估耗时超过任务超时。
// 只有这类错误才触发自动拆分，其他预检失败（FD/磁盘等）仍直接拒绝。
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "超过任务超时") || strings.Contains(msg, "预估耗时")
}

// CalculateSplitBatches 将目标规格列表按 batchSize 拆分为多个批次。
// 每批包含最多 batchSize 个目标规格（注意：这是 specs 条数，不是展开后的地址数）。
func CalculateSplitBatches(specs []store.TargetSpec, batchSize int) [][]store.TargetSpec {
	if len(specs) == 0 || batchSize < 1 {
		return nil
	}
	var batches [][]store.TargetSpec
	for i := 0; i < len(specs); i += batchSize {
		end := i + batchSize
		if end > len(specs) {
			end = len(specs)
		}
		batches = append(batches, specs[i:end])
	}
	return batches
}

// CalculateSmartBatchSize 根据超时时间和目标数量智能计算批次大小。
// 核心思路：确保每个子任务的预估耗时不超过任务超时时间的 80%，留出 20% 余量。
//
// 参数：
//   - targetCount: 目标数量
//   - portsPerTarget: 每个目标的目标的端口数
//   - ratePerSecond: 每秒探测速率
//   - timeout: 任务超时时间
//   - retries: naabu 重试轮数（0 表示工具默认 3 轮）
//
// 返回：推荐的批次大小（至少为 1）
func CalculateSmartBatchSize(targetCount, portsPerTarget, ratePerSecond int, timeout time.Duration, retries ...int) int {
	if targetCount <= 0 || portsPerTarget <= 0 || ratePerSecond <= 0 {
		return defaultSplitBatchSize
	}

	// naabu 轮数契约：0 表示未设置（工具默认 3 轮），>0 即为实际轮数
	naabuRetries := naabuDefaultRetries
	if len(retries) > 0 && retries[0] > 0 {
		naabuRetries = retries[0]
	}

	// 计算单个目标的预估耗时（秒），包含重试轮数
	singleTargetDuration := float64(portsPerTarget) * float64(naabuRetries) / float64(ratePerSecond)

	// 目标超时时间的 80%（留 20% 余量）
	effectiveTimeout := float64(timeout.Seconds()) * 0.8

	// 计算单个批次最多能容纳的目标数
	maxTargetsPerBatch := int(effectiveTimeout / singleTargetDuration)
	if maxTargetsPerBatch < 1 {
		maxTargetsPerBatch = 1
	}

	// 如果目标总数小于单批最大目标数，不需要拆分
	if targetCount <= maxTargetsPerBatch {
		return targetCount
	}

	// 返回计算出的批次大小，但不超过默认值的 2 倍（避免批次过大）
	if maxTargetsPerBatch > defaultSplitBatchSize*2 {
		return defaultSplitBatchSize * 2
	}
	return maxTargetsPerBatch
}

// EncodeSpecsJSON 将目标规格列表编码为 JSON 字符串，便于存储到数据库。
func EncodeSpecsJSON(specs []store.TargetSpec) string {
	if len(specs) == 0 {
		return "[]"
	}
	// 简单编码为 JSON 数组，每个元素是 {raw, kind}
	var buf strings.Builder
	buf.WriteByte('[')
	for i, sp := range specs {
		if i > 0 {
			buf.WriteByte(',')
		}
		// 转义 raw 中的特殊字符
		raw := strings.ReplaceAll(sp.Raw, `\`, `\\`)
		raw = strings.ReplaceAll(raw, `"`, `\"`)
		buf.WriteString(fmt.Sprintf(`{"raw":%q,"kind":%q}`, raw, sp.Kind))
	}
	buf.WriteByte(']')
	return buf.String()
}
