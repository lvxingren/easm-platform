package scanner

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"easm-platform/internal/store"
)

// batchWork 构造 n 目标（每批 scanBatchSize 条）对应的真实批次工作量，
// 与执行侧 processBatch 的分批规则完全一致。
func batchWork(targets int) []int64 {
	perBatch := targets / scanBatchSize
	if targets%scanBatchSize != 0 {
		perBatch++
	}
	work := make([]int64, 0, perBatch)
	remaining := targets
	for remaining > 0 {
		size := scanBatchSize
		if remaining < size {
			size = remaining
		}
		work = append(work, int64(size))
		remaining -= size
	}
	return work
}

// fullPort500Input 是“500 个唯一目标、全端口、默认 60 分钟”的容量输入，
// 对应生产里最容易静默超时被截断的场景（500/20 = 25 个真实批次）。
func fullPort500Input() capacityInput {
	return capacityInput{
		Mode: "full", BatchWork: batchWork(500), Ports: 65535, Retries: 2, Workers: 25,
		Rate: 2000, TotalRate: defaultTotalRate, Budget: defaultProcessBudget,
		Concurrency: 3, Timeout: 60 * time.Minute,
	}
}

// TestEvaluateCapacityRejectsDefaultTimeoutFor500FullPorts 验证默认 60 分钟对 500 全端口
// 不会被静默接受，而是给出包含可操作调整项的错误。
func TestEvaluateCapacityRejectsDefaultTimeoutFor500FullPorts(t *testing.T) {
	plan, err := evaluateCapacity(fullPort500Input())
	if err == nil {
		t.Fatalf("500 目标全端口 + 默认 60 分钟不应通过容量预检，实际 plan=%+v", plan)
	}
	for _, marker := range []string{"容量预检未通过", "超过任务超时", "分钟", "总速率", "重试"} {
		if !strings.Contains(err.Error(), marker) {
			t.Fatalf("拒绝原因缺少可操作提示 %q: %v", marker, err)
		}
	}
	if plan.Batches != 25 || plan.Ports != 65535 || plan.Targets != 500 {
		t.Fatalf("预检计划基础字段错误: %+v", plan)
	}
}

// TestEvaluateCapacityAcceptsRaisedBudget 验证按建议提高超时与平台总速率后可以通过，
// 并且每进程速率不会超过平台总速率预算。
func TestEvaluateCapacityAcceptsRaisedBudget(t *testing.T) {
	in := fullPort500Input()
	in.Timeout = 24 * time.Hour
	in.Rate = 1000000
	in.TotalRate = 16000000
	in.Retries = 0
	in.Concurrency = 16
	plan, err := evaluateCapacity(in)
	if err != nil {
		t.Fatalf("提高超时与总速率预算后应通过预检: %v", err)
	}
	if plan.Concurrency != 16 || plan.PerRate != 1000000 {
		t.Fatalf("并发/每进程速率收敛错误: %+v", plan)
	}
	if int64(plan.PerRate)*int64(plan.Concurrency) > int64(in.TotalRate) {
		t.Fatalf("并发 × 每进程速率超过平台总速率预算: %+v", plan)
	}
	if plan.Estimated <= 0 || plan.Estimated > in.Timeout {
		t.Fatalf("预计耗时不在超时预算内: %s", plan.Estimated)
	}
}

// TestEvaluateCapacityKeepsSmallTasksCompatible 验证小任务（少量目标 + 常用端口）不会被预检拒绝，
// 也不会产生与超时相关的告警，保持既有任务兼容。
func TestEvaluateCapacityKeepsSmallTasksCompatible(t *testing.T) {
	in := capacityInput{
		Mode: "top", BatchWork: batchWork(5), Ports: 1000, Retries: 1, Workers: 25,
		Rate: 1000, TotalRate: defaultTotalRate, Budget: defaultProcessBudget,
		Concurrency: 3, Timeout: 60 * time.Minute,
	}
	plan, err := evaluateCapacity(in)
	if err != nil {
		t.Fatalf("小任务不应被容量预检拒绝: %v", err)
	}
	if plan.Concurrency != 1 {
		t.Fatalf("单批次任务的并发应为 1，实际 %d", plan.Concurrency)
	}
	for _, warning := range plan.Warnings {
		if strings.Contains(warning, "接近任务超时") {
			t.Fatalf("小任务不应出现超时告警: %q", warning)
		}
	}
}

// TestEvaluateCapacityConvergesProcessBudget 验证请求并发超过平台进程预算时按预算收敛并告警。
func TestEvaluateCapacityConvergesProcessBudget(t *testing.T) {
	in := capacityInput{
		Mode: "top", BatchWork: batchWork(500), Ports: 1000, Retries: 0, Workers: 25,
		Rate: 1000, TotalRate: defaultTotalRate, Budget: 4,
		Concurrency: 16, Timeout: 24 * time.Hour,
	}
	plan, err := evaluateCapacity(in)
	if err != nil {
		t.Fatalf("按预算收敛后不应拒绝: %v", err)
	}
	if plan.Concurrency != 4 {
		t.Fatalf("并发未按平台进程预算收敛: %+v", plan)
	}
	if !warningsContain(plan.Warnings, "进程预算") {
		t.Fatalf("未给出进程预算收敛告警: %v", plan.Warnings)
	}
}

// TestEvaluateCapacityConvergesFileDescriptors 验证 FD 预算按“父进程占用 + 每子进程管道开销”收敛并发：
// 子进程需求（workers + 固定开销）只与软上限本身比较，父进程需求（当前 FD + 预留 + 4/进程）决定并发上限。
func TestEvaluateCapacityConvergesFileDescriptors(t *testing.T) {
	in := capacityInput{
		Mode: "top", BatchWork: batchWork(500), Ports: 1000, Retries: 0, Workers: 25,
		Rate: 1000, TotalRate: defaultTotalRate, Budget: 16,
		Concurrency: 16, Timeout: 24 * time.Hour,
		FDKnown: true, FDSoft: 96, FDInUse: 8,
	}
	plan, err := evaluateCapacity(in)
	if err != nil {
		t.Fatalf("FD 不足时应收敛并发而不是直接拒绝: %v", err)
	}
	want := int((96 - 8 - capacityFDParentReserve) / capacityFDParentPerChild)
	if plan.Concurrency != want {
		t.Fatalf("并发未按 FD 预算收敛: 期望 %d 实际 %d (%+v)", want, plan.Concurrency, plan)
	}
	if !warningsContain(plan.Warnings, "文件描述符") {
		t.Fatalf("未给出 FD 收敛告警: %v", plan.Warnings)
	}
	if plan.FDPerProcess != 25+capacityFDChildOverhead {
		t.Fatalf("子进程 FD 需求估算错误: %+v", plan)
	}
	wantParent := uint64(8 + capacityFDParentReserve + plan.Concurrency*capacityFDParentPerChild)
	if plan.FDRequired != wantParent || plan.FDInUse != 8 {
		t.Fatalf("父进程 FD 需求估算错误: 期望 %d 实际 %d (%+v)", wantParent, plan.FDRequired, plan)
	}
}

// TestEvaluateCapacityDoesNotAggregatePerProcessLimit 验证不会把每个 naabu 子进程的
// per-process 软上限需求按并发聚合回父进程软上限：16 个进程 × 564 FD 远超 600，
// 但每个子进程都拥有独立 RLIMIT，父进程只需要自己占用的 FD 与管道开销。
func TestEvaluateCapacityDoesNotAggregatePerProcessLimit(t *testing.T) {
	in := capacityInput{
		Mode: "top", BatchWork: batchWork(320), Ports: 1000, Retries: 0, Workers: 500,
		Rate: 1000, TotalRate: defaultTotalRate, Budget: 16,
		Concurrency: 16, Timeout: 24 * time.Hour,
		FDKnown: true, FDSoft: 600, FDInUse: 90,
	}
	plan, err := evaluateCapacity(in)
	if err != nil {
		t.Fatalf("每个子进程独立 RLIMIT 时不应按并发聚合拒绝: %v", err)
	}
	if plan.Concurrency != 16 {
		t.Fatalf("并发不应被子进程 per-process 需求聚合收敛: %+v", plan)
	}
	if plan.FDPerProcess != 500+capacityFDChildOverhead {
		t.Fatalf("单子进程需求估算错误: %+v", plan)
	}
}

// TestEvaluateCapacitySmallLowSpeedTaskUnderTightFDLimit 验证小软上限下的低速小任务仍可通过：
// 子进程需求 89 ≤ 100，父进程 8+64+4=76 ≤ 100，单批低速任务不需要更多 FD。
func TestEvaluateCapacitySmallLowSpeedTaskUnderTightFDLimit(t *testing.T) {
	in := capacityInput{
		Mode: "top", BatchWork: batchWork(20), Ports: 1000, Retries: 0, Workers: 25,
		Rate: 50, TotalRate: defaultTotalRate, Budget: 16,
		Concurrency: 3, Timeout: 60 * time.Minute,
		FDKnown: true, FDSoft: 100, FDInUse: 8,
	}
	plan, err := evaluateCapacity(in)
	if err != nil {
		t.Fatalf("小软上限下的低速小任务不应被拒绝: %v", err)
	}
	if plan.Concurrency != 1 || plan.FDRequired != 76 {
		t.Fatalf("低速小任务的 FD/并发估算错误: %+v", plan)
	}
}

// TestEvaluateCapacityRejectsTooFewFileDescriptors 验证两类 FD 硬约束：
// 软上限低于单个子进程需求 → 拒绝；父进程自身占用 + 预留已超上限 → 拒绝。
func TestEvaluateCapacityRejectsTooFewFileDescriptors(t *testing.T) {
	t.Run("子进程需求不足", func(t *testing.T) {
		in := fullPort500Input()
		in.FDKnown = true
		in.FDSoft = 80
		in.FDInUse = 0
		if _, err := evaluateCapacity(in); err == nil || !strings.Contains(err.Error(), "子进程") {
			t.Fatalf("软上限低于单子进程需求应拒绝并说明子进程，实际 err=%v", err)
		}
	})
	t.Run("父进程占用已超上限", func(t *testing.T) {
		in := fullPort500Input()
		in.FDKnown = true
		in.FDSoft = 100
		in.FDInUse = 64
		if _, err := evaluateCapacity(in); err == nil || !strings.Contains(err.Error(), "父进程") {
			t.Fatalf("父进程占用超上限应拒绝并说明父进程，实际 err=%v", err)
		}
	})
}

// TestEvaluateCapacityRejectsLowDisk 验证磁盘余量低于安全下限时拒绝启动。
func TestEvaluateCapacityRejectsLowDisk(t *testing.T) {
	in := fullPort500Input()
	// 超时与速率都已放宽，确保命中的是磁盘硬约束而不是时长估算。
	in.Timeout = 24 * time.Hour
	in.Rate = 1000000
	in.TotalRate = 16000000
	in.Retries = 0
	in.Concurrency = 16
	in.DiskKnown = true
	in.DiskFree = 1 << 20
	if _, err := evaluateCapacity(in); err == nil || !strings.Contains(err.Error(), "可用空间") {
		t.Fatalf("磁盘余量不足应拒绝并说明原因，实际 err=%v", err)
	}
}

// TestEvaluateCapacityWarnsTightDisk 验证磁盘够用但不足估算两倍时只告警，不阻断执行。
func TestEvaluateCapacityWarnsTightDisk(t *testing.T) {
	in := fullPort500Input()
	in.Timeout = 24 * time.Hour
	in.Rate = 1000000
	in.TotalRate = 16000000
	in.Retries = 0
	in.Concurrency = 16
	in.DiskKnown = true
	in.DiskFree = 200 << 20
	plan, err := evaluateCapacity(in)
	if err != nil {
		t.Fatalf("磁盘够用时不应拒绝: %v", err)
	}
	if plan.DiskEstimate <= 0 {
		t.Fatalf("未估算扫描产物容量: %+v", plan)
	}
	if !warningsContain(plan.Warnings, "空间紧张") {
		t.Fatalf("磁盘紧张时未给出告警: %v", plan.Warnings)
	}
}

// TestEvaluateCapacityConvergesTotalRate 验证多进程不会无界放大单进程速率：
// 并发 × 速率超过平台总速率预算时按预算等分收敛。
func TestEvaluateCapacityConvergesTotalRate(t *testing.T) {
	in := capacityInput{
		Mode: "top", BatchWork: batchWork(60), Ports: 1000, Retries: 0, Workers: 25,
		Rate: 5000, TotalRate: 6000, Budget: defaultProcessBudget,
		Concurrency: 3, Timeout: 60 * time.Minute,
	}
	plan, err := evaluateCapacity(in)
	if err != nil {
		t.Fatalf("收敛速率后不应拒绝: %v", err)
	}
	if plan.PerRate != 2000 {
		t.Fatalf("每进程速率未按平台总速率收敛: %+v", plan)
	}
	if !warningsContain(plan.Warnings, "总速率预算") {
		t.Fatalf("未给出总速率收敛告警: %v", plan.Warnings)
	}
}

// TestEvaluateCapacityConvergesConcurrencyBeforePerRate 验证 TotalRate < concurrency 时
// 先把进程数收敛到总速率预算，保证并发 × 每进程速率不超过预算（而不是把 perRate 压到 1 后超预算）。
func TestEvaluateCapacityConvergesConcurrencyBeforePerRate(t *testing.T) {
	in := capacityInput{
		Mode: "top", BatchWork: batchWork(100), Ports: 1000, Retries: 0, Workers: 25,
		Rate: 1000, TotalRate: 2, Budget: defaultProcessBudget,
		// 本用例只验证「先收敛并发、再等分速率」这一条不变量：把速率压到 1/s 后
		// 总工作量必然很长，因此超时给足，避免被耗时估算拒绝而掩盖并发收敛结论。
		Concurrency: 5, Timeout: 1000 * time.Hour,
	}
	plan, err := evaluateCapacity(in)
	if err != nil {
		t.Fatalf("收敛并发后不应拒绝: %v", err)
	}
	if plan.Concurrency != 2 {
		t.Fatalf("总速率预算低于并发时应先收敛进程数: %+v", plan)
	}
	if plan.Concurrency*plan.PerRate > in.TotalRate {
		t.Fatalf("并发 × 每进程速率仍超过总速率预算: 并发=%d 每进程=%d 预算=%d", plan.Concurrency, plan.PerRate, in.TotalRate)
	}
}

// TestEvaluateCapacityNaabuRetriesContract 验证 naabu 2.7.0 的 -retries 契约：
// 0 表示“未设置”（工具默认 3 轮），N>0 即为实际轮数；平台自身的批次异常重启单独建模。
func TestEvaluateCapacityNaabuRetriesContract(t *testing.T) {
	cases := []struct {
		retries string
		want    int
	}{
		{retries: "0", want: naabuDefaultRetries},
		{retries: "2", want: 2},
		{retries: "7", want: 7},
	}
	for _, tc := range cases {
		in := capacityInput{
			Mode: "top", BatchWork: batchWork(20), Ports: 1000, Workers: 25,
			Rate: 1000, TotalRate: defaultTotalRate, Budget: defaultProcessBudget,
			Concurrency: 1, Timeout: 24 * time.Hour,
		}
		if value, err := strconv.Atoi(tc.retries); err == nil {
			in.Retries = value
		}
		plan, err := evaluateCapacity(in)
		if err != nil {
			t.Fatalf("-retries=%s 时不应拒绝: %v", tc.retries, err)
		}
		if plan.NaabuRetries != tc.want {
			t.Fatalf("-retries=%s 的轮数=%d，期望 %d", tc.retries, plan.NaabuRetries, tc.want)
		}
		if plan.PlatformRestarts != batchRetryAttempts {
			t.Fatalf("平台异常重启次数未单独建模: %+v", plan)
		}
		wantProbes := int64(20) * 1000 * int64(tc.want)
		if plan.Probes != wantProbes {
			t.Fatalf("-retries=%s 的发包量=%d，期望 %d（轮数必须按工具契约计算）", tc.retries, plan.Probes, wantProbes)
		}
	}
}

// TestEvaluateCapacitySingleCIDRUsesRealBatches 验证 CIDR/范围按真实 specs 批次估时：
// 单个 /24 只产生 1 个批次（254 个展开目标），不能因为展开出 254 个地址就假定额外并行，
// 因此“单 /24 + 全端口 + 60 分钟”必须被明确拒绝。
func TestEvaluateCapacitySingleCIDRUsesRealBatches(t *testing.T) {
	work, capped := batchWorkload([]store.TargetSpec{{Raw: "192.0.2.0/24", Kind: "cidr"}})
	if capped || len(work) != 1 || work[0] != 254 {
		t.Fatalf("单个 /24 应只有 1 个批次、254 个展开目标: work=%v capped=%v", work, capped)
	}
	in := capacityInput{
		Mode: "full", BatchWork: work, Ports: 65535, Retries: 0, Workers: 25,
		Rate: 2000, TotalRate: defaultTotalRate, Budget: defaultProcessBudget,
		Concurrency: 3, Timeout: 60 * time.Minute,
	}
	plan, err := evaluateCapacity(in)
	if err == nil {
		t.Fatalf("单个 /24 全端口在 60 分钟内不可能完成，应拒绝: %+v", plan)
	}
	if !strings.Contains(err.Error(), "超过任务超时") {
		t.Fatalf("拒绝原因应说明超时: %v", err)
	}
	if plan.Batches != 1 || plan.Concurrency != 1 {
		t.Fatalf("单个 /24 不应被当成多批次并行: %+v", plan)
	}
}

func warningsContain(warnings []string, marker string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, marker) {
			return true
		}
	}
	return false
}

// withCapacityEnv 用固定值替换平台探测（FD 软上限/已用 FD/磁盘余量），使容量预检在完全隔离的
// 测试环境中结果确定，不依赖真实 ulimit 或磁盘；测试结束后恢复原探测函数。
func withCapacityEnv(t *testing.T, fdSoft, fdInUse uint64, diskFree int64) {
	t.Helper()
	previous := capacityEnv
	capacityEnv = capacityEnvironment{
		diskPath:    previous.diskPath,
		fdSoftLimit: func() (uint64, bool) { return fdSoft, true },
		fdInUse:     func() (uint64, bool) { return fdInUse, true },
		diskFree:    func(string) (int64, bool) { return diskFree, true },
	}
	t.Cleanup(func() { capacityEnv = previous })
}

// TestModePortCount 验证端口数量估算不改变目标端口范围，只用于容量计算：
// 自定义端口与排除端口都先构造去重集合，再求差集。
func TestModePortCount(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		custom  string
		exclude string
		want    int
		wantErr bool
	}{
		{name: "全端口", mode: "full", want: 65535},
		{name: "常用端口", mode: "top", want: 1000},
		{name: "自定义端口", mode: "custom", custom: "22,80,8000-8010", want: 13},
		{name: "自定义端口重复只算一次", mode: "custom", custom: "22,22,80", want: 2},
		{name: "自定义端口范围重叠只算一次", mode: "custom", custom: "8000-8010,8005-8015", want: 16},
		{name: "自定义端口扣除排除", mode: "custom", custom: "22,80,8000-8010", exclude: "22,80", want: 11},
		{name: "差集与书写顺序无关", mode: "custom", custom: "8000-8010", exclude: "8005-8010", want: 5},
		{name: "排除重复不影响差集", mode: "custom", custom: "22,80", exclude: "22,22,22", want: 1},
		{name: "常用端口扣除排除", mode: "top", exclude: "22", want: 999},
		{name: "全端口扣除排除", mode: "full", exclude: "1-65535", wantErr: true},
		{name: "自定义端口全部被排除", mode: "custom", custom: "22,80", exclude: "80,22", wantErr: true},
		{name: "自定义端口非法", mode: "custom", custom: "abc", wantErr: true},
		{name: "排除端口非法", mode: "full", exclude: "70-60", wantErr: true},
		{name: "常用端口排除量达 1000", mode: "top", exclude: "1-1000", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := modePortCount(c.mode, c.custom, c.exclude)
			if c.wantErr {
				if err == nil {
					t.Fatalf("期望错误，实际 ports=%d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("端口数=%d，期望 %d", got, c.want)
			}
		})
	}
}

// TestBatchWorkloadFollowsRealSpecs 验证批次工作量按真实 specs 分批（每 scanBatchSize 条一批），
// 与展开后的地址总数无关。
func TestBatchWorkloadFollowsRealSpecs(t *testing.T) {
	ips := make([]store.TargetSpec, 0, 25)
	for index := 0; index < 25; index++ {
		ips = append(ips, store.TargetSpec{Raw: "192.0.2.1", Kind: "ip"})
	}
	work, capped := batchWorkload(ips)
	if capped || len(work) != 2 || work[0] != 20 || work[1] != 5 {
		t.Fatalf("25 条规格应分为 20+5 两批: work=%v capped=%v", work, capped)
	}
	// 单条 /24 展开为 254 个地址，但批次仍只有 1 个。
	work, capped = batchWorkload([]store.TargetSpec{{Raw: "198.51.100.0/24", Kind: "cidr"}})
	if capped || len(work) != 1 || work[0] != 254 {
		t.Fatalf("单条 /24 应为 1 个批次、254 个目标: work=%v capped=%v", work, capped)
	}
}

// TestPlanScanCapacityUsesEnvironment 验证 planScanCapacity 会读取注入的 FD/磁盘探测结果，
// 并且不会因为探测而修改目标端口范围或写入数据库。
func TestPlanScanCapacityUsesEnvironment(t *testing.T) {
	withCapacityEnv(t, 65535, 12, 1<<30)
	runner := &Runner{}
	settings := NaabuSettings{
		Path: "./naabu", Rate: "1000", Retries: "0", Workers: "25",
		ResponseTimeout: "1s", OverallTimeout: "60", Concurrency: "3",
		ScanType: "c", TotalRate: "6000", ProcessBudget: "16",
	}
	specs := make([]store.TargetSpec, 0, 10)
	for index := 0; index < 10; index++ {
		specs = append(specs, store.TargetSpec{Raw: "192.0.2.1", Kind: "ip"})
	}
	plan, err := runner.planScanCapacity(settings, "top", "", specs)
	if err != nil {
		t.Fatalf("容量预检失败: %v", err)
	}
	if !plan.FDKnown || !plan.DiskKnown || plan.FDInUse != 12 {
		t.Fatalf("未使用注入的 FD/磁盘探测结果: %+v", plan)
	}
	if plan.Targets != 10 || plan.Ports != 1000 || plan.Batches != 1 {
		t.Fatalf("容量计划与目标/端口不符: %+v", plan)
	}
	if plan.TotalRate != 6000 || plan.TotalBudget != 16 {
		t.Fatalf("平台预算未从设置读取: %+v", plan)
	}
}

// TestCountTargets 验证目标展开计数（CIDR/范围只做有界计数，不改变扫描范围）。
func TestCountTargets(t *testing.T) {
	specs := []store.TargetSpec{
		{Raw: "192.0.2.1", Kind: "ip"},
		{Raw: "192.0.2.0/30", Kind: "cidr"},
		{Raw: "198.51.100.1-198.51.100.4", Kind: "range"},
		{Raw: "example.com", Kind: "domain"},
	}
	got, capped := countTargets(specs)
	if capped {
		t.Fatal("小目标集合不应触发计数上限")
	}
	// 1 + 2（/30 去掉网络与广播）+ 4 + 1
	if got != 8 {
		t.Fatalf("目标展开计数=%d，期望 8", got)
	}
}

// TestNaabuSettingsValidatePlatformBudget 验证平台总速率/进程预算的校验：
// 空值放行（兼容 web 侧只填部分字段），非法值报错。
func TestNaabuSettingsValidatePlatformBudget(t *testing.T) {
	base := NaabuSettings{
		Path: "./naabu", Rate: "1000", Retries: "0", Workers: "25",
		ResponseTimeout: "1s", OverallTimeout: "60", Concurrency: "3", ScanType: "c",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("空预算字段应放行以兼容既有调用方: %v", err)
	}
	bad := base
	bad.TotalRate = "0"
	if err := bad.Validate(); err == nil {
		t.Fatal("非法平台总速率应报错")
	}
	bad = base
	bad.ProcessBudget = "abc"
	if err := bad.Validate(); err == nil {
		t.Fatal("非法进程预算应报错")
	}
	good := base
	good.TotalRate = "6000"
	good.ProcessBudget = "16"
	if err := good.Validate(); err != nil {
		t.Fatalf("合法预算不应报错: %v", err)
	}
}

// TestNaabuArgsUsesJSONLAndKeepsPortScope 验证命令行使用 -json 且不开启 scan-all-ips，
// 全端口仍使用 -p -（不自动缩小端口范围）。
func TestNaabuArgsUsesJSONLAndKeepsPortScope(t *testing.T) {
	settings := NaabuSettings{
		Path: "./naabu", Rate: "1000", Retries: "2", Workers: "25",
		ResponseTimeout: "1s", OverallTimeout: "60", Concurrency: "3", ScanType: "c",
	}
	args := strings.Join(settings.args("targets.txt", "out.jsonl", "full", ""), " ")
	for _, want := range []string{"-json", "-p -", "-o out.jsonl"} {
		if !strings.Contains(args, want) {
			t.Fatalf("命令行缺少 %q: %s", want, args)
		}
	}
	if strings.Contains(args, "scan-all-ips") {
		t.Fatalf("不应扩大扫描范围（禁止 scan-all-ips）: %s", args)
	}
	top := strings.Join(settings.args("targets.txt", "out.jsonl", "top", ""), " ")
	if !strings.Contains(top, "-top-ports 1000") || strings.Contains(top, "-p -") {
		t.Fatalf("常用端口模式不应改为全端口: %s", top)
	}
	custom := strings.Join(settings.args("targets.txt", "out.jsonl", "custom", "22,80"), " ")
	if !strings.Contains(custom, "-p 22,80") {
		t.Fatalf("自定义端口未被原样保留: %s", custom)
	}
}
