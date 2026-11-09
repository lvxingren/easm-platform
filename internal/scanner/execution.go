package scanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

const (
	// stderrLimit 是单批次 stderr 保留上限（末尾字节），避免 naabu 异常刷屏时内存无上限增长。
	stderrLimit = 8 * 1024
	// batchRetryAttempts 是单批次的最大尝试次数：首次 + 最多两次额外尝试。
	batchRetryAttempts = 3
	// batchRetryBackoff 是重试退避基数，按尝试序号递增，且可被暂停/终止打断。
	batchRetryBackoff = 400 * time.Millisecond
	// stdoutDrainGrace 是 naabu 退出后继续读取 stdout 的宽限期；
	// 孙进程占住管道时也必须让批次有界收敛，否则运行标志无法释放。
	stdoutDrainGrace = 3 * time.Second
	// stdoutLineLimit 是 naabu stdout 单行硬上限（1 MiB）：行内的内容最多保留这么多，
	// 超过则该行内容被有界丢弃（继续消费到行尾），保证“无换行超长行”不会让内存无界增长。
	stdoutLineLimit = 1 << 20
	// pipeWaitDelay 交给 os/exec 的有界等待：主进程退出（或 ctx 结束）后，
	// 若仍有遗留子进程占住 stdout/stderr 管道，Wait 最多再等这么久就强制关闭管道并返回 exec.ErrWaitDelay，
	// 从而保证 cmd.Wait 不会因非 *os.File 的 stderr 复制协程等不到 EOF 而永久阻塞。
	pipeWaitDelay = 2 * time.Second
	// processGroupSettleTimeout 是强制收尾后主动终止并确认进程组（含遗留孙进程）收敛的上界。
	processGroupSettleTimeout = 1 * time.Second
	// retryBudgetPoll 是重试退避期间检查有效截止时间的轮询间隔。
	retryBudgetPoll = 100 * time.Millisecond
	// dbFlushRows 是固定的批量写库行数：达到即调用 InsertResultsBatch，
	// 与待写入硬上限共同保证单次 SQL/事务规模有界。
	dbFlushRows = 200
	// pendingMaxRows / pendingMaxBytes 是待写入缓冲的硬上限：任一到达即刷库，
	// 防止 stdout 高峰或大文件补读把待写入切片撑爆内存。
	pendingMaxRows  = 400
	pendingMaxBytes = 256 << 10
	// recentKeyLimit 是有界近期去重缓存容量；真正的去重由数据库唯一索引保证。
	recentKeyLimit = 4096
	// progressMessageLimit 是执行异常消息保留上限，避免超大规模扫描消息切片无界增长。
	progressMessageLimit = 40
	// resolutionSampleLimit 是单批次解析失败目标样例上限。
	resolutionSampleLimit = 5
)

type batchOutcome struct {
	runErr      error
	parseErr    error
	streamErr   error
	storeErr    error
	timedOut    bool
	startFailed bool
	// drainClosed 表示输出管道曾被遗留子进程占用，已在有界时间内被强制关闭；
	// 此时主进程本身正常退出，但无法证明实时输出完整，终态不得为 done。
	drainClosed bool
	// groupUnreaped 表示强制收尾后仍未能确认进程组收敛，批次必须按失败处理且不重试。
	groupUnreaped bool
	// truncatedStdout 表示实时输出在行中被截断（进程被终止/管道被关闭），
	// 实时结果不完整，需由输出文件去重补齐，终态不得为 done。
	truncatedStdout bool
	// oversizedLines 是超过 stdoutLineLimit 而被有界丢弃的输出行数。
	// 这些行没有进入解析器，无法证明实时输出完整，同样不得把终态记为 done。
	oversizedLines int
	// cleanupUnavailable 表示本次进程无法纳入受控的作业/进程组（如 Windows Job Object 建立失败），
	// 因此无法确认后代进程是否全部退出：不得伪报收敛，也不自动重试。
	cleanupUnavailable bool
	attempts           int
	results            int
	// resolutionFailures 是本批次 naabu 明确报告的域名解析失败数；
	// 存在解析失败时终态不得为 done（无法可靠识别全部目标）。
	resolutionFailures int
	resolutionSamples  []string
	malformedLines     int
	malformedSamples   []string
	stdout             string
	stderr             string
}

// errOutputStreamTruncated 表示 naabu 实时输出在行中被截断（不是结构化数据损坏）。
var errOutputStreamTruncated = errors.New("naabu 实时输出在行中被截断")

// resultFlushHook 仅用于测试观察批量写库的分块规模（提交行数、实际新增行数、内部事务数）。
// 生产环境为 nil：未注册时对执行行为与性能没有任何影响，也不参与任何判定。
var resultFlushHook func(stats store.ResultInsertStats)

// tailBuffer 是 stderr 的有界缓冲：只保留末尾 limit 字节，用于异常路径下仍能稳定回传错误输出。
type tailBuffer struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func newTailBuffer(limit int) *tailBuffer {
	return &tailBuffer{limit: limit}
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.limit {
		b.buf = append(b.buf[:0], b.buf[len(b.buf)-b.limit:]...)
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// scanProgress 是并行多批次共享的执行状态，所有字段访问均由 mu 保护。
// 去重不再依赖无界 seen map：近期缓存只做有界加速，最终正确性由
// scan_results 的 UNIQUE(scan_id, ip, port, proto) 与 INSERT OR IGNORE 保证。
type scanProgress struct {
	mu        sync.Mutex
	recent    *recentKeyCache
	openPorts int
	results   int
	processed int
	failed    int
	completed int
	// unreliable 表示出现过无法可靠识别的输出（域名解析失败/坏 JSON），终态不得为 done。
	unreliable bool
	messages   []string
	suppressed int
	// connectFallback 表示本次执行已确认 SYN 权限不足，后续批次与重试统一降级为 CONNECT。
	connectFallback bool
}

func newScanProgress() *scanProgress {
	return &scanProgress{recent: newRecentKeyCache(recentKeyLimit)}
}

type progressSnapshot struct {
	processed int
	failed    int
	completed int
	openPorts int
	results   int
}

func (p *scanProgress) addMessage(m string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.messages) >= progressMessageLimit {
		p.suppressed++
		return
	}
	p.messages = append(p.messages, m)
}

func (p *scanProgress) addProcessed(n int) {
	p.mu.Lock()
	p.processed += n
	p.mu.Unlock()
}

func (p *scanProgress) addFailed(n int) {
	p.mu.Lock()
	p.failed += n
	p.mu.Unlock()
}

func (p *scanProgress) completeBatch() {
	p.mu.Lock()
	p.completed++
	p.mu.Unlock()
}

func (p *scanProgress) snapshot() progressSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return progressSnapshot{processed: p.processed, failed: p.failed, completed: p.completed, openPorts: p.openPorts, results: p.results}
}

func (p *scanProgress) finalMessages() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	messages := append([]string(nil), p.messages...)
	if p.suppressed > 0 {
		messages = append(messages, fmt.Sprintf("另有 %d 条异常说明因超出保留上限未展示，请查看运行日志", p.suppressed))
	}
	return messages
}

// hasRecent / remember 只服务于有界近期缓存，不承担最终去重职责。
func (p *scanProgress) hasRecent(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.recent.has(key)
}

func (p *scanProgress) remember(key string) {
	p.mu.Lock()
	p.recent.add(key)
	p.mu.Unlock()
}

// addInserted 使用数据库实际新增行数更新开放端口与结果行数，
// 因此重试、stdout 与文件补读的重复行不会被重复计数。
func (p *scanProgress) addInserted(n int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n > 0 {
		p.openPorts += n
		p.results += n
	}
	return p.openPorts
}

func (p *scanProgress) markUnreliable() {
	p.mu.Lock()
	p.unreliable = true
	p.mu.Unlock()
}

func (p *scanProgress) isUnreliable() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.unreliable
}

// connectOnly 返回本次执行是否已降级为仅 CONNECT 扫描。
func (p *scanProgress) connectOnly() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connectFallback
}

// markConnectOnly 把本次执行标记为仅 CONNECT 扫描，返回是否为首次标记（用于只记录一次事件）。
func (p *scanProgress) markConnectOnly() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.connectFallback {
		return false
	}
	p.connectFallback = true
	return true
}

func (r *Runner) run(scanID int64, mode string, customPorts string, specs []store.TargetSpec, settings NaabuSettings, plan capacityPlan) {
	defer r.setRunning(false)
	// 任何 panic 都不应让执行状态悬空在 running/paused：恢复后强制修正为 stopped（幂等，已结束不受影响）。
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("扫描 %d panic 恢复: %v", scanID, rec)
			_ = r.st.ForceStopScanIfActive(scanID, fmt.Sprintf("扫描进程异常（panic）：%v；已保留入库结果，不生成告警。", rec))
		}
	}()
	start := time.Now()
	totalBatches := (len(specs) + scanBatchSize - 1) / scanBatchSize
	if err := r.st.StartScanExecution(scanID, len(specs), totalBatches); err != nil {
		r.fail(scanID, fmt.Errorf("初始化扫描进度失败，扫描未启动: %v", err))
		return
	}

	// settings 由 StartTask 传入（与容量预检同一份快照，-rate 已是 plan.PerRate）：
	// 这里不再重新读取设置，避免执行与容量结论不一致。
	if err := settings.Validate(); err != nil {
		r.fail(scanID, fmt.Errorf("naabu 配置校验失败：%v", err))
		return
	}
	timeout := settings.overallTimeout()
	r.mu.Lock()
	if r.active == nil {
		r.mu.Unlock()
		r.fail(scanID, fmt.Errorf("扫描控制状态初始化失败"))
		return
	}
	r.active.deadline = time.Now().Add(timeout)
	r.mu.Unlock()

	// 启动前按容量/保留策略清理旧的扫描产物：只删除平台生成的 batch_* 文件，
	// 绝不触碰 data/easm.db、证书、日志等用户业务数据。
	pruneScanArtifacts("data", scanID)

	dataDir := filepath.Join("data", fmt.Sprintf("scan_%d", scanID))
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		r.fail(scanID, fmt.Errorf("创建扫描数据目录 %q 失败：%v；请检查服务运行账号的目录权限", dataDir, err))
		return
	}

	prog := newScanProgress()
	concurrency := plan.Concurrency
	if concurrency > totalBatches {
		concurrency = totalBatches
	}
	if concurrency < 1 {
		concurrency = 1
	}
	// 容量结论与告警写入执行事件：告警只是提示，不改变终态；真正的拒绝在 StartTask 前已完成。
	_ = r.st.AddScanEvent(scanID, "info", "capacity", plan.Summary())
	for _, warning := range plan.Warnings {
		log.Printf("扫描 %d 容量提示: %s", scanID, warning)
		_ = r.st.AddScanEvent(scanID, "warn", "capacity", warning)
	}
	log.Printf("扫描 %d 启动：%d 个目标规格分 %d 批，并发度 %d（容量预计 %s）", scanID, len(specs), totalBatches, concurrency, plan.Estimated.Round(time.Second))

	// 预填批次队列（缓冲，避免暂停时喂入阻塞）；concurrency 个 worker 并行消费，
	// 每个 worker 独立启动一个 naabu 进程扫一批，总发包吞吐≈并发度×rate。
	batchQueue := make(chan int, totalBatches)
	for batchIndex := 0; batchIndex < totalBatches; batchIndex++ {
		batchQueue <- batchIndex
	}
	close(batchQueue)
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batchIndex := range batchQueue {
				if r.isStopped(scanID) {
					continue // 已终止：排空队列，不再启动新批次
				}
				if r.waitWhilePaused(scanID) {
					continue // 暂停期间不启动新批次；恢复后继续，若已终止则跳过
				}
				if _, stopped, deadline, _, _ := r.controlWatch(scanID); !stopped && !deadline.IsZero() && time.Now().After(deadline) {
					prog.addMessage(fmt.Sprintf("任务有效扫描总超时 %s，部分目标规格未开始处理（暂停时间不计入）", timeout))
					continue
				}
				r.processBatch(scanID, settings, mode, customPorts, specs, batchIndex, totalBatches, dataDir, timeout, prog)
			}
		}()
	}
	wg.Wait()

	elapsed := time.Since(start).Round(time.Second)
	snap := prog.snapshot()
	message := strings.Join(prog.finalMessages(), "\n\n")
	status := "done"
	if prog.isUnreliable() {
		// 域名解析失败/结构化输出损坏时无法证明执行范围完整，禁止虚报 done。
		// 后续 else 分支会结合 openPorts 继续细化为 partial/failed。
		if message != "" {
			message += "\n\n"
		}
		message += "本次执行存在无法可靠识别的输出（域名解析失败或结构化输出损坏），已保留可识别结果；为避免虚报完成，终态标记为不完整，不执行白名单比对和告警。"
		status = "partial"
	}
	if r.isStopped(scanID) {
		status = "stopped"
		if message != "" {
			message += "\n\n"
		}
		message += "扫描已由用户或平台停止，当前展示的是停止前已发现的结果；不执行白名单比对和端口风险告警。"
	} else if message != "" {
		status = "failed"
		if snap.openPorts > 0 {
			status = "partial"
		}
		message += "\n\n不完整结果不会执行白名单比对和告警。"
	}
	if err := r.st.FinishScanStatus(scanID, status, snap.openPorts, message); err != nil {
		log.Printf("更新扫描状态失败: %v", err)
	}
	log.Printf("扫描 %d 结束(%s): 已处理 %d/%d 个目标，异常目标 %d 个，开放端口 %d 条，耗时 %s",
		scanID, status, snap.processed, len(specs), snap.failed, snap.openPorts, elapsed)
	// 任务结束时无论成败只发一条飞书汇总；仅完整完成的执行才比对白名单并生成端口风险告警。
	var newAlerts []store.Alert
	if status == "done" {
		newAlerts = r.eng.AfterScan(scanID)
	}
	r.eng.NotifyScanSummary(scanID, status, newAlerts)
}

// processBatch 处理单个批次：写目标文件 → 启动 naabu（runBatch 流式入库）→ 累计进度与异常。
// 由并行 worker 调用，共享状态经 prog 加锁；DB 写入依赖 WAL+busy_timeout 并发安全。
func (r *Runner) processBatch(scanID int64, settings NaabuSettings, mode, customPorts string, specs []store.TargetSpec, batchIndex, totalBatches int, dataDir string, timeout time.Duration, prog *scanProgress) {
	batchNumber := batchIndex + 1
	end := (batchIndex + 1) * scanBatchSize
	if end > len(specs) {
		end = len(specs)
	}
	batch := specs[batchIndex*scanBatchSize : end]
	targetsFile := filepath.Join(dataDir, fmt.Sprintf("batch_%04d_targets.txt", batchNumber))
	outFile := filepath.Join(dataDir, fmt.Sprintf("batch_%04d.out", batchNumber))
	if err := writeTargets(targetsFile, batch); err != nil {
		prog.addMessage(fmt.Sprintf("批次 %d 写入目标文件 %q 失败：%v；本批目标未处理，请检查目录权限和磁盘空间", batchNumber, targetsFile, err))
		prog.addFailed(len(batch))
		prog.completeBatch()
		return
	}
	if prog.connectOnly() {
		// 本次执行已确认 SYN 权限不足：后续批次不再重复踩坑，直接使用 CONNECT。
		settings.ScanType = "c"
	}
	args := settings.args(targetsFile, outFile, mode, customPorts)
	commandText := strings.Join(append([]string{settings.Path}, args...), " ")
	log.Printf("扫描 %d 批次 %d/%d 启动(%d 个目标): %s", scanID, batchNumber, totalBatches, len(batch), commandText)

	outcome := r.runBatchWithRetry(scanID, settings, mode, customPorts, targetsFile, outFile, batchNumber, prog)
	stopped := r.isStopped(scanID)
	if outcome.drainClosed {
		// 管道被强制关闭，已无法证明 stdout 实时输出完整：终态必须是 partial/failed，
		// 不能 done、也不触发“完整结果”才有的白名单比对与端口风险告警；结果仍由输出文件补齐。
		message := fmt.Sprintf("批次 %d 的 naabu 主进程已退出，但遗留子进程仍占用输出管道；已在 %s 内强制关闭管道并终止遗留进程，实时输出可能不完整，本批结果以输出文件去重补齐", batchNumber, pipeWaitDelay)
		log.Printf("扫描 %d %s", scanID, message)
		_ = r.st.AddScanEvent(scanID, "warn", "drain", message)
		prog.addMessage(message)
	}

	// 用户终止导致的批次中断不计入已处理（已实时入库的结果保留）；存储失败的批次也不计已处理。
	if !(stopped && outcome.runErr != nil) && outcome.storeErr == nil {
		prog.addProcessed(len(batch))
	}
	if outcome.runErr != nil || outcome.parseErr != nil || outcome.streamErr != nil || outcome.timedOut || outcome.storeErr != nil || outcome.groupUnreaped || outcome.drainClosed || outcome.truncatedStdout || outcome.oversizedLines > 0 {
		// drainClosed/truncatedStdout/oversizedLines 表示本批实时输出无法证明完整，
		// 同样计入异常目标，不能只停留在 partial 终态。
		prog.addFailed(len(batch))
	}
	// 域名解析失败的目标 naabu 不会实际扫描：计入异常目标并阻止终态为 done。
	if outcome.resolutionFailures > 0 {
		failures := outcome.resolutionFailures
		if failures > len(batch) {
			failures = len(batch)
		}
		prog.addFailed(failures)
		prog.markUnreliable()
		message := fmt.Sprintf("批次 %d 有 %d 个目标域名解析失败，naabu 不会扫描解析失败的目标；失败目标样例：%s。为避免虚报完成，本次执行不会标记为 done",
			batchNumber, outcome.resolutionFailures, strings.Join(outcome.resolutionSamples, "、"))
		log.Printf("扫描 %d %s", scanID, message)
		_ = r.st.AddScanEvent(scanID, "warn", "resolve", message)
		prog.addMessage(message)
	}
	if outcome.malformedLines > 0 {
		prog.markUnreliable()
		message := fmt.Sprintf("批次 %d 的 naabu 输出中有 %d 行结构化数据无法解析，无法证明实时/文件输出完整；样例：%s",
			batchNumber, outcome.malformedLines, strings.Join(outcome.malformedSamples, " | "))
		log.Printf("扫描 %d %s", scanID, message)
		_ = r.st.AddScanEvent(scanID, "warn", "parse", message)
		prog.addMessage(message)
	}
	if outcome.storeErr != nil {
		prog.addMessage(fmt.Sprintf("批次 %d 实时保存扫描结果失败：%v；原始输出保留在 %s", batchNumber, outcome.storeErr, outFile))
	}
	if outcome.timedOut {
		prog.addMessage(fmt.Sprintf("批次 %d 达到任务有效扫描总超时 %s，naabu 进程组已强制终止；本批新增 %d 条结果，暂停时间不计入超时", batchNumber, timeout, outcome.results))
	} else if outcome.runErr != nil && !stopped {
		attemptNote := ""
		if outcome.attempts > 1 {
			attemptNote = fmt.Sprintf("（共 %d 次尝试，已做 %d 次额外重试）", outcome.attempts, outcome.attempts-1)
		}
		prog.addMessage(fmt.Sprintf("批次 %d naabu 进程异常退出%s：%v\n标准输出：%s\n错误输出：%s", batchNumber, attemptNote, outcome.runErr, limitedOutput(outcome.stdout), limitedOutput(outcome.stderr)))
	}
	// 重试后成功只记事件和日志：不计入 messages，避免把本已成功的执行误标为 partial/failed。
	if outcome.attempts > 1 && outcome.runErr == nil && outcome.storeErr == nil {
		message := fmt.Sprintf("批次 %d 第 %d 次尝试成功（前 %d 次为 naabu 瞬态失败），结果已按端口去重入库", batchNumber, outcome.attempts, outcome.attempts-1)
		log.Printf("扫描 %d %s", scanID, message)
		_ = r.st.AddScanEvent(scanID, "info", "retry", message)
	}
	if outcome.streamErr != nil {
		prog.addMessage(fmt.Sprintf("批次 %d 读取 naabu 实时输出失败：%v；已保存实时结果，并继续从输出文件去重补齐", batchNumber, outcome.streamErr))
	}
	if outcome.truncatedStdout && !stopped && !outcome.timedOut {
		message := fmt.Sprintf("批次 %d 的 naabu 实时输出在行中被截断（进程被终止或输出管道被关闭），实时结果不完整；已从输出文件去重补齐，但本次执行不会标记为 done", batchNumber)
		log.Printf("扫描 %d %s", scanID, message)
		_ = r.st.AddScanEvent(scanID, "warn", "truncate", message)
		prog.addMessage(message)
	}
	if outcome.oversizedLines > 0 {
		message := fmt.Sprintf("批次 %d 的 naabu 实时输出中有 %d 行超过单行上限 %d 字节，已按有界策略丢弃（内存不会随输出增长）；本批实时结果可能不完整，已从输出文件去重补齐，但本次执行不会标记为 done",
			batchNumber, outcome.oversizedLines, stdoutLineLimit)
		log.Printf("扫描 %d %s", scanID, message)
		_ = r.st.AddScanEvent(scanID, "warn", "oversize", message)
		prog.addMessage(message)
	}
	if outcome.groupUnreaped {
		// 无法证明后代进程已退出：既不能伪报结论，也不自动重试（重试只会再造一个失控进程）。
		message := fmt.Sprintf("批次 %d 结束后无法确认 naabu 后代进程已全部退出（%s）；为避免残留进程继续累积，平台不会对本次批次自动重试，请检查系统中是否有残留 naabu 进程并手动清理",
			batchNumber, processGroupLimitation())
		log.Printf("扫描 %d %s", scanID, message)
		_ = r.st.AddScanEvent(scanID, "warn", "cleanup", message)
		prog.addMessage(message)
	}
	if outcome.parseErr != nil {
		prog.addMessage(fmt.Sprintf("批次 %d 读取输出文件 %q 不完整：%v；本批实时及文件去重后新增 %d 条结果", batchNumber, outFile, outcome.parseErr, outcome.results))
	}
	prog.completeBatch()
	if err := r.persistProgress(scanID, prog, commandText); err != nil {
		prog.addMessage(fmt.Sprintf("批次 %d 完成后保存进度失败：%v", batchNumber, err))
	}
	log.Printf("扫描 %d 批次 %d/%d 已处理，累计 %d 条开放端口", scanID, batchNumber, totalBatches, prog.snapshot().openPorts)
}

// persistProgress 用任务 15 的单调合并接口写入进度：processed/failed/completed/openPorts/results
// 只增不减，迟到的旧快照不会覆盖更高值；command 仅非空时覆盖。
func (r *Runner) persistProgress(scanID int64, prog *scanProgress, command string) error {
	snap := prog.snapshot()
	return r.st.ApplyScanProgress(scanID, store.ScanProgress{
		Processed:    snap.processed,
		Failed:       snap.failed,
		CurrentBatch: snap.completed,
		OpenPorts:    snap.openPorts,
		Results:      snap.results,
		Command:      command,
	})
}

// pauseHealInterval 是暂停期间的自愈巡检间隔：暂停中的 naabu 进程全部退出时没有任何
// 控制变更通知（不会 notify），必须靠周期性巡检发现“已无进程可恢复”并自动解除暂停。
// 它只用于自愈巡检，不再承担“补偿丢失唤醒”的职责——唤醒由 controlWatch 的原子快照保证。
const pauseHealInterval = 300 * time.Millisecond

// pausedWaitHook 仅用于测试：waitWhilePaused 拿到原子快照（状态 + 代际通道）后、进入 select 前
// 调用一次，用确定性的方式模拟“刚读到 paused 就发生 Resume”的时序。生产环境为 nil。
var pausedWaitHook func(scanID int64)

// waitWhilePaused 阻塞直到取消暂停或扫描终止；返回 true 表示已终止（调用方应跳过该批次）。
// 暂停期间若所有 naabu 进程都已异常退出，则自动解除暂停，避免待处理批次永久等待。
//
// 状态与代际通知通道由 controlWatch 在同一次加锁内取得：Resume/Stop 要么发生在快照前
// （快照已看到新状态），要么发生在快照后（它关闭的正是本函数持有的通道），不会丢唤醒。
func (r *Runner) waitWhilePaused(scanID int64) bool {
	heal := time.NewTicker(pauseHealInterval)
	defer heal.Stop()
	for {
		paused, stopped, _, changed, ok := r.controlWatch(scanID)
		if !ok || stopped {
			return true
		}
		if !paused {
			return false
		}
		if hook := pausedWaitHook; hook != nil {
			hook(scanID)
		}
		if r.healPausedAfterProcessExit(scanID) {
			return false
		}
		select {
		case <-changed:
			// 状态已变化（Resume/Stop/新增进程）：重新做一次原子快照。
		case <-heal.C:
			// 周期巡检只用于“暂停期间进程已全部退出”的自愈。
		}
	}
}

// streamReadError 过滤掉能确认由主动关闭管道造成的读取错误（cmd.Wait 会关闭 StdoutPipe 读端，
// WaitDelay 收尾同样会关闭管道），这类 os.ErrClosed 不是真实读取失败；
// 其他错误一律保留，交由上层把终态判为 partial/failed。
func streamReadError(err error) error {
	if err == nil || errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

// stdoutLine 是读取协程交给主循环的一行 stdout。
// oversized=true 表示该行超过单行硬上限，text 已被丢弃（但读取已消费到行尾）。
type stdoutLine struct {
	text      string
	oversized bool
}

// readBoundedLine 从 reader 读取一行，内存占用始终不超过 limit（另加一个读缓冲块）：
//   - line 是去掉行尾 \n 的内容（超限时为空）；
//   - oversized 表示该行超过 limit，内容已被有界丢弃，但已消费到行尾，不会影响后续行；
//   - truncated 表示读到 EOF 时仍有残行（无换行结尾），属于“输出在行中被截断”；
//   - err == nil 表示读到完整的一行，err == io.EOF 表示已经到流尾且没有残行。
//
// 旧实现用 ReadString('\n')：一个永不换行的超长行会无限累积到内存里，
// 因此这里改为 ReadSlice 分块累积，超过 limit 立即丢弃并继续消费。
func readBoundedLine(reader *bufio.Reader, limit int) (line string, oversized, truncated bool, err error) {
	if reader == nil {
		return "", false, false, io.EOF
	}
	if limit < 1 {
		limit = 1
	}
	var buf []byte
	for {
		chunk, readErr := reader.ReadSlice('\n')
		if len(chunk) > 0 {
			if readErr == nil {
				// 本行以换行结尾：丢弃分隔符后再计入长度。
				chunk = chunk[:len(chunk)-1]
			}
			switch {
			case oversized:
				// 已超限：继续丢弃剩余分块，不再分配。
			case len(buf)+len(chunk) > limit:
				oversized = true
				buf = nil
			default:
				buf = append(buf, chunk...)
			}
		}
		switch {
		case readErr == nil:
			return string(buf), oversized, false, nil
		case errors.Is(readErr, bufio.ErrBufferFull):
			continue
		case errors.Is(readErr, io.EOF):
			// 没有换行结尾的残行：内容不完整，交由上层按“行中被截断”处理。
			return "", oversized, len(buf) > 0 || oversized, io.EOF
		default:
			return "", oversized, false, readErr
		}
	}
}

// runBatch 执行一批 naabu：实时解析 stdout 入库，结束后从 -o 文件去重补齐。
// 返回值必须为命名结果：defer 中回填的 stderr 才会真正返回给调用方（异常路径也能拿到有界错误输出）。
func (r *Runner) runBatch(scanID int64, settings NaabuSettings, args []string, outFile string, prog *scanProgress) (outcome batchOutcome) {
	// stderr 不是 *os.File，cmd.Wait 会等待其复制协程读到 EOF；
	// 因此必须用 CommandContext + WaitDelay 给 Wait 一个有界上界：
	// 主进程退出后若孙进程仍占住管道，WaitDelay 到期即强制关闭管道（返回 exec.ErrWaitDelay），
	// 而 Cancel 复用现有 Unix 进程组清理，超时/取消时连同孙进程一起 SIGKILL。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stderr := newTailBuffer(stderrLimit)
	cmd := exec.CommandContext(ctx, settings.Path, args...)
	cmd.WaitDelay = pipeWaitDelay
	cmd.Cancel = func() error { return killProcess(cmd) }
	prepareProcess(cmd)
	// stdout 使用自建管道而不是 cmd.StdoutPipe：cmd.Wait 会在子进程退出后关闭读端，
	// 与并发读取竞争时可能把最后一行截断（被误判为结构化数据损坏）。
	// 自建管道的读端由我们持有、写端交给子进程继承，读到 EOF 才算读完。
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		outcome.runErr = err
		outcome.startFailed = true
		return outcome
	}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = stdoutWriter.Close()
		_ = stdoutReader.Close()
		outcome.runErr = err
		outcome.startFailed = true
		outcome.stderr = stderr.String()
		return outcome
	}
	// 子进程已继承写端副本；父进程必须关闭自己的写端，读端才能在子进程全部退出后收到 EOF。
	_ = stdoutWriter.Close()
	// 启动后的受控化（Windows 加入 Job Object；Unix 已由 Setpgid 完成）失败时，
	// 平台无法枚举/确认后代进程，只能按“收尾不可确认”处理：不伪报收敛、不自动重试。
	if err := afterStartProcess(cmd); err != nil {
		outcome.cleanupUnavailable = true
		if outcome.runErr == nil {
			outcome.runErr = fmt.Errorf("naabu 子进程未能纳入受控作业/进程组：%v", err)
		}
		_ = killProcess(cmd)
	}
	if err := r.registerProcess(scanID, cmd); err != nil && outcome.runErr == nil {
		outcome.runErr = err
	}
	defer func() {
		// 无论是否触发 WaitDelay，主进程退出后都必须主动终止本次进程组并确认收敛，
		// 再清除登记、释放运行锁：仅关闭管道不能算收敛（遗留孙进程会继续占端口/CPU）。
		leftover, converged := cleanupProcessGroup(cmd, processGroupSettleTimeout)
		if leftover && !outcome.timedOut {
			// 主进程退出后仍有子进程存活：实时输出可能已被截断，无法证明完整。
			outcome.drainClosed = true
		}
		if outcome.cleanupUnavailable {
			// 未纳入受控作业：根本无法证明后代进程已退出，不得伪报收敛。
			converged = false
		}
		if !converged {
			outcome.groupUnreaped = true
			if outcome.runErr == nil {
				outcome.runErr = fmt.Errorf("naabu 遗留子进程未能在 %s 内退出，进程组未收敛（%s）", processGroupSettleTimeout, processGroupLimitation())
			}
		}
		r.clearProcess(scanID, cmd)
		outcome.stderr = stderr.String()
	}()

	monitor := newResourceMonitor(scanID, int64(cmd.Process.Pid), settings, r.st, r.eng)
	// lines/streamDone 只由读取协程关闭和发送，主循环只通过下面两个本地接收变量订阅。
	// 主循环不得重新赋值 lines/streamDone 本身：否则与读取协程的 close(lines) 形成数据竞争，
	// 严重时会在“主循环已置空 + 读取协程仍 close”时 panic: close of nil channel。
	lines := make(chan stdoutLine, 128)
	streamDone := make(chan error, 1)
	readStop := make(chan struct{})
	var stopOnce sync.Once
	stopReader := func() {
		stopOnce.Do(func() {
			close(readStop)
			// 关闭读端用来打断阻塞中的 Read，保证读取协程一定能退出。
			_ = stdoutReader.Close()
		})
	}
	defer stopReader()
	go func() {
		reader := bufio.NewReaderSize(stdoutReader, 64*1024)
		for {
			line, oversized, truncated, readErr := readBoundedLine(reader, stdoutLineLimit)
			if truncated {
				// 行尾没有换行符：输出在行中被截断（进程被终止或管道被强制关闭），
				// 残行既不是完整结果，也不能当作“结构化数据损坏”。
				close(lines)
				streamDone <- errOutputStreamTruncated
				return
			}
			if oversized || readErr == nil {
				select {
				case lines <- stdoutLine{text: line, oversized: oversized}:
				case <-readStop:
					close(lines)
					streamDone <- nil
					return
				}
			}
			if readErr != nil {
				close(lines)
				if errors.Is(readErr, io.EOF) {
					// 正常读到流尾：输出完整。
					streamDone <- nil
					return
				}
				streamDone <- readErr
				return
			}
		}
	}()
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	flushTicker := time.NewTicker(500 * time.Millisecond)
	resourceTicker := time.NewTicker(5 * time.Second)
	timeoutTimer := time.NewTimer(time.Second)
	defer flushTicker.Stop()
	defer resourceTicker.Stop()
	defer timeoutTimer.Stop()
	var timeoutC <-chan time.Time
	resetTimeout := func() {
		paused, _, deadline, _, _ := r.controlWatch(scanID)
		if !timeoutTimer.Stop() {
			select {
			case <-timeoutTimer.C:
			default:
			}
		}
		if paused || deadline.IsZero() {
			timeoutC = nil
			return
		}
		remaining := time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		}
		timeoutTimer.Reset(remaining)
		timeoutC = timeoutTimer.C
	}
	resetTimeout()

	// pending 是有硬上限的待写入缓冲：条数或字节任一到达上限立即刷库，
	// 刷库固定使用 InsertResultsBatch，并按数据库实际新增数更新进度。
	pending := make([]store.Result, 0, dbFlushRows)
	pendingKeys := make(map[string]struct{}, dbFlushRows)
	pendingBytes := 0
	var stdoutTail strings.Builder
	failStore := func(err error) {
		if outcome.storeErr == nil {
			outcome.storeErr = err
			_ = r.killBatchProcess(scanID, cmd)
		}
	}
	flush := func() error {
		if len(pending) == 0 || outcome.storeErr != nil {
			return nil
		}
		batch := append([]store.Result(nil), pending...)
		pending = pending[:0]
		clear(pendingKeys)
		pendingBytes = 0
		stats, err := r.st.InsertResultsBatch(scanID, batch)
		if stats.Inserted > 0 {
			// 只按数据库实际新增数计数：重试、stdout 与文件补读的重复行都会被唯一索引忽略。
			prog.addInserted(stats.Inserted)
			outcome.results += stats.Inserted
		}
		if hook := resultFlushHook; hook != nil {
			hook(stats)
		}
		if err != nil {
			return err
		}
		return r.persistProgress(scanID, prog, "")
	}
	queue := func(result store.Result) {
		key := engine.ResultKey(result.IP, result.Port, result.Proto)
		if prog.hasRecent(key) {
			return
		}
		if _, exists := pendingKeys[key]; exists {
			return
		}
		prog.remember(key)
		pendingKeys[key] = struct{}{}
		pending = append(pending, result)
		pendingBytes += len(result.IP) + len(result.Proto) + len(result.Service) + 32
	}
	needsFlush := func() bool {
		return len(pending) >= dbFlushRows || pendingBytes >= pendingMaxBytes
	}
	flushIfNeeded := func() {
		if !needsFlush() {
			return
		}
		if err := flush(); err != nil {
			failStore(err)
		}
	}

	// 每一代控制变更通道都会被广播关闭；收到通知后重新订阅新一代，
	// 保证 Pause/Resume/Stop 同时作用于所有活跃批次。
	// 状态与通道在同一次加锁内取得，避免“刚订阅就错过上一代通知”。
	_, _, _, changed, _ := r.controlWatch(scanID)
	resourceC := resourceTicker.C
	// lineC/streamC 是主循环的接收端视图，置 nil 即停止订阅；lines/streamDone 本身保持不变。
	lineC := (<-chan stdoutLine)(lines)
	streamC := (<-chan error)(streamDone)
	var drainTimer *time.Timer
	var drainC <-chan time.Time
	defer func() {
		if drainTimer != nil {
			drainTimer.Stop()
		}
	}()
	startDrain := func() {
		if drainC != nil || lineC == nil {
			return
		}
		drainTimer = time.NewTimer(stdoutDrainGrace)
		drainC = drainTimer.C
	}
	for waitDone != nil || lineC != nil || streamC != nil {
		select {
		case item, ok := <-lineC:
			if !ok {
				lineC = nil
				continue
			}
			if item.oversized {
				// 超过单行硬上限：内容已被有界丢弃（不会累积内存），
				// 但无法证明实时输出完整，因此计数并阻断 done。
				outcome.oversizedLines++
				prog.markUnreliable()
				continue
			}
			line := item.text
			appendProcessOutput(&stdoutTail, line)
			if outcome.storeErr == nil {
				parsed := parseOutputLine(line)
				switch parsed.kind {
				case parseResult:
					queue(parsed.result)
					flushIfNeeded()
				case parseResolutionFailure:
					outcome.resolutionFailures++
					if len(outcome.resolutionSamples) < resolutionSampleLimit {
						outcome.resolutionSamples = append(outcome.resolutionSamples, parsed.target)
					}
					prog.markUnreliable()
				case parseMalformed:
					outcome.malformedLines++
					if len(outcome.malformedSamples) < resolutionSampleLimit {
						outcome.malformedSamples = append(outcome.malformedSamples, truncateText(line, 200))
					}
					prog.markUnreliable()
				}
			}
		case err := <-waitDone:
			if errors.Is(err, exec.ErrWaitDelay) {
				// 主进程本身已正常退出，只是 stdout/stderr 管道被遗留子进程占住并超过 WaitDelay：
				// 按成功收尾（结果由输出文件去重补齐），管道已被 Wait 强制关闭。
				err = nil
				outcome.drainClosed = true
			}
			outcome.runErr = err
			waitDone = nil
			timeoutC = nil
			resourceC = nil
			startDrain()
		case err := <-streamC:
			if errors.Is(err, errOutputStreamTruncated) {
				// 输出在行中被截断：不当作结构化数据损坏，而是“实时输出不完整”，
				// 由输出文件去重补齐后仍按不完整处理（终态不得为 done）。
				outcome.truncatedStdout = true
			} else {
				// 只忽略能确认由主动关闭（关闭读端 / WaitDelay 收尾）造成的
				// os.ErrClosed；其他读取错误必须保留，由上层把终态判为 partial/failed。
				outcome.streamErr = streamReadError(err)
			}
			streamC = nil
		case <-drainC:
			// naabu 已退出但仍有孙进程占住 stdout 管道时，最多再等一个宽限期，
			// 保证批次有界收敛、运行标志能及时释放。
			outcome.drainClosed = true
			stopReader()
			lineC = nil
			streamC = nil
			drainC = nil
		case <-flushTicker.C:
			if err := flush(); err != nil {
				failStore(err)
			}
		case <-resourceC:
			monitor.Sample(time.Now())
		case <-changed:
			// 代际通道被关闭：重新做一次原子快照（状态 + deadline + 新一代通道）。
			_, _, _, changed, _ = r.controlWatch(scanID)
			resetTimeout()
		case <-timeoutC:
			// 定时器触发前复核当前暂停状态与有效 deadline：暂停期间预算冻结，
			// 若用户恰好在到期瞬间暂停/恢复，必须重新计时而不是误杀进程。
			paused, stopped, deadline, _, _ := r.controlWatch(scanID)
			if paused || stopped || deadline.IsZero() || time.Now().Before(deadline) {
				resetTimeout()
				continue
			}
			outcome.timedOut = true
			timeoutC = nil
			_ = r.killBatchProcess(scanID, cmd)
		}
	}
	if err := flush(); err != nil {
		failStore(err)
	}

	// 文件补读与 stdout 使用同一套流式解析：逐行回调、不构造全量结果切片。
	if outcome.storeErr == nil {
		fileErr := streamResultFile(outFile,
			func(result store.Result) bool {
				queue(result)
				if needsFlush() {
					if err := flush(); err != nil {
						failStore(err)
						return false
					}
				}
				return outcome.storeErr == nil
			},
			func(target string) {
				outcome.resolutionFailures++
				if len(outcome.resolutionSamples) < resolutionSampleLimit {
					outcome.resolutionSamples = append(outcome.resolutionSamples, target)
				}
				prog.markUnreliable()
			},
			func(line string) {
				outcome.malformedLines++
				if len(outcome.malformedSamples) < resolutionSampleLimit {
					outcome.malformedSamples = append(outcome.malformedSamples, truncateText(line, 200))
				}
				prog.markUnreliable()
			},
		)
		outcome.parseErr = fileErr
		if err := flush(); err != nil {
			failStore(err)
		}
	}
	outcome.stdout = stdoutTail.String()
	return outcome
}

// runBatchWithRetry 在批次级别做有界重试：仅对 naabu 进程启动瞬态错误或非零退出重试，
// 首次 + 最多两次额外尝试（短退避，可被暂停/终止打断）；用户终止、总超时、存储与
// 配置/目标类错误一律不重试。SYN 因原始套接字/权限能力不足失败时，后续尝试降级为 CONNECT。
func (r *Runner) runBatchWithRetry(scanID int64, settings NaabuSettings, mode, customPorts, targetsFile, outFile string, batchNumber int, prog *scanProgress) batchOutcome {
	var final batchOutcome
	lastStderr := ""
	results := 0
	for attempt := 1; attempt <= batchRetryAttempts; attempt++ {
		if attempt > 1 {
			// 每次尝试前重新读取本次执行的降级状态：并发批次已确认 SYN 权限不足时，
			// 后续重试直接使用 CONNECT（总尝试次数仍不超过三次）。
			if prog.connectOnly() {
				settings.ScanType = "c"
			}
			// 重试会重新启动进程：先检查暂停修正后的有效截止时间，预算耗尽直接判超时。
			if r.retryBudgetExhausted(scanID) {
				final.timedOut = true
				final.attempts = attempt - 1
				final.stderr = lastStderr
				if final.runErr == nil {
					final.runErr = fmt.Errorf("任务有效扫描总超时，剩余重试未执行")
				}
				return final
			}
		}
		if r.isStopped(scanID) || r.waitWhilePaused(scanID) {
			// 未实际执行：带上错误让调用方不计入已处理，保持原有终止语义。
			if final.runErr == nil {
				final.runErr = fmt.Errorf("扫描已终止，当前批次未执行")
			}
			final.attempts = attempt
			final.stderr = lastStderr
			return final
		}
		if attempt > 1 {
			// 丢弃上次失败尝试的输出文件，避免重试结果与旧文件混在一起；结果仍由端口去重集保障。
			_ = os.Remove(outFile)
		}
		args := settings.args(targetsFile, outFile, mode, customPorts)
		attemptOut := r.runBatch(scanID, settings, args, outFile, prog)
		results += attemptOut.results
		attemptOut.results = results
		attemptOut.attempts = attempt
		if attemptOut.stderr != "" {
			lastStderr = attemptOut.stderr
		} else {
			attemptOut.stderr = lastStderr
		}
		final = attemptOut
		if final.storeErr != nil || final.timedOut || r.isStopped(scanID) || !batchRetryable(final) {
			return final
		}
		if attempt == batchRetryAttempts {
			return final
		}
		// 仅在确定要再试时降级：stderr 明确指向 SYN/raw socket/权限能力问题时改用 CONNECT。
		if settings.ScanType != "c" && synCapabilityFailure(final.stderr) {
			settings.ScanType = "c"
			r.noteSynFallback(scanID, batchNumber, final.stderr, prog)
		}
		proceed, budgetExhausted := r.waitBeforeRetry(scanID, batchRetryBackoff*time.Duration(attempt))
		if budgetExhausted {
			// 退避期间有效截止时间已耗尽：禁止再启动进程，直接按超时收尾。
			final.timedOut = true
			return final
		}
		if !proceed {
			return final
		}
	}
	return final
}

// batchRetryable 判断一次批次失败是否属于可重试的瞬态错误：
// 启动阶段的瞬态错误（如资源暂时不可用、文本忙）与非零退出；
// 工具缺失/无执行权限、参数配置类错误、存储失败、超时、被信号终止一律不重试。
func batchRetryable(outcome batchOutcome) bool {
	if outcome.timedOut || outcome.storeErr != nil || outcome.runErr == nil || outcome.groupUnreaped {
		return false
	}
	if outcome.startFailed {
		return isTransientStartError(outcome.runErr)
	}
	var exitErr *exec.ExitError
	if !errors.As(outcome.runErr, &exitErr) || exitErr.ExitCode() <= 0 {
		return false
	}
	return !stderrIndicatesConfigError(outcome.stderr)
}

// stderrIndicatesConfigError 识别 naabu 参数/配置类错误；这类错误重试也不会成功。
func stderrIndicatesConfigError(stderr string) bool {
	text := strings.ToLower(stderr)
	for _, marker := range []string{
		"flag provided but not defined",
		"unknown flag",
		"incorrect usage",
		"invalid value",
		"invalid argument",
		"no such file or directory",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// synCapabilityFailure 判断 stderr 是否明确指向 SYN 扫描的原始套接字/权限能力问题。
// 关键词取自 naabu 自身报错（SYN 不可用提示、raw socket、NET_RAW 等）；
// 笼统的权限报错必须同时出现 tcp/socket/syn 一类上下文才算，避免把输出路径无权限等误判为 SYN 降级。
func synCapabilityFailure(stderr string) bool {
	text := strings.ToLower(stderr)
	if text == "" {
		return false
	}
	for _, marker := range []string{
		"syn scan is not possible",
		"privileged/net_raw",
		"cap_net_raw",
		"raw socket",
		"could not setup ip4:tcp",
		"could not determine source ip",
		"route lookup failed",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	permission := false
	for _, marker := range []string{"operation not permitted", "permission denied", "requires root", "root privileges"} {
		if strings.Contains(text, marker) {
			permission = true
			break
		}
	}
	if !permission {
		return false
	}
	for _, hint := range []string{"syn", "socket", "tcp", "privileg", "raw", "capability"} {
		if strings.Contains(text, hint) {
			return true
		}
	}
	return false
}

// noteSynFallback 将本次执行标记为仅 CONNECT（后续批次也不再尝试 SYN），并记录一次事件。
// 参数依据本机 naabu --help：-scan-type/-s 支持 SYN/CONNECT，现有实现用 c 表示 CONNECT。
func (r *Runner) noteSynFallback(scanID int64, batchNumber int, stderr string, prog *scanProgress) {
	if !prog.markConnectOnly() {
		return
	}
	message := fmt.Sprintf("批次 %d 的 SYN 扫描因原始套接字/权限能力不足失败，本次执行后续尝试与批次自动降级为 CONNECT 扫描（naabu -scan-type c）；如需 SYN 扫描请为运行账号授予 CAP_NET_RAW 或 root 权限，平台不会自动提权或安装工具", batchNumber)
	log.Printf("扫描 %d %s；naabu 错误输出：%s", scanID, message, limitedOutput(stderr))
	_ = r.st.AddScanEvent(scanID, "warn", "degrade", message+"\n错误输出："+limitedOutput(stderr))
}

// waitBeforeRetry 在重试前做短退避；退避期间持续检查有效截止时间、暂停与终止，返回：
// proceed 表示可以继续下一次尝试；budgetExhausted 表示有效扫描预算已耗尽，
// 调用方必须直接按超时收敛、不得再启动进程。
func (r *Runner) waitBeforeRetry(scanID int64, delay time.Duration) (proceed bool, budgetExhausted bool) {
	deadline := time.Now().Add(delay)
	for {
		if r.isStopped(scanID) {
			return false, false
		}
		paused, _, _ := r.controlSnapshot(scanID)
		if paused {
			// 暂停期间不消耗退避与有效扫描预算：等暂停解除（或自愈）后再继续。
			if r.waitWhilePaused(scanID) {
				return false, false
			}
			continue
		}
		if r.retryBudgetExhausted(scanID) {
			return false, true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return true, false
		}
		wait := remaining
		if wait > retryBudgetPoll {
			wait = retryBudgetPoll
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-r.changedChan(scanID):
		}
		timer.Stop()
	}
}

// changedChan 返回当前执行的控制变更通知通道（只读，代际通道）；执行已失效时返回 nil。
// 调用方拿到通道后必须重新订阅：每次 notify 都会关闭旧通道并建立新一代通道。
func (r *Runner) changedChan(scanID int64) <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.scanID != scanID {
		return nil
	}
	return r.active.changed
}

func appendProcessOutput(out *strings.Builder, line string) {
	out.WriteString(line)
	out.WriteByte('\n')
	if out.Len() > 4000 {
		value := out.String()
		out.Reset()
		out.WriteString(value[len(value)-3500:])
	}
}
