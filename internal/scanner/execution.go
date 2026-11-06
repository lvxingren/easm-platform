package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

type batchOutcome struct {
	runErr    error
	parseErr  error
	streamErr error
	storeErr  error
	timedOut  bool
	results   int
	stdout    string
	stderr    string
}

// scanProgress 是并行多批次共享的执行状态，所有字段访问均由 mu 保护。
// seen 用于跨批次端口去重；openPorts/processed/failed/completed 为累加计数；messages 收集异常说明。
type scanProgress struct {
	mu        sync.Mutex
	seen      map[string]struct{}
	openPorts int
	processed int
	failed    int
	completed int
	messages  []string
}

type progressSnapshot struct {
	processed int
	failed    int
	completed int
	openPorts int
}

func (p *scanProgress) addMessage(m string) {
	p.mu.Lock()
	p.messages = append(p.messages, m)
	p.mu.Unlock()
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
	return progressSnapshot{processed: p.processed, failed: p.failed, completed: p.completed, openPorts: p.openPorts}
}

func (p *scanProgress) finalMessages() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.messages...)
}

// hasSeen 判断端口结果是否已在其他批次入过库（跨批次去重）。
func (p *scanProgress) hasSeen(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.seen[key]
	return ok
}

// markSeen 将一批结果键计入全局去重集，返回本批真正新增数与累计开放端口总数（避免并行重复计数）。
func (p *scanProgress) markSeen(keys []string) (added int, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, k := range keys {
		if _, ok := p.seen[k]; !ok {
			p.seen[k] = struct{}{}
			added++
		}
	}
	p.openPorts += added
	return added, p.openPorts
}

func (r *Runner) run(scanID int64, mode string, customPorts string, specs []store.TargetSpec) {
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

	settings := r.naabuSettings()
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

	dataDir := filepath.Join("data", fmt.Sprintf("scan_%d", scanID))
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		r.fail(scanID, fmt.Errorf("创建扫描数据目录 %q 失败：%v；请检查服务运行账号的目录权限", dataDir, err))
		return
	}

	prog := &scanProgress{seen: make(map[string]struct{})}
	concurrency := settings.concurrency()
	if concurrency > totalBatches {
		concurrency = totalBatches
	}
	if concurrency < 1 {
		concurrency = 1
	}
	log.Printf("扫描 %d 启动：%d 个目标规格分 %d 批，并发度 %d", scanID, len(specs), totalBatches, concurrency)

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
				if _, stopped, deadline := r.controlSnapshot(scanID); !stopped && !deadline.IsZero() && time.Now().After(deadline) {
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
	args := settings.args(targetsFile, outFile, mode, customPorts)
	commandText := strings.Join(append([]string{settings.Path}, args...), " ")
	log.Printf("扫描 %d 批次 %d/%d 启动(%d 个目标): %s", scanID, batchNumber, totalBatches, len(batch), commandText)

	outcome := r.runBatch(scanID, settings, args, outFile, prog)
	stopped := r.isStopped(scanID)

	// 用户终止导致的批次中断不计入已处理（已实时入库的结果保留）；存储失败的批次也不计已处理。
	if !(stopped && outcome.runErr != nil) && outcome.storeErr == nil {
		prog.addProcessed(len(batch))
	}
	if outcome.runErr != nil || outcome.parseErr != nil || outcome.streamErr != nil || outcome.timedOut || outcome.storeErr != nil {
		prog.addFailed(len(batch))
	}
	if outcome.storeErr != nil {
		prog.addMessage(fmt.Sprintf("批次 %d 实时保存扫描结果失败：%v；原始输出保留在 %s", batchNumber, outcome.storeErr, outFile))
	}
	if outcome.timedOut {
		prog.addMessage(fmt.Sprintf("批次 %d 达到任务有效扫描总超时 %s，naabu 进程组已强制终止；本批新增 %d 条结果，暂停时间不计入超时", batchNumber, timeout, outcome.results))
	} else if outcome.runErr != nil && !stopped {
		prog.addMessage(fmt.Sprintf("批次 %d naabu 进程异常退出：%v\n标准输出：%s\n错误输出：%s", batchNumber, outcome.runErr, limitedOutput(outcome.stdout), limitedOutput(outcome.stderr)))
	}
	if outcome.streamErr != nil {
		prog.addMessage(fmt.Sprintf("批次 %d 读取 naabu 实时输出失败：%v；已保存实时结果，并继续从输出文件去重补齐", batchNumber, outcome.streamErr))
	}
	if outcome.parseErr != nil {
		prog.addMessage(fmt.Sprintf("批次 %d 读取输出文件 %q 不完整：%v；本批实时及文件去重后新增 %d 条结果", batchNumber, outFile, outcome.parseErr, outcome.results))
	}
	prog.completeBatch()
	snap := prog.snapshot()
	if err := r.st.UpdateScanProgress(scanID, snap.processed, snap.failed, snap.completed, snap.openPorts, commandText); err != nil {
		prog.addMessage(fmt.Sprintf("批次 %d 完成后保存进度失败：%v", batchNumber, err))
	}
	log.Printf("扫描 %d 批次 %d/%d 已处理，累计 %d 条开放端口", scanID, batchNumber, totalBatches, snap.openPorts)
}

// waitWhilePaused 阻塞直到取消暂停或扫描终止；返回 true 表示已终止（调用方应跳过该批次）。
func (r *Runner) waitWhilePaused(scanID int64) bool {
	for {
		paused, stopped, _ := r.controlSnapshot(scanID)
		if stopped {
			return true
		}
		if !paused {
			return false
		}
		r.mu.Lock()
		var changed chan struct{}
		if r.active != nil && r.scanID == scanID {
			changed = r.active.changed
		}
		r.mu.Unlock()
		if changed == nil {
			return true
		}
		select {
		case <-changed:
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func (r *Runner) runBatch(scanID int64, settings NaabuSettings, args []string, outFile string, prog *scanProgress) batchOutcome {
	var outcome batchOutcome
	cmd := exec.Command(settings.Path, args...)
	prepareProcess(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		outcome.runErr = err
		return outcome
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		outcome.runErr = err
		outcome.stderr = stderr.String()
		return outcome
	}
	if err := r.registerProcess(scanID, cmd); err != nil && outcome.runErr == nil {
		outcome.runErr = err
	}
	defer func() {
		r.clearProcess(scanID, cmd)
		outcome.stderr = stderr.String()
	}()

	monitor := newResourceMonitor(scanID, int64(cmd.Process.Pid), settings, r.st, r.eng)
	lines := make(chan string, 128)
	streamDone := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
		streamDone <- sc.Err()
	}()
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	r.mu.Lock()
	control := r.active
	r.mu.Unlock()
	if control == nil {
		outcome.runErr = fmt.Errorf("扫描控制状态丢失")
		_ = killProcess(cmd)
		control = newExecutionControl()
	}

	flushTicker := time.NewTicker(500 * time.Millisecond)
	resourceTicker := time.NewTicker(5 * time.Second)
	timeoutTimer := time.NewTimer(time.Second)
	defer flushTicker.Stop()
	defer resourceTicker.Stop()
	defer timeoutTimer.Stop()
	var timeoutC <-chan time.Time
	resetTimeout := func() {
		paused, _, deadline := r.controlSnapshot(scanID)
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

	pending := make([]store.Result, 0, 50)
	pendingKeys := make(map[string]struct{})
	var stdoutTail strings.Builder
	flush := func() error {
		if len(pending) == 0 || outcome.storeErr != nil {
			return nil
		}
		batch := append([]store.Result(nil), pending...)
		if err := r.st.InsertResults(scanID, batch); err != nil {
			return err
		}
		keys := make([]string, 0, len(batch))
		for _, result := range batch {
			keys = append(keys, engine.ResultKey(result.IP, result.Port, result.Proto))
		}
		added, total := prog.markSeen(keys)
		outcome.results += added
		pending = pending[:0]
		clear(pendingKeys)
		return r.st.UpdateScanOpenPorts(scanID, total)
	}
	queue := func(result store.Result) {
		key := engine.ResultKey(result.IP, result.Port, result.Proto)
		if prog.hasSeen(key) {
			return
		}
		if _, exists := pendingKeys[key]; exists {
			return
		}
		pendingKeys[key] = struct{}{}
		pending = append(pending, result)
	}
	failStore := func(err error) {
		if outcome.storeErr == nil {
			outcome.storeErr = err
			_ = r.killBatchProcess(scanID, cmd)
		}
	}

	resourceC := resourceTicker.C
	for waitDone != nil || lines != nil || streamDone != nil {
		select {
		case line, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			appendProcessOutput(&stdoutTail, line)
			if outcome.storeErr == nil {
				if result, ok := parseResultLine(line); ok {
					queue(result)
					if len(pending) >= 50 {
						if err := flush(); err != nil {
							failStore(err)
						}
					}
				}
			}
		case err := <-waitDone:
			outcome.runErr = err
			waitDone = nil
			timeoutC = nil
			resourceC = nil
		case err := <-streamDone:
			outcome.streamErr = err
			streamDone = nil
		case <-flushTicker.C:
			if err := flush(); err != nil {
				failStore(err)
			}
		case <-resourceC:
			monitor.Sample(time.Now())
		case <-control.changed:
			resetTimeout()
		case <-timeoutC:
			outcome.timedOut = true
			timeoutC = nil
			_ = r.killBatchProcess(scanID, cmd)
		}
	}
	if err := flush(); err != nil {
		failStore(err)
	}

	fileResults, parseErr := parseOutput(outFile)
	outcome.parseErr = parseErr
	if outcome.storeErr == nil {
		for _, result := range fileResults {
			queue(result)
		}
		if err := flush(); err != nil {
			failStore(err)
		}
	}
	outcome.stdout = stdoutTail.String()
	return outcome
}

func parseResultLine(line string) (store.Result, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return store.Result{}, false
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return store.Result{}, false
	}
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || port < 1 || port > 65535 || strings.TrimSpace(parts[0]) == "" {
		return store.Result{}, false
	}
	return store.Result{IP: strings.TrimSpace(parts[0]), Port: port, Proto: "tcp", Status: 1}, true
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
