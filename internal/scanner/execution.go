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

	processed, failedTargets, openPorts := 0, 0, 0
	seenResults := make(map[string]struct{})
	messages := make([]string, 0)
	for batchIndex := 0; batchIndex < totalBatches; batchIndex++ {
		batchNumber := batchIndex + 1
		paused, stopped, deadline := r.controlSnapshot(scanID)
		if stopped {
			break
		}
		if !paused && !deadline.IsZero() && time.Now().After(deadline) {
			messages = append(messages, fmt.Sprintf("任务有效扫描总超时 %s，剩余 %d 个目标规格未开始处理（暂停时间不计入）", timeout, len(specs)-processed))
			break
		}
		end := (batchIndex + 1) * scanBatchSize
		if end > len(specs) {
			end = len(specs)
		}
		batch := specs[batchIndex*scanBatchSize : end]
		targetsFile := filepath.Join(dataDir, fmt.Sprintf("batch_%04d_targets.txt", batchNumber))
		outFile := filepath.Join(dataDir, fmt.Sprintf("batch_%04d.out", batchNumber))
		if err := writeTargets(targetsFile, batch); err != nil {
			messages = append(messages, fmt.Sprintf("批次 %d 写入目标文件 %q 失败：%v；本批及剩余目标未处理，请检查目录权限和磁盘空间", batchNumber, targetsFile, err))
			break
		}

		args := settings.args(targetsFile, outFile, mode, customPorts)
		commandText := strings.Join(append([]string{settings.Path}, args...), " ")
		if err := r.st.UpdateScanProgress(scanID, processed, failedTargets, batchNumber, openPorts, commandText); err != nil {
			messages = append(messages, fmt.Sprintf("批次 %d 保存进度失败，扫描中止：%v", batchNumber, err))
			break
		}
		log.Printf("扫描 %d 批次 %d/%d 启动(%d 个目标): %s", scanID, batchNumber, totalBatches, len(batch), commandText)

		outcome := r.runBatch(scanID, settings, args, outFile, seenResults, &openPorts)
		stopped = r.isStopped(scanID)
		if stopped && outcome.runErr != nil {
			// 用户终止的当前批次不伪记为全部处理完成，已实时保存的结果不受影响。
			break
		}
		if outcome.storeErr != nil {
			messages = append(messages, fmt.Sprintf("批次 %d 实时保存扫描结果失败：%v；原始输出保留在 %s，后续批次已停止", batchNumber, outcome.storeErr, outFile))
			break
		}

		processed += len(batch)
		if outcome.runErr != nil || outcome.parseErr != nil || outcome.streamErr != nil || outcome.timedOut {
			failedTargets += len(batch)
		}
		if outcome.timedOut {
			messages = append(messages, fmt.Sprintf("批次 %d 达到任务有效扫描总超时 %s，naabu 进程组已强制终止；本批新增 %d 条结果，暂停时间不计入超时", batchNumber, timeout, outcome.results))
		} else if outcome.runErr != nil {
			messages = append(messages, fmt.Sprintf("批次 %d naabu 进程异常退出：%v\n标准输出：%s\n错误输出：%s", batchNumber, outcome.runErr, limitedOutput(outcome.stdout), limitedOutput(outcome.stderr)))
		}
		if outcome.streamErr != nil {
			messages = append(messages, fmt.Sprintf("批次 %d 读取 naabu 实时输出失败：%v；已保存实时结果，并继续从输出文件去重补齐", batchNumber, outcome.streamErr))
		}
		if outcome.parseErr != nil {
			messages = append(messages, fmt.Sprintf("批次 %d 读取输出文件 %q 不完整：%v；本批实时及文件去重后新增 %d 条结果", batchNumber, outFile, outcome.parseErr, outcome.results))
		}
		if err := r.st.UpdateScanProgress(scanID, processed, failedTargets, batchNumber, openPorts, commandText); err != nil {
			messages = append(messages, fmt.Sprintf("批次 %d 完成后保存进度失败，扫描中止：%v", batchNumber, err))
			break
		}
		log.Printf("扫描 %d 批次 %d/%d 已处理，累计 %d 条开放端口", scanID, batchNumber, totalBatches, openPorts)
		if stopped || outcome.timedOut {
			break
		}
	}

	elapsed := time.Since(start).Round(time.Second)
	message := strings.Join(messages, "\n\n")
	status := "done"
	if r.isStopped(scanID) {
		status = "stopped"
		if message != "" {
			message += "\n\n"
		}
		message += "扫描已由用户或平台停止，当前展示的是停止前已发现的结果；不执行白名单比对和端口风险告警。"
	} else if message != "" {
		status = "failed"
		if openPorts > 0 {
			status = "partial"
		}
		message += "\n\n不完整结果不会执行白名单比对和告警。"
	}
	if err := r.st.FinishScanStatus(scanID, status, openPorts, message); err != nil {
		log.Printf("更新扫描状态失败: %v", err)
	}
	log.Printf("扫描 %d 结束(%s): 已处理 %d/%d 个目标，异常目标 %d 个，开放端口 %d 条，耗时 %s",
		scanID, status, processed, len(specs), failedTargets, openPorts, elapsed)
	// 任务结束时无论成败只发一条飞书汇总；仅完整完成的执行才比对白名单并生成端口风险告警。
	var newAlerts []store.Alert
	if status == "done" {
		newAlerts = r.eng.AfterScan(scanID)
	}
	r.eng.NotifyScanSummary(scanID, status, newAlerts)
}

func (r *Runner) runBatch(scanID int64, settings NaabuSettings, args []string, outFile string, seen map[string]struct{}, openPorts *int) batchOutcome {
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
		for _, result := range batch {
			seen[engine.ResultKey(result.IP, result.Port, result.Proto)] = struct{}{}
		}
		*openPorts += len(batch)
		outcome.results += len(batch)
		pending = pending[:0]
		clear(pendingKeys)
		return r.st.UpdateScanOpenPorts(scanID, *openPorts)
	}
	queue := func(result store.Result) {
		key := engine.ResultKey(result.IP, result.Port, result.Proto)
		if _, exists := seen[key]; exists {
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
