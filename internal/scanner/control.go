package scanner

import (
	"fmt"
	"log"
	"os/exec"
	"time"
)

// executionControl 贯穿一次执行的所有批次；并行多批次时 cmds 同时持有多个活跃 naabu 进程。
//
// 变更通知采用“代际通道 + 单调版本”的广播机制：changed 是当前这一代的通知通道，
// 每次状态变化都关闭当前代并建立新一代通道。所有等待者持有的都是各自代际的通道，
// 因此 Pause/Resume/Stop 能同时唤醒全部活跃批次，不会出现容量为 1 的共享通道
// 只唤醒其中一个等待者、其余批次继续睡眠的旧问题。
//
// 该结构体所有字段都由 Runner.mu 保护（与 running/scanID 同锁）。
type executionControl struct {
	cmds          map[*exec.Cmd]struct{}
	paused        bool
	pauseStarted  time.Time
	deadline      time.Time
	stopRequested bool
	// version 是控制状态版本号，每次状态变化递增，便于诊断与测试。
	version uint64
	changed chan struct{}
}

func newExecutionControl() *executionControl {
	return &executionControl{cmds: make(map[*exec.Cmd]struct{}), changed: make(chan struct{})}
}

// notify 递增控制版本、关闭当前代通知通道并建立新一代通道，从而广播给所有等待者。
// 调用方必须持有 Runner.mu：与状态读取使用同一把锁可避免“先检查状态、后注册等待”之间丢唤醒。
func (c *executionControl) notify() {
	c.version++
	close(c.changed)
	c.changed = make(chan struct{})
}

func (r *Runner) activeExecution(scanID int64) (*executionControl, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || r.scanID != scanID || r.active == nil {
		return nil, fmt.Errorf("执行 #%d 不是当前活动扫描，可能已结束或服务已重启", scanID)
	}
	return r.active, nil
}

// scanStatusPersistHook 仅用于测试模拟“状态落库延迟”，生产环境为 nil。
var scanStatusPersistHook func(scanID int64, status string)

// Pause 暂停当前执行。状态转换与状态落库统一由 stateApplyMu 串行化，
// 避免暂停自愈/恢复的迟到落库覆盖用户新的 Pause。
func (r *Runner) Pause(scanID int64) error {
	r.stateApplyMu.Lock()
	defer r.stateApplyMu.Unlock()
	return r.pauseState(scanID)
}

func (r *Runner) pauseState(scanID int64) error {
	r.mu.Lock()
	if !r.running || r.scanID != scanID || r.active == nil {
		r.mu.Unlock()
		return fmt.Errorf("执行 #%d 不是当前活动扫描，无法暂停", scanID)
	}
	control := r.active
	if control.stopRequested {
		r.mu.Unlock()
		return fmt.Errorf("执行 #%d 正在终止，不能暂停", scanID)
	}
	if control.paused {
		r.mu.Unlock()
		return fmt.Errorf("执行 #%d 已经处于暂停状态", scanID)
	}
	if len(control.cmds) == 0 {
		r.mu.Unlock()
		return fmt.Errorf("当前没有正在运行的 naabu 批次，请稍后重试暂停")
	}
	for cmd := range control.cmds {
		if err := pauseProcess(cmd); err != nil {
			// 尽力恢复已暂停的进程，保持一致状态
			for c := range control.cmds {
				_ = resumeProcess(c)
			}
			r.mu.Unlock()
			return fmt.Errorf("暂停 naabu 进程失败: %v", err)
		}
	}
	control.paused = true
	control.pauseStarted = time.Now()
	control.notify()
	r.mu.Unlock()

	if err := r.st.SetScanActiveStatus(scanID, "paused"); err != nil {
		_ = r.resumeState(scanID)
		return fmt.Errorf("naabu 已暂停但保存状态失败，已尝试恢复: %v", err)
	}
	return r.st.AddScanEvent(scanID, "info", "pause", "用户暂停了 naabu 进程；暂停期间不启动后续批次，也不计有效扫描超时")
}

func (r *Runner) Resume(scanID int64) error {
	r.stateApplyMu.Lock()
	defer r.stateApplyMu.Unlock()
	return r.resumeState(scanID)
}

func (r *Runner) resumeState(scanID int64) error {
	r.mu.Lock()
	if !r.running || r.scanID != scanID || r.active == nil {
		r.mu.Unlock()
		return fmt.Errorf("执行 #%d 不是当前活动扫描，无法恢复", scanID)
	}
	control := r.active
	if !control.paused {
		r.mu.Unlock()
		return fmt.Errorf("执行 #%d 当前不是暂停状态", scanID)
	}
	if len(control.cmds) == 0 {
		r.mu.Unlock()
		// 暂停期间进程已全部退出：自动解除暂停继续剩余批次，而不是把执行永久卡在暂停态。
		if r.healPausedState(scanID) {
			return nil
		}
		return fmt.Errorf("暂停对应的 naabu 进程已退出且执行正在终止，请查看执行状态")
	}
	for cmd := range control.cmds {
		if err := resumeProcess(cmd); err != nil {
			r.mu.Unlock()
			return fmt.Errorf("恢复 naabu 进程失败: %v", err)
		}
	}
	control.deadline = control.deadline.Add(time.Since(control.pauseStarted))
	control.paused = false
	control.pauseStarted = time.Time{}
	control.notify()
	r.mu.Unlock()

	if err := r.st.SetScanActiveStatus(scanID, "running"); err != nil {
		return fmt.Errorf("naabu 已恢复但保存运行状态失败: %v", err)
	}
	return r.st.AddScanEvent(scanID, "info", "resume", "用户恢复了 naabu 进程，任务继续运行")
}

func (r *Runner) Stop(scanID int64) error {
	return r.stop(scanID, "用户终止了扫描；已发现的端口结果会保留，不再启动后续批次")
}

// healPausedAfterProcessExit 处理“暂停期间全部 naabu 进程已退出”的悬空状态：
// 已经没有进程可以 SIGCONT，继续等待只会让待处理批次永久阻塞（且 Stop 之外无路可走），
// 因此自动解除暂停、顺延有效扫描截止时间并继续剩余批次。返回 true 表示暂停已不再成立。
// 状态转换与落库由 stateApplyMu 与 Pause/Resume 串行，确保数据库状态不会被迟到写入覆盖。
func (r *Runner) healPausedAfterProcessExit(scanID int64) bool {
	r.stateApplyMu.Lock()
	defer r.stateApplyMu.Unlock()
	return r.healPausedState(scanID)
}

func (r *Runner) healPausedState(scanID int64) bool {
	r.mu.Lock()
	if !r.running || r.scanID != scanID || r.active == nil {
		r.mu.Unlock()
		return true
	}
	control := r.active
	if !control.paused {
		r.mu.Unlock()
		return true
	}
	if control.stopRequested || len(control.cmds) > 0 {
		r.mu.Unlock()
		return false
	}
	if !control.pauseStarted.IsZero() {
		control.deadline = control.deadline.Add(time.Since(control.pauseStarted))
	}
	control.paused = false
	control.pauseStarted = time.Time{}
	control.notify()
	r.mu.Unlock()

	// 内存已解除暂停，落库仍在 stateApplyMu 临界区内，保证与后续 Pause/Resume 的写入顺序一致。
	if hook := scanStatusPersistHook; hook != nil {
		hook(scanID, "running")
	}
	if err := r.st.SetScanActiveStatus(scanID, "running"); err != nil {
		log.Printf("扫描 %d 暂停自动解除后保存运行状态失败: %v", scanID, err)
	}
	if err := r.st.AddScanEvent(scanID, "warn", "resume", "暂停期间 naabu 进程已全部退出，已自动解除暂停并继续处理剩余批次"); err != nil {
		log.Printf("扫描 %d 暂停自动解除后保存事件失败: %v", scanID, err)
	}
	return true
}

// retryBudgetExhausted 判断暂停修正后的有效扫描截止时间是否已耗尽。
// 暂停期间预算冻结（deadline 在恢复/自愈时顺延），所以暂停中不判超时。
func (r *Runner) retryBudgetExhausted(scanID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.scanID != scanID || r.active.paused {
		return false
	}
	if r.active.deadline.IsZero() {
		return false
	}
	return !time.Now().Before(r.active.deadline)
}

// Shutdown 在服务退出时终止当前执行，避免 naabu 成为遗留进程。
func (r *Runner) Shutdown() {
	r.mu.Lock()
	scanID := r.scanID
	r.mu.Unlock()
	if scanID > 0 {
		_ = r.stop(scanID, "平台服务退出，已终止当前 naabu 进程并保留已入库结果")
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *Runner) stop(scanID int64, message string) error {
	r.mu.Lock()
	if !r.running || r.scanID != scanID || r.active == nil {
		r.mu.Unlock()
		return fmt.Errorf("执行 #%d 不是当前活动扫描，无法终止", scanID)
	}
	control := r.active
	if control.stopRequested {
		r.mu.Unlock()
		return nil
	}
	control.stopRequested = true
	var signalErr error
	wasPaused := control.paused
	control.paused = false
	for cmd := range control.cmds {
		if wasPaused {
			_ = resumeProcess(cmd)
		}
		if err := killProcess(cmd); err != nil && signalErr == nil {
			signalErr = err
		}
	}
	control.notify()
	r.mu.Unlock()

	if signalErr != nil {
		return fmt.Errorf("请求终止 naabu 进程失败: %v", signalErr)
	}
	return r.st.AddScanEvent(scanID, "warn", "stop", message)
}

func (r *Runner) registerProcess(scanID int64, cmd *exec.Cmd) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || r.scanID != scanID || r.active == nil {
		return fmt.Errorf("扫描执行状态已失效")
	}
	r.active.cmds[cmd] = struct{}{}
	if r.active.stopRequested {
		delete(r.active.cmds, cmd)
		if err := killProcess(cmd); err != nil {
			return err
		}
		return fmt.Errorf("扫描已请求终止，当前批次不记为处理完成")
	}
	if r.active.paused {
		// 并行模式下若正处于暂停期，新启动的批次进程立即 SIGSTOP，与其余进程保持一致
		_ = pauseProcess(cmd)
	}
	return nil
}

func (r *Runner) clearProcess(scanID int64, cmd *exec.Cmd) {
	r.mu.Lock()
	remaining := 0
	if r.active != nil && r.scanID == scanID {
		delete(r.active.cmds, cmd)
		remaining = len(r.active.cmds)
	}
	r.mu.Unlock()
	// 并行模式下仅当所有批次进程都退出后才清零资源当前值；峰值由 SQL MAX 保留。
	if remaining == 0 {
		_ = r.st.UpdateScanResource(scanID, 0, 0)
	}
}

func (r *Runner) killBatchProcess(scanID int64, cmd *exec.Cmd) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.scanID != scanID {
		return nil
	}
	if _, ok := r.active.cmds[cmd]; !ok {
		return nil
	}
	return killProcess(cmd)
}

func (r *Runner) controlSnapshot(scanID int64) (paused, stopped bool, deadline time.Time) {
	paused, stopped, deadline, _, _ = r.controlWatch(scanID)
	return paused, stopped, deadline
}

// controlWatch 在一次加锁内同时返回控制状态、有效截止时间与当前代际通知通道。
// 这是消除“先读状态、后订阅通道”竞态的关键：
//   - 先检查 paused 再订阅通道时，若 Resume 恰好发生在两步之间，旧通道会被关闭、
//     而新订阅到的是新一代通道，等待者会漏掉这次唤醒（旧实现靠 300ms 轮询兜底）；
//   - 状态与通道同锁返回后，Resume 只可能发生在返回之后，那时它关闭的正是我们持有的通道，
//     select 一定会立即被唤醒。
//
// ok=false 表示执行已失效（已结束或 scanID 不匹配），调用方应直接停止等待。
func (r *Runner) controlWatch(scanID int64) (paused, stopped bool, deadline time.Time, changed <-chan struct{}, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.scanID != scanID {
		return false, true, time.Time{}, nil, false
	}
	return r.active.paused, r.active.stopRequested, r.active.deadline, r.active.changed, true
}

func (r *Runner) isStopped(scanID int64) bool {
	_, stopped, _ := r.controlSnapshot(scanID)
	return stopped
}
