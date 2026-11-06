package scanner

import (
	"fmt"
	"os/exec"
	"time"
)

// executionControl 贯穿一次执行的所有批次，进程引用只指向当前批次。
type executionControl struct {
	cmd           *exec.Cmd
	paused        bool
	pauseStarted  time.Time
	deadline      time.Time
	stopRequested bool
	changed       chan struct{}
}

func newExecutionControl() *executionControl {
	return &executionControl{changed: make(chan struct{}, 1)}
}

func (c *executionControl) notify() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

func (r *Runner) activeExecution(scanID int64) (*executionControl, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || r.scanID != scanID || r.active == nil {
		return nil, fmt.Errorf("执行 #%d 不是当前活动扫描，可能已结束或服务已重启", scanID)
	}
	return r.active, nil
}

func (r *Runner) Pause(scanID int64) error {
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
	if control.cmd == nil {
		r.mu.Unlock()
		return fmt.Errorf("当前 naabu 批次尚未启动或刚刚结束，请稍后重试暂停")
	}
	if err := pauseProcess(control.cmd); err != nil {
		r.mu.Unlock()
		return fmt.Errorf("暂停 naabu 进程失败: %v", err)
	}
	control.paused = true
	control.pauseStarted = time.Now()
	control.notify()
	r.mu.Unlock()

	if err := r.st.SetScanActiveStatus(scanID, "paused"); err != nil {
		_ = r.Resume(scanID)
		return fmt.Errorf("naabu 已暂停但保存状态失败，已尝试恢复: %v", err)
	}
	return r.st.AddScanEvent(scanID, "info", "pause", "用户暂停了 naabu 进程；暂停期间不启动后续批次，也不计有效扫描超时")
}

func (r *Runner) Resume(scanID int64) error {
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
	if control.cmd == nil {
		r.mu.Unlock()
		return fmt.Errorf("暂停对应的 naabu 进程已退出，请查看执行状态")
	}
	if err := resumeProcess(control.cmd); err != nil {
		r.mu.Unlock()
		return fmt.Errorf("恢复 naabu 进程失败: %v", err)
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
	if control.cmd != nil {
		if control.paused {
			_ = resumeProcess(control.cmd)
			control.paused = false
		}
		signalErr = killProcess(control.cmd)
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
	r.active.cmd = cmd
	if r.active.stopRequested {
		if err := killProcess(cmd); err != nil {
			return err
		}
		return fmt.Errorf("扫描已请求终止，当前批次不记为处理完成")
	}
	return nil
}

func (r *Runner) clearProcess(scanID int64, cmd *exec.Cmd) {
	r.mu.Lock()
	if r.active != nil && r.scanID == scanID && r.active.cmd == cmd {
		r.active.cmd = nil
	}
	r.mu.Unlock()
	_ = r.st.UpdateScanResource(scanID, 0, 0)
}

func (r *Runner) killBatchProcess(scanID int64, cmd *exec.Cmd) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.scanID != scanID || r.active.cmd != cmd {
		return nil
	}
	return killProcess(cmd)
}

func (r *Runner) controlSnapshot(scanID int64) (paused, stopped bool, deadline time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.scanID != scanID {
		return false, true, time.Time{}
	}
	return r.active.paused, r.active.stopRequested, r.active.deadline
}

func (r *Runner) isStopped(scanID int64) bool {
	_, stopped, _ := r.controlSnapshot(scanID)
	return stopped
}
