package scanner

import (
	"fmt"
	"strconv"
	"strings"
)

// 本文件实现「继续扫描未完成节点」：从被终止/部分完成的执行中提取未完成目标规格，
// 创建一次增量续扫执行（resume_of 指向父执行），保留父执行已完成结果，避免重复劳动。

// StartResume 对父执行的未完成目标发起增量续扫。
// 仅终态（stopped/partial/failed/done 但仍有未完成规格）可续扫；运行中/暂停中拒绝。
// 续扫复用现有 naabu/fscan 执行路径，不修改原任务定义。
func (r *Runner) StartResume(parentScanID int64) (int64, error) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return 0, fmt.Errorf("已有扫描任务运行或暂停中，本次续扫未启动；请等待当前任务结束后再试")
	}
	r.running = true
	r.mu.Unlock()
	fail := func(err error) (int64, error) {
		r.setRunning(false)
		return 0, err
	}

	parent, err := r.st.Scan(parentScanID)
	if err != nil || parent == nil {
		return fail(fmt.Errorf("读取父执行失败：%v", err))
	}
	if parent.Status == "running" || parent.Status == "paused" {
		return fail(fmt.Errorf("该执行仍在运行/暂停中，无需续扫"))
	}
	specs, err := r.st.UnfinishedSpecs(parentScanID)
	if err != nil {
		return fail(fmt.Errorf("读取未完成目标失败：%v", err))
	}
	if len(specs) == 0 {
		return fail(fmt.Errorf("没有未完成的目标规格，无需续扫"))
	}

	mode := parent.Mode
	if mode != "full" && mode != "custom" {
		mode = "top"
	}
	engine := "naabu"
	customPorts := ""
	if parent.TaskID > 0 {
		if t, _ := r.st.ScanTask(parent.TaskID); t != nil {
			engine = t.Engine
			customPorts = strings.TrimSpace(t.CustomPorts)
		}
	}

	scanID, err := r.st.CreateScan(parent.TaskID, parent.Name+" · 续扫未完成", mode)
	if err != nil {
		return fail(fmt.Errorf("创建续扫执行记录失败：%v", err))
	}
	_ = r.st.SetScanResumeOf(scanID, parentScanID)
	r.mu.Lock()
	r.scanID = scanID
	r.active = newExecutionControl()
	r.mu.Unlock()
	failStart := func(err error) (int64, error) {
		r.fail(scanID, err)
		r.setRunning(false)
		return scanID, err
	}
	_ = r.st.AddScanEvent(scanID, "info", "resume",
		fmt.Sprintf("增量续扫执行 #%d 的 %d 个未完成目标（保留父执行已完成结果）", parentScanID, len(specs)))

	// fscan 系列引擎走 fscan 路径。
	if engineIsFscan(engine) {
		if customPorts != "" {
			if err := ValidatePortList(customPorts, "fscan 自定义端口"); err != nil {
				return failStart(err)
			}
		}
		fs := r.fscanSettings()
		fs.Mode = engineFscanMode(engine)
		return r.startFscanTask(scanID, specs, fs, customPorts)
	}

	// naabu 引擎：自检 + 容量预检 + 启动。
	settings := r.naabuSettings()
	if _, _, err := r.checkNaabu(settings); err != nil {
		return failStart(err)
	}
	plan, err := r.planScanCapacity(settings, mode, customPorts, specs)
	if err != nil {
		return failStart(fmt.Errorf("容量预检未通过，续扫未启动：%v", err))
	}
	settings.Rate = strconv.Itoa(plan.PerRate)
	go r.run(scanID, mode, customPorts, specs, settings, plan)
	return scanID, nil
}
