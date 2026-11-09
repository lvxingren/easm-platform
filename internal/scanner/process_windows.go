//go:build windows

package scanner

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Windows 没有 Unix 进程组：要“连同 naabu 拉起的后代进程一起终止，并且能证明它们都已退出”，
// 唯一可靠的手段是 Job Object。当前模块不直接依赖 golang.org/x/sys/windows（它只是间接依赖，
// 不允许为了本任务改动 go.mod），因此这里用标准库 syscall.NewLazyDLL 调用 kernel32 的最小接口集：
//   - CreateJobObjectW / SetInformationJobObject(KILL_ON_JOB_CLOSE)：作业句柄关闭即杀掉全部成员，
//     即使平台崩溃也不会留下 naabu 残留；
//   - AssignProcessToJobObject：把 naabu 主进程加入作业，其后续子进程自动继承；
//   - QueryInformationJobObject(BasicAccounting)：用 ActiveProcesses 判定“作业里是否还有存活进程”，
//     这是 Windows 上唯一能确认后代进程已退出的证据；
//   - TerminateJobObject：等价 Unix 的 kill(-pgid, SIGKILL)。
//
// 关键约束：没有 Job Object（创建/加入失败）时，平台无法枚举后代进程，因此 cleanupProcessGroup
// 必须返回 converged=false —— 绝不伪报收敛，上层据此不自动重试并给出明确的平台限制说明。
var (
	kernel32                      = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW          = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject   = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject  = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject        = kernel32.NewProc("TerminateJobObject")
	procQueryInformationJobObject = kernel32.NewProc("QueryInformationJobObject")
	procOpenProcess               = kernel32.NewProc("OpenProcess")
	procCloseHandle               = kernel32.NewProc("CloseHandle")
)

const (
	// jobObjectBasicAccountingInformationClass / jobObjectExtendedLimitInformationClass 是 InfoClass 取值。
	jobObjectBasicAccountingInformationClass = 1
	jobObjectExtendedLimitInformationClass   = 9
	// jobObjectLimitKillOnJobClose 让最后一个作业句柄关闭时终止作业内全部进程。
	jobObjectLimitKillOnJobClose = 0x00002000
	// processTerminate / processSetQuota 是 AssignProcessToJobObject 所需的最小访问权限。
	processTerminate = 0x0001
	processSetQuota  = 0x0100
	// createNewProcessGroup 让 naabu 拥有独立控制台信号组（不依赖它做收尾判定）。
	createNewProcessGroup = 0x00000200
	// jobSettlePoll 是作业活动进程数归零的轮询间隔。
	jobSettlePoll = 10 * time.Millisecond
)

// jobObjectBasicLimitInformation 对应 JOBOBJECT_BASIC_LIMIT_INFORMATION（64 位 Windows 布局）。
type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

// ioCounters 对应 IO_COUNTERS。
type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

// jobObjectExtendedLimitInformation 对应 JOBOBJECT_EXTENDED_LIMIT_INFORMATION（64 位布局，144 字节）。
type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// jobObjectBasicAccountingInformation 对应 JOBOBJECT_BASIC_ACCOUNTING_INFORMATION。
type jobObjectBasicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

// jobRegistry 按 pid 登记作业句柄：启动后登记，cleanupProcessGroup 取走并关闭。
var (
	jobRegistryMu sync.Mutex
	jobRegistry   = map[int]syscall.Handle{}
)

func prepareProcess(cmd *exec.Cmd) {
	// 独立进程组只用于让 naabu 不接收平台自身的控制台事件；收尾仍以 Job Object 为准。
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
}

// afterStartProcess 在 naabu 启动后立即把它加入 KillOnJobClose 的 Job Object。
// 失败意味着后代进程不可追踪：调用方会按“收尾不可确认”处理（不伪报收敛、不自动重试）。
func afterStartProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("naabu 进程尚未启动，无法加入 Job Object")
	}
	job, err := createKillOnCloseJob()
	if err != nil {
		return err
	}
	handle, err := openProcessForJob(uint32(cmd.Process.Pid))
	if err != nil {
		closeHandle(job)
		return err
	}
	defer closeHandle(handle)
	if err := assignProcessToJob(job, handle); err != nil {
		closeHandle(job)
		return err
	}
	jobRegistryMu.Lock()
	jobRegistry[cmd.Process.Pid] = job
	jobRegistryMu.Unlock()
	return nil
}

func pauseProcess(*exec.Cmd) error {
	// Windows 没有 SIGSTOP 等价语义：挂起单进程无法保证其后代也被挂起，
	// 因此这里明确报错而不是做“看起来暂停了”的假动作。
	return fmt.Errorf("Windows 平台不支持挂起 naabu 进程（内核无 SIGSTOP 等价语义），请改用终止任务")
}

func resumeProcess(*exec.Cmd) error {
	return fmt.Errorf("Windows 平台不支持恢复 naabu 进程（内核无 SIGCONT 等价语义）")
}

func killProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("naabu 进程尚未启动")
	}
	if job, ok := lookupJob(cmd.Process.Pid); ok {
		// 终止整个作业：naabu 及其后代一并被杀。
		if err := terminateJob(job); err == nil {
			return nil
		}
	}
	return cmd.Process.Kill()
}

// cleanupProcessGroup 通过 Job Object 终止整个作业，并用 ActiveProcesses 归零作为收敛证据。
// 没有登记的作业句柄时返回 converged=false：主进程 Kill 成功不代表后代进程已退出。
func cleanupProcessGroup(cmd *exec.Cmd, timeout time.Duration) (leftover bool, converged bool) {
	if cmd == nil || cmd.Process == nil {
		return false, true
	}
	job, ok := takeJob(cmd.Process.Pid)
	if !ok {
		_ = cmd.Process.Kill()
		return false, false
	}
	// 关闭句柄会因 KILL_ON_JOB_CLOSE 兜底杀掉剩余成员；必须在查询收敛之后再关。
	defer closeHandle(job)
	if active, err := queryActiveProcesses(job); err == nil && active > 0 {
		leftover = true
	}
	_ = terminateJob(job)
	deadline := time.Now().Add(timeout)
	for {
		active, err := queryActiveProcesses(job)
		if err == nil && active == 0 {
			return leftover, true
		}
		if !time.Now().Before(deadline) {
			return leftover, false
		}
		time.Sleep(jobSettlePoll)
	}
}

// processGroupLimitation 描述 Windows 上确认后代进程的能力边界。
func processGroupLimitation() string {
	return "Windows Job Object 不可用或 ActiveProcesses 未归零"
}

// isTransientStartError：Windows 不做进程启动重试（保留各平台最小差异）。
func isTransientStartError(error) bool { return false }

func createKillOnCloseJob() (syscall.Handle, error) {
	result, _, callErr := procCreateJobObjectW.Call(0, 0)
	if result == 0 {
		return 0, windowsCallError("CreateJobObjectW", callErr)
	}
	job := syscall.Handle(result)
	var limits jobObjectExtendedLimitInformation
	limits.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	ok, _, setErr := procSetInformationJobObject.Call(
		uintptr(job),
		jobObjectExtendedLimitInformationClass,
		uintptr(unsafe.Pointer(&limits)),
		unsafe.Sizeof(limits),
	)
	if ok == 0 {
		closeHandle(job)
		return 0, windowsCallError("SetInformationJobObject", setErr)
	}
	return job, nil
}

func openProcessForJob(pid uint32) (syscall.Handle, error) {
	result, _, callErr := procOpenProcess.Call(processTerminate|processSetQuota, 0, uintptr(pid))
	if result == 0 {
		return 0, windowsCallError("OpenProcess", callErr)
	}
	return syscall.Handle(result), nil
}

func assignProcessToJob(job, process syscall.Handle) error {
	ok, _, callErr := procAssignProcessToJobObject.Call(uintptr(job), uintptr(process))
	if ok == 0 {
		return windowsCallError("AssignProcessToJobObject", callErr)
	}
	return nil
}

func terminateJob(job syscall.Handle) error {
	ok, _, callErr := procTerminateJobObject.Call(uintptr(job), 1)
	if ok == 0 {
		return windowsCallError("TerminateJobObject", callErr)
	}
	return nil
}

func queryActiveProcesses(job syscall.Handle) (uint32, error) {
	var info jobObjectBasicAccountingInformation
	var returned uint32
	ok, _, callErr := procQueryInformationJobObject.Call(
		uintptr(job),
		jobObjectBasicAccountingInformationClass,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&returned)),
	)
	if ok == 0 {
		return 0, windowsCallError("QueryInformationJobObject", callErr)
	}
	return info.ActiveProcesses, nil
}

func closeHandle(handle syscall.Handle) {
	if handle == 0 {
		return
	}
	_, _, _ = procCloseHandle.Call(uintptr(handle))
}

func lookupJob(pid int) (syscall.Handle, bool) {
	jobRegistryMu.Lock()
	defer jobRegistryMu.Unlock()
	job, ok := jobRegistry[pid]
	return job, ok
}

func takeJob(pid int) (syscall.Handle, bool) {
	jobRegistryMu.Lock()
	defer jobRegistryMu.Unlock()
	job, ok := jobRegistry[pid]
	if ok {
		delete(jobRegistry, pid)
	}
	return job, ok
}

// windowsCallError 归一化 LazyProc.Call 的错误：失败时 err 可能是 Errno(0)（无扩展信息）。
func windowsCallError(name string, err error) error {
	if errno, ok := err.(syscall.Errno); !ok || errno == 0 {
		return fmt.Errorf("%s 调用失败（无扩展错误信息）", name)
	}
	return fmt.Errorf("%s 失败：%v", name, err)
}
