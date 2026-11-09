//go:build !linux && !darwin

package scanner

// platformFDSoftLimit 在非 Unix 平台不查询 ulimit，容量预检跳过 FD 硬约束（仅保留其他预算）。
func platformFDSoftLimit() (uint64, bool) { return 0, false }

// platformFDInUse 在非 Unix 平台无法可靠枚举父进程句柄，返回 unknown，容量预检只按平台预留估算。
func platformFDInUse() (uint64, bool) { return 0, false }

// platformDiskFreeBytes 在非 Unix 平台不查询磁盘余量，容量预检跳过磁盘硬约束。
func platformDiskFreeBytes(string) (int64, bool) { return 0, false }
