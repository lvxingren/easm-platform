//go:build linux || darwin

package scanner

import (
	"os"
	"runtime"
	"syscall"
)

// platformFDSoftLimit 返回当前进程的文件描述符软上限；查询失败时返回 unknown=false。
func platformFDSoftLimit() (uint64, bool) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return 0, false
	}
	return limit.Cur, true
}

// platformFDInUse 返回父进程当前已打开的文件描述符数量（容量预检只用于估算父进程自身开销）。
// Linux 通过 /proc/self/fd 枚举，Darwin 通过 /dev/fd 枚举；查询失败时返回 unknown=false，
// 此时容量预检只按平台预留估算，不会凭空放大父进程占用。
func platformFDInUse() (uint64, bool) {
	dir := "/proc/self/fd"
	if runtime.GOOS == "darwin" {
		dir = "/dev/fd"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, false
	}
	return uint64(len(entries)), true
}

// platformDiskFreeBytes 返回指定路径所在文件系统的可用字节数。
func platformDiskFreeBytes(path string) (int64, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(nearestExistingDir(path), &stat); err != nil {
		return 0, false
	}
	return int64(stat.Bavail) * int64(stat.Bsize), true
}
