//go:build linux || darwin

package engine

import (
	"errors"
	"syscall"
)

// dialUnreachable 在类 Unix 平台按系统 errno 结构化判定拨号错误是否为网络层不可达，
// 避免依赖错误文案（locale/Go 版本变化会让字符串匹配失效）。Windows 等平台由同名的
// 非 unix 实现返回 false，探测主路径回退到大小写无关的文案匹配。
func dialUnreachable(err error) bool {
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETDOWN) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ENETUNREACH || errno == syscall.EHOSTUNREACH || errno == syscall.ENETDOWN
	}
	return false
}
