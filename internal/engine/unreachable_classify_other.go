//go:build !linux && !darwin

package engine

// dialUnreachable 在非类 Unix 平台（如 Windows）不做 errno 判定，返回 false。
// 探测主路径仍保留大小写无关的错误文案匹配作为通用兜底。
func dialUnreachable(err error) bool { return false }
