//go:build !race

package scanner

// raceDetectorEnabled 表示当前测试二进制由 -race 构建；非 race 构建为 false。
const raceDetectorEnabled = false
