package applog

import "testing"

func TestSetMinLevelAndStderrGate(t *testing.T) {
	// 默认 warn
	SetMinLevel("")
	if MinLevel() != LevelWarn {
		t.Fatalf("非法值应回退 warn: %s", MinLevel())
	}
	if stderrAllowed(LevelInfo) {
		t.Fatal("warn 级别不应允许 info 输出 stderr")
	}
	if !stderrAllowed(LevelWarn) || !stderrAllowed(LevelError) {
		t.Fatal("warn 级别应允许 warn/error")
	}
	SetMinLevel(LevelInfo)
	if !stderrAllowed(LevelInfo) {
		t.Fatal("info 级别应允许 info")
	}
	SetMinLevel(LevelError)
	if stderrAllowed(LevelWarn) {
		t.Fatal("error 级别不应允许 warn")
	}
	SetMinLevel(LevelWarn) // 恢复默认
}

func TestRingAlwaysFullRegardlessOfLevel(t *testing.T) {
	Init()                  // 安装 teeWriter，使日志进入环形缓冲
	SetMinLevel(LevelError) // stderr 仅 error
	defer SetMinLevel(LevelWarn)
	var before int64
	if es := Query("", "", 0, maxEntries); len(es) > 0 {
		before = es[0].ID
	}
	Infof("环形缓冲全量 info 记录")
	Warnf("环形缓冲全量 warn 记录")
	// 环形缓冲不受 stderr 级别影响，info/warn 均应可检索。
	if got := Query(LevelInfo, "环形缓冲全量 info", before, 10); len(got) != 1 {
		t.Fatalf("info 应仍在环形缓冲: %+v", got)
	}
	if got := Query(LevelWarn, "环形缓冲全量 warn", before, 10); len(got) != 1 {
		t.Fatalf("warn 应仍在环形缓冲: %+v", got)
	}
}
