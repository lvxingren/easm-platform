package applog

import "testing"

func TestClassifyLevels(t *testing.T) {
	cases := []struct{ in, level, msg string }{
		{"[ERROR] 读取失败", LevelError, "读取失败"},
		{"[WARN] 资源告警", LevelWarn, "资源告警"},
		{"[INFO] 启动", LevelInfo, "启动"},
		{"扫描 3 保存结果失败: boom", LevelError, "扫描 3 保存结果失败: boom"},
		{"扫描 1 资源告警: high", LevelWarn, "扫描 1 资源告警: high"},
		{"扫描 1 结束(done)", LevelInfo, "扫描 1 结束(done)"},
	}
	for _, c := range cases {
		level, msg := classify(c.in)
		if level != c.level || msg != c.msg {
			t.Fatalf("classify(%q)=%q,%q，期望 %q,%q", c.in, level, msg, c.level, c.msg)
		}
	}
}

func TestSplitTimestamp(t *testing.T) {
	ts, rest := splitTimestamp("2026/11/05 22:10:30 [ERROR] 出错了")
	if ts != "2026/11/05 22:10:30" || rest != "[ERROR] 出错了" {
		t.Fatalf("时间前缀解析错误: ts=%q rest=%q", ts, rest)
	}
	if ts2, rest2 := splitTimestamp("无前缀日志"); ts2 != "" || rest2 != "无前缀日志" {
		t.Fatalf("无时间前缀时应原样返回: ts=%q rest=%q", ts2, rest2)
	}
}

func TestQueryLevelAndKeywordFilter(t *testing.T) {
	Init()
	var before int64
	if existing := Query("", "", 0, maxEntries); len(existing) > 0 {
		before = existing[0].ID
	}
	Errorf("数据库写入失败: %v", "boom")
	Warnf("扫描 %d 资源告警", 7)
	Infof("扫描 %d 批次启动", 7)

	if all := Query("", "", before, 100); len(all) != 3 {
		t.Fatalf("新增日志数=%d，期望 3: %+v", len(all), all)
	}
	errs := Query(LevelError, "", before, 100)
	if len(errs) != 1 || errs[0].Level != LevelError {
		t.Fatalf("只看报错筛选错误: %+v", errs)
	}
	if kw := Query("", "资源告警", before, 100); len(kw) != 1 {
		t.Fatalf("关键词检索错误: %+v", kw)
	}
	if none := Query(LevelError, "资源告警", before, 100); len(none) != 0 {
		t.Fatalf("级别+关键词组合应无结果: %+v", none)
	}
	// 非法级别应回退为全部，而不是返回空。
	if fallback := Query("bogus", "", before, 100); len(fallback) != 3 {
		t.Fatalf("非法级别未回退为全部: %+v", fallback)
	}
}

func TestIsClientTLSNoise(t *testing.T) {
	noise := []string{
		"http: TLS handshake error from 119.8.165.218:52039: remote error: tls: unknown certificate",
		"http: TLS handshake error from 1.2.3.4:1: remote error: tls: bad certificate",
		"http: TLS handshake error from 1.2.3.4:1: EOF",
		"http: TLS handshake error from 1.2.3.4:1: remote error: tls: protocol version not supported",
	}
	for _, m := range noise {
		if !IsClientTLSNoise(m) {
			t.Fatalf("应判定为客户端噪音: %q", m)
		}
	}
	real := []string{
		"http: TLS handshake error from 1.2.3.4:1: private key does not match public key",
		"http: Accept error: accept tcp: too many open files",
		"其他服务错误",
	}
	for _, m := range real {
		if IsClientTLSNoise(m) {
			t.Fatalf("不应判定为客户端噪音: %q", m)
		}
	}
}

func TestServerErrorWriterDowngradesClientNoise(t *testing.T) {
	Init()
	var before int64
	if es := Query("", "", 0, maxEntries); len(es) > 0 {
		before = es[0].ID
	}
	lg := NewServerErrorLogger()
	lg.Printf("http: TLS handshake error from 203.0.113.5:1: remote error: tls: unknown certificate")
	if errs := Query(LevelError, "", before, 100); len(errs) != 0 {
		t.Fatalf("客户端握手噪音不应记为 error: %+v", errs)
	}
	if infos := Query(LevelInfo, "", before, 100); len(infos) == 0 {
		t.Fatal("客户端握手噪音应降级为 info 记录")
	}
	lg.Printf("http: TLS handshake error from 203.0.113.5:1: private key does not match public key")
	if errs := Query(LevelError, "", before, 100); len(errs) != 1 {
		t.Fatalf("服务端真正的 TLS 错误应记为 error: %+v", errs)
	}
}
