package applog

import (
	"strings"
	"testing"
	"time"
)

func TestExtractClientIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http: TLS handshake error from 203.0.113.5:52039: remote error: tls: unknown certificate", "203.0.113.5"},
		{"http: TLS handshake error from [2001:db8::1]:443: EOF", "2001:db8::1"},
		{"http: TLS handshake error from 1.2.3.4:1: connection reset by peer", "1.2.3.4"},
		{"no address here", ""},
	}
	for _, c := range cases {
		if got := ExtractClientIP(c.in); got != c.want {
			t.Fatalf("ExtractClientIP(%q)=%q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestMaskIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.5", "203.0.113.*"},
		{"1.2.3.4", "1.2.3.*"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, c := range cases {
		if got := MaskIP(c.in); got != c.want {
			t.Fatalf("MaskIP(%q)=%q，期望 %q", c.in, got, c.want)
		}
	}
	if got := MaskIP("2001:db8::1"); !strings.HasSuffix(got, ":*") {
		t.Fatalf("IPv6 掩码应保留前 3 组并以 :* 结尾: %q", got)
	}
}

func TestIPSegment(t *testing.T) {
	if got := IPSegment("203.0.113.5"); got != "203.0.113" {
		t.Fatalf("IPv4 /24 段错误: %q", got)
	}
	if got := IPSegment("bad"); got != "" {
		t.Fatalf("非法 IP 段应为空: %q", got)
	}
	if got := IPSegment("2001:db8:abcd::1"); got == "" {
		t.Fatal("IPv6 段不应为空")
	}
}

func resetNoise() {
	noiseTracker.mu.Lock()
	noiseTracker.events = nil
	noiseTracker.mu.Unlock()
}

func TestTLSNoiseStatsTodayWeekAndTop(t *testing.T) {
	resetNoise()
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.Local)
	// 当日 3 条（两个段），本周早前 1 条，超过 7 天 1 条（应被排除）。
	recordTLSNoise("203.0.113.5", now.Add(-1*time.Hour))
	recordTLSNoise("203.0.113.6", now.Add(-2*time.Hour))
	recordTLSNoise("198.51.100.9", now.Add(-3*time.Hour))
	recordTLSNoise("203.0.113.7", now.Add(-48*time.Hour))
	recordTLSNoise("192.0.2.1", now.Add(-8*24*time.Hour))

	today, week, top := tlsNoiseStatsAt(now)
	if today != 3 {
		t.Fatalf("当日计数=%d，期望 3", today)
	}
	if week != 4 {
		t.Fatalf("本周计数=%d，期望 4（排除 8 天前）", week)
	}
	if len(top) == 0 || top[0].Segment != "203.0.113" || top[0].Count != 3 {
		t.Fatalf("Top 段应为 203.0.113 计 3: %+v", top)
	}
}

func TestTLSNoiseBounded(t *testing.T) {
	resetNoise()
	now := time.Now()
	for i := 0; i < tlsNoiseMaxEvents+50; i++ {
		recordTLSNoise("203.0.113.5", now)
	}
	noiseTracker.mu.Lock()
	n := len(noiseTracker.events)
	noiseTracker.mu.Unlock()
	if n != tlsNoiseMaxEvents {
		t.Fatalf("事件应有界保留 %d，实际 %d", tlsNoiseMaxEvents, n)
	}
}

func TestServerErrorWriterMasksIPAndRecordsStats(t *testing.T) {
	Init()
	resetNoise()
	var before int64
	if es := Query("", "", 0, maxEntries); len(es) > 0 {
		before = es[0].ID
	}
	lg := NewServerErrorLogger()
	lg.Printf("http: TLS handshake error from 203.0.113.5:1: remote error: tls: unknown certificate")

	infos := Query(LevelInfo, "", before, 100)
	if len(infos) == 0 {
		t.Fatal("噪音应降级为 info")
	}
	if strings.Contains(infos[0].Msg, "203.0.113.5") {
		t.Fatalf("info 不应包含完整 IP: %q", infos[0].Msg)
	}
	if !strings.Contains(infos[0].Msg, "203.0.113.*") {
		t.Fatalf("info 应包含掩码 IP: %q", infos[0].Msg)
	}
	today, _, top := TLSNoiseStats()
	if today < 1 || len(top) == 0 || top[0].Segment != "203.0.113" {
		t.Fatalf("统计应记录来源段: today=%d top=%+v", today, top)
	}
}
