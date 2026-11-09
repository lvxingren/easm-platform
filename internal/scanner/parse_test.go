package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easm-platform/internal/store"
)

// TestParseOutputLineJSONL 验证 -json 输出能正确解析 hostname、IPv4、IPv6、port、protocol。
func TestParseOutputLineJSONL(t *testing.T) {
	cases := []struct {
		name string
		line string
		want store.Result
	}{
		{
			name: "IPv4",
			line: `{"host":"192.0.2.10","ip":"192.0.2.10","port":443,"protocol":"tcp"}`,
			want: store.Result{IP: "192.0.2.10", Port: 443, Proto: "tcp", Status: 1},
		},
		{
			name: "域名取解析后的第一个 IPv4",
			line: `{"host":"Web.Example.COM.","ip":"198.51.100.7","port":8443,"protocol":"TCP"}`,
			want: store.Result{IP: "198.51.100.7", Port: 8443, Proto: "tcp", Status: 1},
		},
		{
			name: "IPv6 规范为压缩小写",
			line: `{"host":"v6.example.com","ip":"2001:0DB8:0000:0000:0000:0000:0000:0001","port":22,"protocol":"tcp"}`,
			want: store.Result{IP: "2001:db8::1", Port: 22, Proto: "tcp", Status: 1},
		},
		{
			name: "端口为字符串",
			line: `{"host":"example.com","ip":"203.0.113.5","port":"8080","protocol":"tcp"}`,
			want: store.Result{IP: "203.0.113.5", Port: 8080, Proto: "tcp", Status: 1},
		},
		{
			name: "缺少 ip 时保留规范化域名",
			line: `{"host":"HOST.Example.com.","port":80,"protocol":"tcp"}`,
			want: store.Result{IP: "host.example.com", Port: 80, Proto: "tcp", Status: 1},
		},
		{
			name: "缺少 protocol 默认 tcp",
			line: `{"host":"example.com","ip":"203.0.113.6","port":81}`,
			want: store.Result{IP: "203.0.113.6", Port: 81, Proto: "tcp", Status: 1},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseOutputLine(c.line)
			if got.kind != parseResult {
				t.Fatalf("解析类型=%v，期望 parseResult（原始=%s）", got.kind, c.line)
			}
			if got.result != c.want {
				t.Fatalf("解析结果=%+v，期望 %+v", got.result, c.want)
			}
		})
	}
}

// TestParseOutputLineKeepsPlainTextCompatibility 验证普通文本 "host:port" 仍然可用（含 IPv6 方括号形式）。
func TestParseOutputLineKeepsPlainTextCompatibility(t *testing.T) {
	cases := []struct {
		line string
		want store.Result
	}{
		{"192.0.2.1:443", store.Result{IP: "192.0.2.1", Port: 443, Proto: "tcp", Status: 1}},
		{"[2001:db8::1]:443", store.Result{IP: "2001:db8::1", Port: 443, Proto: "tcp", Status: 1}},
		{"2001:db8::1:8443", store.Result{IP: "2001:db8::1", Port: 8443, Proto: "tcp", Status: 1}},
	}
	for _, c := range cases {
		got := parseOutputLine(c.line)
		if got.kind != parseResult || got.result != c.want {
			t.Fatalf("文本行 %q 解析=%+v(kind=%v)，期望 %+v", c.line, got.result, got.kind, c.want)
		}
	}
	if got := parseOutputLine("scan finished in 12s"); got.kind != parseSkip {
		t.Fatalf("无关日志行应跳过，实际 kind=%v", got.kind)
	}
	if got := parseOutputLine("192.0.2.1:70000"); got.kind != parseSkip {
		t.Fatalf("非法端口应跳过，实际 kind=%v", got.kind)
	}
}

// TestParseOutputLineResolutionFailure 验证域名解析失败被显式识别（用于阻止虚报 done）。
func TestParseOutputLineResolutionFailure(t *testing.T) {
	cases := []struct {
		line       string
		wantTarget string
	}{
		{`{"host":"nx.example.com","error":"could not resolve host nx.example.com"}`, "nx.example.com"},
		{"could not resolve host: nx.example.com", "nx.example.com"},
		{"dns lookup failed for missing.example.org", "missing.example.org"},
	}
	for _, c := range cases {
		got := parseOutputLine(c.line)
		if got.kind != parseResolutionFailure {
			t.Fatalf("%q 应识别为解析失败，实际 kind=%v", c.line, got.kind)
		}
		if got.target != c.wantTarget {
			t.Fatalf("%q 失败目标=%q，期望 %q", c.line, got.target, c.wantTarget)
		}
	}
}

// TestParseOutputLineMalformedJSON 验证结构化输出损坏会被标记（不能当作完整输出）。
func TestParseOutputLineMalformedJSON(t *testing.T) {
	for _, line := range []string{`{"host":`, `{"port":"abc"}`, `{`, `{"ip":"not-an-ip","port":443}`} {
		if got := parseOutputLine(line); got.kind != parseMalformed {
			t.Fatalf("损坏的 JSONL %q 应标记为 parseMalformed，实际 kind=%v", line, got.kind)
		}
	}
}

// TestNormalizeHelpers 验证域名大小写/结尾点与 IP 表示规范化。
func TestNormalizeHelpers(t *testing.T) {
	if got := normalizeHostname("Web.Example.COM."); got != "web.example.com" {
		t.Fatalf("域名规范化=%q", got)
	}
	for _, bad := range []string{"bad host", "a..b", "http://example.com", "example.com:443", ""} {
		if got := normalizeHostname(bad); got != "" {
			t.Fatalf("非法域名 %q 应被拒绝，实际=%q", bad, got)
		}
	}
	if got, ok := normalizeIP("[2001:0DB8::0001]"); !ok || got != "2001:db8::1" {
		t.Fatalf("IPv6 规范化=(%q,%v)", got, ok)
	}
	if got, ok := normalizeIP("192.000.002.001"); ok {
		t.Fatalf("非法 IPv4 不应被接受: %q", got)
	}
	if got := normalizeProtocol(" TCP "); got != "tcp" {
		t.Fatalf("协议规范化=%q", got)
	}
	if got := normalizeProtocol(""); got != "tcp" {
		t.Fatalf("空协议应回退 tcp，实际=%q", got)
	}
}

// TestRecentKeyCacheIsBounded 验证近期缓存有界：超过容量后淘汰最旧键，内存不会随全端口扫描无限增长。
func TestRecentKeyCacheIsBounded(t *testing.T) {
	cache := newRecentKeyCache(3)
	for _, key := range []string{"a", "b", "c"} {
		cache.add(key)
	}
	if !cache.has("a") || cache.len() != 3 {
		t.Fatalf("容量内的键应全部保留: len=%d", cache.len())
	}
	cache.add("d")
	if cache.has("a") {
		t.Fatal("超出容量后应淘汰最旧键")
	}
	if !cache.has("d") || cache.len() != 3 {
		t.Fatalf("新增键应保留且容量固定: len=%d", cache.len())
	}
	// 重复添加不应扩张
	cache.add("b")
	if cache.len() != 3 {
		t.Fatalf("重复键不应扩张缓存: len=%d", cache.len())
	}
}

// TestStreamResultFileStreamsAndCanStop 验证文件补读是逐行流式回调（不构造全量切片），
// 并且 emit 返回 false 时立即停止。
func TestStreamResultFileStreamsAndCanStop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "batch.out")
	content := strings.Join([]string{
		`{"host":"a.example.com","ip":"192.0.2.1","port":80,"protocol":"tcp"}`,
		"",
		"192.0.2.2:443",
		`{"host":"nx.example.com","error":"could not resolve host nx.example.com"}`,
		`{"host":`,
		`{"host":"b.example.com","ip":"2001:db8::2","port":8443,"protocol":"tcp"}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var results []store.Result
	var resolutions, malformed int
	err := streamResultFile(path,
		func(result store.Result) bool { results = append(results, result); return true },
		func(string) { resolutions++ },
		func(string) { malformed++ },
	)
	if err != nil {
		t.Fatalf("流式补读失败: %v", err)
	}
	if len(results) != 3 || resolutions != 1 || malformed != 1 {
		t.Fatalf("流式补读统计错误: results=%d resolutions=%d malformed=%d", len(results), resolutions, malformed)
	}
	if results[2].IP != "2001:db8::2" || results[2].Port != 8443 {
		t.Fatalf("IPv6 结果解析错误: %+v", results[2])
	}

	stopped := 0
	if err := streamResultFile(path, func(store.Result) bool { stopped++; return false }, nil, nil); err != nil {
		t.Fatalf("提前停止不应返回错误: %v", err)
	}
	if stopped != 1 {
		t.Fatalf("emit 返回 false 后应立即停止，实际回调 %d 次", stopped)
	}
}

// TestWriteTargetsNormalizesScope 验证写目标文件时规范化域名/IP，但不改动 CIDR 与范围（不扩大范围）。
func TestWriteTargetsNormalizesScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	specs := []store.TargetSpec{
		{Raw: "Web.Example.COM.", Kind: "domain"},
		{Raw: "[2001:0DB8::1]", Kind: "ip"},
		{Raw: "192.0.2.0/30", Kind: "cidr"},
		{Raw: "198.51.100.1-198.51.100.4", Kind: "range"},
	}
	if err := writeTargets(path, specs); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "web.example.com\n2001:db8::1\n192.0.2.0/30\n198.51.100.1-198.51.100.4\n"
	if string(data) != want {
		t.Fatalf("目标文件内容不符:\n实际=%q\n期望=%q", string(data), want)
	}
}
