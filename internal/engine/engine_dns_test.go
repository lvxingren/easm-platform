package engine

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"easm-platform/internal/store"
)

// roundTripFunc 注入 HTTP 响应，便于离线测试 DoH 回退。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// fakeResolver 注入 DNS 结果，便于离线测试。
type fakeResolver struct {
	ips map[string][]string
}

func (f fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, s := range f.ips[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	return out, nil
}
func (f fakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return "", &net.DNSError{Err: "no cname", Name: host}
}

func TestLoadSubdomainSeeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdomains.txt")
	if err := os.WriteFile(path, []byte("www\n# comment\n\napi\nwww\nMail\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	seeds, err := LoadSubdomainSeeds(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) != 3 { // www, api, mail（去重+去注释+小写）
		t.Fatalf("种子数=%d，期望 3: %v", len(seeds), seeds)
	}
	if _, err := LoadSubdomainSeeds(filepath.Join(dir, "nope.txt")); err == nil {
		t.Fatal("缺失种子文件应报错")
	}
}

func TestExpandDomainSeeds(t *testing.T) {
	got := ExpandDomainSeeds("*.Example.com", []string{"www", "api", "www"})
	if len(got) != 3 { // example.com, www.example.com, api.example.com
		t.Fatalf("展开数=%d，期望 3: %v", len(got), got)
	}
	if got[0] != "example.com" {
		t.Fatalf("主域名应归一化为首项: %v", got)
	}
	if ExpandDomainSeeds("", nil) != nil {
		t.Fatal("空域名应返回 nil")
	}
}

func TestParseSubfinderOutput(t *testing.T) {
	if d, ok := parseSubfinderOutput("API.Example.com"); !ok || d != "api.example.com" {
		t.Fatalf("子域解析错误: %q %v", d, ok)
	}
	if _, ok := parseSubfinderOutput("[INF] some log line"); ok {
		t.Fatal("日志行不应识别为子域")
	}
	if _, ok := parseSubfinderOutput(""); ok {
		t.Fatal("空行不应识别")
	}
}

func TestSubfinderArgs(t *testing.T) {
	args := subfinderArgs("example.com", "o.txt")
	if args[0] != "-d" || args[1] != "example.com" {
		t.Fatalf("subfinder 参数错误: %v", args)
	}
}

func TestRegistrableDomainAndPortKey(t *testing.T) {
	if registrableDomain("a.b.example.com") != "example.com" {
		t.Fatal("可注册域应为最后两级")
	}
	// 同一主域不同子域相同端口 → 同一合并键（避免重复告警）。
	if DomainPortKey("a.example.com", 443) != DomainPortKey("b.example.com", 443) {
		t.Fatal("同主域同端口应合并")
	}
	if DomainPortKey("a.example.com", 443) == DomainPortKey("a.example.com", 80) {
		t.Fatal("不同端口不应合并")
	}
}

func TestResolveDomainWithFake(t *testing.T) {
	r := fakeResolver{ips: map[string][]string{"example.com": {"192.0.2.1", "192.0.2.1"}}}
	ips, err := resolveDomainWith(context.Background(), "example.com", r)
	if err != nil || len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("解析去重错误: %v %v", ips, err)
	}
	if _, err := resolveDomainWith(context.Background(), "", r); err == nil {
		t.Fatal("空域名应报错")
	}
}

func TestParseDoHAnswer(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[{"name":"example.com","type":1,"data":"192.0.2.1"},{"type":5,"data":"cname.example.com"},{"type":28,"data":"2001:db8::1"}]}`)
	ips, err := parseDoHAnswer(body)
	if err != nil || len(ips) != 2 {
		t.Fatalf("DoH 应提取 A+AAAA 两条: %v %v", ips, err)
	}
	if _, err := parseDoHAnswer([]byte("not json")); err == nil {
		t.Fatal("非法 JSON 应报错")
	}
}

func TestCollectDomainTargets(t *testing.T) {
	r := fakeResolver{ips: map[string][]string{
		"example.com":     {"192.0.2.1"},
		"www.example.com": {"192.0.2.1", "192.0.2.2"},
	}}
	specs, mappings := CollectDomainTargets(context.Background(), []string{"example.com"}, []string{"www"}, r)
	// IP 去重后应为 2 个目标；映射 3 条（example.com→1, www→1, www→2）。
	if len(specs) != 2 {
		t.Fatalf("目标池应去重为 2: %+v", specs)
	}
	if len(mappings) != 3 {
		t.Fatalf("映射应 3 条: %+v", mappings)
	}
	for _, m := range mappings {
		if m.Source != "domain_resolver" {
			t.Fatalf("来源应为 domain_resolver: %+v", m)
		}
	}
	_ = store.TargetSpec{}
}

func TestReadAllLimited(t *testing.T) {
	body, err := readAllLimited(strings.NewReader("abcdef"), 3)
	if err != nil || string(body) != "abc" {
		t.Fatalf("限读错误: %q %v", body, err)
	}
}

func TestResolveDomainDoHFallback(t *testing.T) {
	// 系统解析失败时回退 DoH（注入 RoundTripper 返回 DoH JSON）。
	old := dohHTTPClient
	dohHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"Status":0,"Answer":[{"type":1,"data":"192.0.2.9"}]}`)),
		}, nil
	})}
	defer func() { dohHTTPClient = old }()

	ips, err := resolveDomainWith(context.Background(), "example.com", fakeResolver{ips: map[string][]string{}})
	if err != nil || len(ips) != 1 || ips[0] != "192.0.2.9" {
		t.Fatalf("DoH 回退应解析出 IP: %v %v", ips, err)
	}
}

func TestResolveDomainWrapper(t *testing.T) {
	old := defaultDNSResolver
	defaultDNSResolver = fakeResolver{ips: map[string][]string{"example.com": {"192.0.2.1"}}}
	defer func() { defaultDNSResolver = old }()
	ips, err := ResolveDomain(context.Background(), "example.com")
	if err != nil || len(ips) != 1 {
		t.Fatalf("ResolveDomain 包装错误: %v %v", ips, err)
	}
}
