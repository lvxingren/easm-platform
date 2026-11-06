package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newTestFeishu(fn roundTripFunc) *Feishu {
	return &Feishu{
		Webhook: "https://open.feishu.cn/open-apis/bot/v2/hook/test-hook",
		client:  &http.Client{Transport: fn},
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// TestSendRetriesOnConnectionReset 连接重置（read: connection reset by peer）属网络层错误，
// 应自动重试并在第二次尝试成功。
func TestSendRetriesOnConnectionReset(t *testing.T) {
	calls := 0
	f := newTestFeishu(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, errors.New(`Post "https://open.feishu.cn/...": read tcp 192.168.110.140:49700->221.204.193.68:443: read: connection reset by peer`)
		}
		return jsonResponse(200, `{"code":0,"msg":"success"}`), nil
	})
	if err := f.Send("汇总"); err != nil {
		t.Fatalf("网络错误重试后应成功，err=%v", err)
	}
	if calls != 2 {
		t.Fatalf("调用次数=%d，期望 2", calls)
	}
}

// TestSendNoRetryOnBusinessError 飞书业务错误（如签名非法）重试不会改变结果，应直接失败；
// 覆盖 code/msg 与 StatusCode/StatusMessage 两种互斥返回格式。
func TestSendNoRetryOnBusinessError(t *testing.T) {
	for _, body := range []string{
		`{"code":19021,"msg":"sign match fail"}`,
		`{"StatusCode":10002,"StatusMessage":"invalid token"}`,
	} {
		calls := 0
		f := newTestFeishu(func(r *http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(200, body), nil
		})
		if err := f.Send("汇总"); err == nil {
			t.Fatalf("业务错误应返回错误: %s", body)
		}
		if calls != 1 {
			t.Fatalf("业务错误不应重试，调用次数=%d（body=%s）", calls, body)
		}
	}
}

// TestSendRetryOnRateLimit 限流（429）应重试并在第二次成功。
func TestSendRetryOnRateLimit(t *testing.T) {
	calls := 0
	f := newTestFeishu(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(429, `{"code":9499,"msg":"rate limit"}`), nil
		}
		return jsonResponse(200, `{"code":0}`), nil
	})
	if err := f.Send("汇总"); err != nil {
		t.Fatalf("限流重试后应成功，err=%v", err)
	}
	if calls != 2 {
		t.Fatalf("调用次数=%d，期望 2", calls)
	}
}

// TestSendGivesUpAfterMaxAttempts 全部网络错误：重试耗尽后返回带次数的错误。
func TestSendGivesUpAfterMaxAttempts(t *testing.T) {
	orig := sendBackoff
	sendBackoff = []time.Duration{0, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { sendBackoff = orig })
	calls := 0
	f := newTestFeishu(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("read: connection reset by peer")
	})
	err := f.Send("汇总")
	if err == nil || !strings.Contains(err.Error(), "3 次") {
		t.Fatalf("全部失败应返回重试耗尽错误，err=%v", err)
	}
	if calls != 3 {
		t.Fatalf("调用次数=%d，期望 3", calls)
	}
}

// TestSendNoRetryOnHTTP400 4xx（除 429）不重试。
func TestSendNoRetryOnHTTP400(t *testing.T) {
	calls := 0
	f := newTestFeishu(func(r *http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(400, `bad request`), nil
	})
	if err := f.Send("汇总"); err == nil {
		t.Fatal("HTTP 400 应返回错误")
	}
	if calls != 1 {
		t.Fatalf("HTTP 400 不应重试，调用次数=%d", calls)
	}
}

// TestSendRetryOnTruncatedResponse 响应中途被 RST（JSON 截断）应重试。
func TestSendRetryOnTruncatedResponse(t *testing.T) {
	calls := 0
	f := newTestFeishu(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResponse(200, `{"code":`), nil
		}
		return jsonResponse(200, `{"code":0}`), nil
	})
	if err := f.Send("汇总"); err != nil {
		t.Fatalf("截断响应重试后应成功，err=%v", err)
	}
	if calls != 2 {
		t.Fatalf("调用次数=%d，期望 2", calls)
	}
}

// TestSendEmptyWebhook 未配置 Webhook 时静默跳过，不发任何请求。
func TestSendEmptyWebhook(t *testing.T) {
	f := &Feishu{Webhook: ""}
	if err := f.Send("不发送"); err != nil {
		t.Fatalf("空 Webhook 应静默跳过，err=%v", err)
	}
}

// TestValidateWebhookURL Webhook 地址校验：官方域名放行，其余拒绝且不重试。
func TestValidateWebhookURL(t *testing.T) {
	ok := []string{
		"https://open.feishu.cn/open-apis/bot/v2/hook/abc",
		"https://open.larksuite.com/open-apis/bot/v2/hook/abc",
		"https://open.larkoffice.com/open-apis/bot/v2/hook/abc",
	}
	for _, raw := range ok {
		if err := validateWebhookURL(raw); err != nil {
			t.Fatalf("官方域名应放行 %s: %v", raw, err)
		}
	}
	bad := []string{
		"http://open.feishu.cn/open-apis/bot/v2/hook/abc", // 非 https
		"https://evil.example.com/hook",                   // 非官方域名
		"https://open.feishu.cn.evil.com/hook",            // 后缀混淆
		"https://127.0.0.1/hook",                          // 环回地址
		"https://192.168.110.140:443/hook",                // 内网地址
		"not-a-url",
	}
	for _, raw := range bad {
		if err := validateWebhookURL(raw); err == nil {
			t.Fatalf("非法地址应拒绝: %s", raw)
		}
	}
}

// TestSendRejectsUnofficialWebhookHost 非官方主机直接失败且不发请求、不重试。
func TestSendRejectsUnofficialWebhookHost(t *testing.T) {
	calls := 0
	f := &Feishu{
		Webhook: "https://192.168.110.140/hook",
		client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(200, `{"code":0}`), nil
		})},
	}
	if err := f.Send("汇总"); err == nil {
		t.Fatal("非官方主机应拒绝发送")
	}
	if calls != 0 {
		t.Fatalf("非法地址不应发起请求，调用次数=%d", calls)
	}
}

// TestSign 签名应稳定且随时间戳变化。
func TestSign(t *testing.T) {
	got := sign("1609227842", "test-secret")
	if got == "" || got == "1609227842" {
		t.Fatalf("签名异常: %q", got)
	}
	if sign("1609227842", "test-secret") != got {
		t.Fatal("同一输入签名不稳定")
	}
	if sign("1609227843", "test-secret") == got {
		t.Fatal("不同时间戳签名应不同")
	}
}

// TestSendRetriesWithDoHAfterReset 首次尝试（系统 DNS）失败后，重试阶段应切换
// 到 DoH 客户端（模拟本地 DNS 解析到错误节点被 RST、公共 DNS 解析正确节点的场景）。
func TestSendRetriesWithDoHAfterReset(t *testing.T) {
	origDefault, origDoh := defaultFeishuClient, dohFeishuClient
	defaultFeishuClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("read tcp 192.168.110.140:41480->221.204.193.68:443: read: connection reset by peer")
	})}
	dohCalls := 0
	dohFeishuClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		dohCalls++
		return jsonResponse(200, `{"code":0}`), nil
	})}
	t.Cleanup(func() { defaultFeishuClient = origDefault; dohFeishuClient = origDoh })

	f := &Feishu{Webhook: "https://open.feishu.cn/open-apis/bot/v2/hook/test"}
	if err := f.Send("汇总"); err != nil {
		t.Fatalf("DoH 兑底重试后应成功，err=%v", err)
	}
	if dohCalls != 1 {
		t.Fatalf("DoH 客户端调用次数=%d，期望 1", dohCalls)
	}
}

// TestLookupIPsViaDoH 通过本地测试服务器验证 DoH JSON 解析与 A 记录提取。
func TestLookupIPsViaDoH(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query" || r.URL.Query().Get("name") != "open.feishu.cn" || r.URL.Query().Get("type") != "A" {
			t.Errorf("DoH 查询参数异常: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[{"name":"open.feishu.cn","type":1,"TTL":60,"data":"1.2.3.4"},{"name":"open.feishu.cn","type":1,"TTL":60,"data":"5.6.7.8"}]}`))
	}))
	defer srv.Close()
	origServers, origClient := dohServers, dohHTTPClient
	dohServers = []string{srv.URL + "/dns-query"}
	dohHTTPClient = srv.Client()
	t.Cleanup(func() { dohServers = origServers; dohHTTPClient = origClient })

	ips, err := lookupIPsViaDoH(context.Background(), "open.feishu.cn")
	if err != nil {
		t.Fatalf("DoH 解析失败: %v", err)
	}
	if len(ips) != 2 || ips[0].String() != "1.2.3.4" || ips[1].String() != "5.6.7.8" {
		t.Fatalf("DoH 解析结果异常: %v", ips)
	}
}

// TestFeishuClientDialViaResolvedIP 自定义 resolve 时拨号应指向解析出的 IP，
// 而 HTTP Host 头保持域名（SNI/证书校验不受影响）。
func TestFeishuClientDialViaResolvedIP(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	resolve := func(ctx context.Context, host string) ([]net.IP, error) {
		if host != "open.feishu.cn" {
			t.Fatalf("解析的主机名=%q，期望 open.feishu.cn", host)
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	cl := newFeishuClient(resolve)
	resp, err := cl.Get(fmt.Sprintf("http://open.feishu.cn:%d/hook", port))
	if err != nil {
		t.Fatalf("拨号解析 IP 失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码=%d", resp.StatusCode)
	}
	if gotHost != fmt.Sprintf("open.feishu.cn:%d", port) {
		t.Fatalf("Host 头=%q，期望保留域名 open.feishu.cn", gotHost)
	}
}
