package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Feishu 飞书机器人推送。Webhook 为空时所有发送操作静默跳过。
// client 为可注入的 HTTP 客户端（测试用）；nil 时使用 defaultFeishuClient。
type Feishu struct {
	Webhook string
	Secret  string
	client  *http.Client
}

// retryableError 表示可安全重试的失败（网络层错误、限流、5xx、响应传输中断）。
// 飞书业务错误（code 非 0）不可重试：重试不会改变结果。
type retryableError struct{ err error }

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

// sendBackoff 网络层重试的递增退避；测试可替换为更短的值以加速。
var sendBackoff = []time.Duration{0, time.Second, 3 * time.Second}

// dohServers 兑底 DNS 服务器（DNS over HTTPS）。本地 DNS 解析异常（如把域名解析到
// 与部署地不匹配的节点导致连接被重置）时，重试阶段改用公共 DNS 重新解析域名。
// 测试可替换为本地测试服务器地址。
var dohServers = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
}

// dohHTTPClient 查询 DoH 端点所用的 HTTP 客户端；测试可替换。
var dohHTTPClient = &http.Client{Timeout: 8 * time.Second}

// newFeishuClient 构造适配飞书 Webhook 的 HTTP 客户端，规避两类常见的连接重置：
//   - 强制 HTTP/1.1：自定义 DialContext 时 Go 默认不再协商 HTTP/2（并显式
//     ForceAttemptHTTP2=false 声明意图）。部分网络中间设备（运营商/企业防火墙）
//     对 h2 连接处理不当，会在服务端响应阶段直接 RST，表现为
//     "read tcp ...:443: read: connection reset by peer"；
//   - 短连接：每次任务结束仅推送一条汇总，频率极低，禁用 keep-alive 可避免
//     陈旧连接被对端关闭后客户端复写触发 reset；
//   - 分层超时：连接建立 / TLS 握手 / 响应头各有限制，总超时兜底防挂死。
//
// resolve 非 nil 时按该函数解析域名（绕开系统 DNS），对每个解析结果依次尝试拨号。
func newFeishuClient(resolve func(ctx context.Context, host string) ([]net.IP, error)) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
	}
	if resolve != nil {
		base := transport.DialContext
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := resolve(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				conn, err := base(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		}
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}
}

// defaultFeishuClient 走系统 DNS；dohFeishuClient 优先走公共 DNS 解析（用于网络失败后的重试兑底）。
// 两者均共享短连接 + HTTP/1.1 的保守 Transport，线程安全。
var defaultFeishuClient = newFeishuClient(nil)
var dohFeishuClient = newFeishuClient(func(ctx context.Context, host string) ([]net.IP, error) {
	if ips, err := lookupIPsViaDoH(ctx, host); err == nil && len(ips) > 0 {
		return ips, nil
	}
	// DoH 不可用（被阻断/未通外网 DNS）：回退系统解析
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
})

// lookupIPsViaDoH 通过 DoH 解析域名的 IPv4 地址，按配置顺序逐个端点尝试。
func lookupIPsViaDoH(ctx context.Context, host string) ([]net.IP, error) {
	var lastErr error
	for _, base := range dohServers {
		ips, err := queryDoH(ctx, base, host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("未配置 DoH 端点")
	}
	return nil, lastErr
}

// queryDoH 向单个 DoH 端点查询 A 记录（application/dns-json 协议）。
func queryDoH(ctx context.Context, baseURL, host string) ([]net.IP, error) {
	u := baseURL + "?name=" + url.QueryEscape(host) + "&type=A"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 端点 %s 返回 HTTP %d", baseURL, resp.StatusCode)
	}
	var rj struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rj); err != nil {
		return nil, fmt.Errorf("DoH 响应解析失败: %v", err)
	}
	var ips []net.IP
	for _, a := range rj.Answer {
		if a.Type == 1 { // A 记录
			if ip := net.ParseIP(a.Data); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DoH 未返回 %s 的 A 记录", host)
	}
	return ips, nil
}

func sign(timestamp, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp + "\n" + secret))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// validateWebhookURL 校验 Webhook 地址：必须为 HTTPS 且主机属于飞书官方域名。
// 既防止配置错误，也阻断把 Webhook 指向内网地址的 SSRF 风险；
// 校验失败返回不可重试错误（重试不会改变结果）。
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("Webhook 地址非法: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("Webhook 仅支持 https（当前 %q）", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	for _, official := range []string{"open.feishu.cn", "open.larksuite.com", "open.larkoffice.com"} {
		if host == official || strings.HasSuffix(host, "."+official) {
			return nil
		}
	}
	return fmt.Errorf("Webhook 主机 %q 不在飞书官方域名范围内，已拒绝发送", host)
}

// Send 推送一条文本消息。网络层失败自动重试（默认最多 3 次、递增退避）：
// 首次尝试走系统 DNS，重试阶段改用公共 DNS（DoH）重新解析域名，绕过本地 DNS
// 解析异常导致的节点连接重置；飞书业务错误（如签名非法）不重试，避免无效等待。
func (f *Feishu) Send(text string) error {
	if f.Webhook == "" {
		return nil
	}
	var lastErr error
	for attempt, delay := range sendBackoff {
		if delay > 0 {
			time.Sleep(delay)
		}
		lastErr = f.sendOnce(text, attempt == 0)
		if lastErr == nil {
			return nil
		}
		var re *retryableError
		if !errors.As(lastErr, &re) {
			return lastErr
		}
	}
	return fmt.Errorf("飞书推送失败（已尝试 %d 次）: %w", len(sendBackoff), lastErr)
}

func (f *Feishu) sendOnce(text string, systemDNS bool) error {
	if err := validateWebhookURL(f.Webhook); err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := map[string]interface{}{
		"timestamp": ts,
		"msg_type":  "text",
		"content":   map[string]string{"text": text},
	}
	if f.Secret != "" {
		payload["sign"] = sign(ts, f.Secret)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := f.client
	if client == nil {
		client = defaultFeishuClient
		if !systemDNS {
			client = dohFeishuClient
		}
	}
	req, err := http.NewRequest(http.MethodPost, f.Webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		// 网络层失败（connection reset、超时、DNS 等）：换新连接重试通常可恢复
		return &retryableError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		// 限流与服务端错误稍后重试
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return &retryableError{fmt.Errorf("飞书服务暂不可用（HTTP %d）", resp.StatusCode)}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("飞书返回 HTTP %d", resp.StatusCode)
	}
	var rj map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rj); err != nil {
		// 响应损坏或传输中断（对端可能在读取中途 RST）
		return &retryableError{fmt.Errorf("飞书响应解析失败: %v", err)}
	}
	// 飞书有两种互斥返回格式：code/msg 与 StatusCode/StatusMessage，
	// 按字段存在性分别判断；任一非 0 均为业务错误（重试不会改变结果）。
	if c, ok := rj["code"].(float64); ok && c != 0 {
		return fmt.Errorf("飞书返回异常: %v", rj)
	}
	if sc, ok := rj["StatusCode"].(float64); ok && sc != 0 {
		return fmt.Errorf("飞书返回异常: %v", rj)
	}
	return nil
}
