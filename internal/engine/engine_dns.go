package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"easm-platform/internal/store"
)

// 本文件实现域名资产的被动发现与主动探测：DNS 递归解析（A/AAAA/CNAME）、
// 子域名种子枚举、可选 Subfinder 集成，以及域名→IP 目标池与告警去重。
// 解析出的 IP 以 source=domain_resolver 标注入库，复用现有 naabu StartTask 扫描。

// dnsResolver 抽象 DNS 查询能力，便于测试注入（生产用 net.Resolver）。
type dnsResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// defaultDNSResolver 使用系统解析器；失败时由 ResolveDomain 回退公共 DoH。
var defaultDNSResolver dnsResolver = net.DefaultResolver

// dohEndpoint 是固定的公共 DoH JSON 白名单主机（Google DNS，HTTPS），不可由用户配置，
// 域名仅作为查询参数（转义后）传入，不改变请求目的地，避免 SSRF。
const dohEndpoint = "https://dns.google/resolve"

// dohHTTPClient 可注入以便测试。
var dohHTTPClient = &http.Client{Timeout: 8 * time.Second}

// ResolveDomain 对域名递归查询 A/AAAA 与 CNAME，返回去重后的 IP 列表。
// 系统解析失败时回退公共 DoH；两者都失败返回错误。
func ResolveDomain(ctx context.Context, domain string) ([]string, error) {
	return resolveDomainWith(ctx, domain, defaultDNSResolver)
}

func resolveDomainWith(ctx context.Context, domain string, r dnsResolver) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "*.")
	if domain == "" {
		return nil, fmt.Errorf("域名为空")
	}
	seen := map[string]bool{}
	var ips []string
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	if r != nil {
		if addrs, err := r.LookupIPAddr(ctx, domain); err == nil {
			for _, a := range addrs {
				add(a.IP.String())
			}
		}
	}
	if len(ips) == 0 {
		if dohIPs, err := dohLookup(ctx, domain); err == nil {
			for _, ip := range dohIPs {
				add(ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("域名 %q 解析不到任何 IP", domain)
	}
	return ips, nil
}

// dohAnswer 是 DoH JSON 响应的 Answer 子集。
type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

// parseDoHAnswer 从 DoH JSON 中提取 A(1)/AAAA(28) 记录的 IP。
func parseDoHAnswer(body []byte) ([]string, error) {
	var resp dohResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	var ips []string
	for _, a := range resp.Answer {
		if a.Type == 1 || a.Type == 28 {
			if net.ParseIP(strings.TrimSpace(a.Data)) != nil {
				ips = append(ips, strings.TrimSpace(a.Data))
			}
		}
	}
	return ips, nil
}

func dohLookup(ctx context.Context, domain string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dohEndpoint+"?name="+url.QueryEscape(domain)+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readAllLimited(resp.Body, 1<<20)
	if err != nil {
		return nil, err
	}
	return parseDoHAnswer(body)
}

// readAllLimited 读取响应体但限制上限，避免超大响应耗尽内存。
func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

// LoadSubdomainSeeds 读取子域种子文件（每行一个子域前缀，忽略空行与 # 注释），去重返回。
func LoadSubdomainSeeds(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	seen := map[string]bool{}
	var seeds []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ToLower(line)
		if !seen[line] {
			seen[line] = true
			seeds = append(seeds, line)
		}
	}
	return seeds, sc.Err()
}

// ExpandDomainSeeds 由主域名与种子前缀生成候选子域名（含主域名本身），去重。
// 通配符 *.example.com 归一为 example.com 后再展开。
func ExpandDomainSeeds(domain string, seeds []string) []string {
	base := strings.ToLower(strings.TrimSpace(domain))
	base = strings.TrimPrefix(base, "*.")
	if base == "" {
		return nil
	}
	seen := map[string]bool{base: true}
	out := []string{base}
	for _, s := range seeds {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		host := s + "." + base
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

// parseSubfinderOutput 解析 Subfinder 一行输出为一个子域名（忽略空行/日志）。
func parseSubfinderOutput(line string) (string, bool) {
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" || strings.ContainsAny(line, " \t") {
		return "", false
	}
	if ValidDomain(line) {
		return line, true
	}
	return "", false
}

// subfinderArgs 构造 Subfinder 命令行（-d 主域名 -o 输出 -silent）。
func subfinderArgs(domain, outFile string) []string {
	return []string{"-d", domain, "-o", outFile, "-silent"}
}

// registrableDomain 返回可注册域（最后两级），用于同一主域不同子域的告警合并。
func registrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	labels := strings.Split(host, ".")
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return host
}

// DomainPortKey 生成「主域+端口」合并键：同一主域不同子域的相同端口共用一个键，避免重复告警。
func DomainPortKey(domain string, port int) string {
	return fmt.Sprintf("%s|%d", registrableDomain(domain), port)
}

// CollectDomainTargetsDefault 使用系统 DNS（失败回退公共 DoH）解析域名目标池，供扫描器调用。
func CollectDomainTargetsDefault(ctx context.Context, domains, seeds []string) ([]store.TargetSpec, []store.DomainMapping) {
	return CollectDomainTargets(ctx, domains, seeds, defaultDNSResolver)
}

// CollectDomainTargets 解析域名（含种子子域）为 IP 目标池与域名→IP 映射。
// 返回的 TargetSpec 以 IP 为 Raw（Kind=ip），映射 source=domain_resolver，供台账标注与暴露面域名列。
func CollectDomainTargets(ctx context.Context, domains []string, seeds []string, r dnsResolver) ([]store.TargetSpec, []store.DomainMapping) {
	ipSeen := map[string]bool{}
	var specs []store.TargetSpec
	var mappings []store.DomainMapping
	for _, domain := range domains {
		for _, host := range ExpandDomainSeeds(domain, seeds) {
			ips, err := resolveDomainWith(ctx, host, r)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				mappings = append(mappings, store.DomainMapping{Domain: host, IP: ip, Source: "domain_resolver"})
				if !ipSeen[ip] {
					ipSeen[ip] = true
					specs = append(specs, store.TargetSpec{Raw: ip, Kind: "ip"})
				}
			}
		}
	}
	return specs, mappings
}
