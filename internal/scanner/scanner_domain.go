package scanner

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

// 本文件实现域名资产的主动探测接线：把台账/手工目标中的域名解析为 IP 目标池，
// 标记来源 domain_resolver 并入台账与扫描范围，复用现有 naabu StartTask 流程。
// 默认关闭（domain_resolve_enabled=0），保证原有任务不受影响（向后兼容）。

// expandDomainDerived 在启用域名解析时，把域名规格展开为衍生 IP 目标并去重追加。
// 解析失败不致命（跳过），不影响原有 IP/网段目标。
func (r *Runner) expandDomainDerived(specs []store.TargetSpec) []store.TargetSpec {
	if r.setting("domain_resolve_enabled", "0") != "1" {
		return specs
	}
	var domains []string
	for _, s := range specs {
		if s.Kind == "domain" {
			domains = append(domains, s.Raw)
		}
	}
	if len(domains) == 0 {
		return specs
	}
	seeds, _ := engine.LoadSubdomainSeeds(filepath.Join("data", "subdomains.txt"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	extra, mappings := engine.CollectDomainTargetsDefault(ctx, domains, seeds)
	if len(mappings) > 0 {
		_, _ = r.st.InsertDomainMappings(mappings)
	}
	if len(extra) > 0 {
		// 衍生 IP 入台账并标注来源 domain_resolver。
		_, _ = r.st.ImportTargets(extra, "", "domain_resolver")
	}
	seen := map[string]bool{}
	for _, s := range specs {
		seen[s.Raw] = true
	}
	for _, e := range extra {
		if !seen[e.Raw] {
			seen[e.Raw] = true
			specs = append(specs, e)
		}
	}
	return specs
}

// prefetchDomainMappings 为 naabu 原生域名目标补记 domain_map：
// naabu 能直接扫描域名，但结果只保存解析后的 IP，不记录映射会导致
// 暴露面「域名」列与域名详情无法关联到端口。
// 仅用于展示/白名单匹配，不改变扫描目标；失败静默跳过（naabu 自身仍会解析）。
func (r *Runner) prefetchDomainMappings(specs []store.TargetSpec) {
	if r.setting("domain_resolve_enabled", "0") == "1" {
		return // 已由 expandDomainDerived 记录映射
	}
	seen := map[string]bool{}
	var domains []string
	for _, sp := range specs {
		if sp.Kind != "domain" {
			continue
		}
		d := normalizeHostname(sp.Raw)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		domains = append(domains, d)
		if len(domains) >= 200 { // 防止超大台账起始阻塞，其余域名由扫描结果/后续执行补齐
			break
		}
	}
	if len(domains) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var mappings []store.DomainMapping
	for _, d := range domains {
		if ctx.Err() != nil {
			break
		}
		ips, err := resolveDomainForScan(ctx, d)
		if err != nil {
			continue
		}
		for _, raw := range ips {
			if ip, ok := normalizeIP(raw); ok {
				mappings = append(mappings, store.DomainMapping{Domain: d, IP: ip, Source: "scan_target"})
			}
		}
	}
	if len(mappings) > 0 {
		_, _ = r.st.InsertDomainMappings(mappings)
	}
}

// fscanDomainSource 标记「fscan 执行前平台侧解析域名」写入 domain_map 的来源。
const fscanDomainSource = "fscan_domain"

// resolveDomainForScan 可注入以便离线测试；生产环境使用系统 DNS + DoH 回退。
var resolveDomainForScan = engine.ResolveDomain

// resolveFscanDomainTargets 在 fscan 执行前把域名规格解析为 IPv4 目标：
// fscan 自身域名解析依赖系统 DNS 且输出 host 为域名（平台结果只接受 IP），
// 直接下发域名会出现「扫描成功但 0 结果」；这里统一解析后写入目标文件，
// 同时记录域名→IP 映射供域名详情/暴露面域名列回显。
// 仅保留 IPv4（fscan 不支持 IPv6）；解析失败的域名返回给调用方决定终态。
func (r *Runner) resolveFscanDomainTargets(scanID int64, specs []store.TargetSpec) ([]store.TargetSpec, []string) {
	hasDomain := false
	for _, sp := range specs {
		if sp.Kind == "domain" {
			hasDomain = true
			break
		}
	}
	if !hasDomain {
		return specs, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out := make([]store.TargetSpec, 0, len(specs))
	seen := map[string]bool{}
	var mappings []store.DomainMapping
	var failed []string
	for _, sp := range specs {
		if sp.Kind != "domain" {
			if ip, ok := normalizeIP(sp.Raw); ok {
				seen[ip] = true
			}
			out = append(out, sp)
			continue
		}
		domain := normalizeHostname(sp.Raw)
		if domain == "" {
			failed = append(failed, sp.Raw)
			continue
		}
		ips, err := resolveDomainForScan(ctx, domain)
		if err != nil {
			failed = append(failed, domain)
			continue
		}
		resolved := 0
		for _, raw := range ips {
			ip, ok := normalizeIP(raw)
			if !ok {
				continue
			}
			if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
				continue // fscan 不支持 IPv6，写入也无法扫描
			}
			resolved++
			mappings = append(mappings, store.DomainMapping{Domain: domain, IP: ip, Source: fscanDomainSource})
			if seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, store.TargetSpec{Raw: ip, Kind: "ip"})
		}
		if resolved == 0 {
			failed = append(failed, domain)
		}
	}
	if len(mappings) > 0 {
		_, _ = r.st.InsertDomainMappings(mappings)
	}
	if len(failed) > 0 {
		sample := failed
		if len(sample) > 5 {
			sample = sample[:5]
		}
		suffix := ""
		if len(failed) > len(sample) {
			suffix = fmt.Sprintf(" 等 %d 个", len(failed))
		}
		_ = r.st.AddScanEvent(scanID, "warn", "domain", fmt.Sprintf("fscan 域名解析失败（仅支持 IPv4），未扫描：%s%s", strings.Join(sample, ", "), suffix))
	}
	return out, failed
}
