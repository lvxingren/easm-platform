package scanner

import (
	"context"
	"path/filepath"
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
