package scanner

import (
	"context"
	"errors"
	"testing"

	"easm-platform/internal/store"
)

// TestResolveFscanDomainTargets 验证 fscan 域名目标在执行前被解析为 IPv4：
// 仅保留 IPv4（fscan 不支持 IPv6）、重复 IP 去重、解析失败的域名上报并记录映射。
func TestResolveFscanDomainTargets(t *testing.T) {
	r, st := newFscanRunner(t)
	taskID, err := st.CreateScanTask(store.ScanTask{Name: "域名检测", Mode: "top", Engine: "fscan", TargetType: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := st.CreateScan(taskID, "域名检测", "top")
	if err != nil {
		t.Fatal(err)
	}

	old := resolveDomainForScan
	resolveDomainForScan = func(ctx context.Context, domain string) ([]string, error) {
		switch domain {
		case "example.com":
			return []string{"203.0.113.5", "2001:db8::1"}, nil
		case "dup.example.com":
			return []string{"203.0.113.5"}, nil
		default:
			return nil, errors.New("no such host")
		}
	}
	t.Cleanup(func() { resolveDomainForScan = old })

	specs := []store.TargetSpec{
		{Raw: "example.com", Kind: "domain"},
		{Raw: "dup.example.com", Kind: "domain"},
		{Raw: "bad.example.com", Kind: "domain"},
		{Raw: "192.0.2.9", Kind: "ip"},
	}
	got, failed := r.resolveFscanDomainTargets(scanID, specs)
	if len(got) != 2 || got[0].Raw != "203.0.113.5" || got[1].Raw != "192.0.2.9" {
		t.Fatalf("解析后目标错误: %+v", got)
	}
	if len(failed) != 1 || failed[0] != "bad.example.com" {
		t.Fatalf("失败域名应上报 bad.example.com: %v", failed)
	}
	domains, err := st.DomainsForIP("203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 {
		t.Fatalf("domain_map 应记录两个域名指向同一 IP: %v", domains)
	}
	if ips, _ := st.IPsForDomain("example.com"); len(ips) != 1 || ips[0] != "203.0.113.5" {
		t.Fatalf("IPv6 不应写入 fscan 目标: %v", ips)
	}
}

// TestPrefetchDomainMappings 校验 naabu 域名目标在启动前记录映射；
// 已开启「域名衍生 IP 扫描」时不重复解析（映射由 expandDomainDerived 负责）。
func TestPrefetchDomainMappings(t *testing.T) {
	r, st := newFscanRunner(t)
	old := resolveDomainForScan
	t.Cleanup(func() { resolveDomainForScan = old })
	resolveDomainForScan = func(ctx context.Context, domain string) ([]string, error) {
		return []string{"198.51.100.7", "2001:db8::7"}, nil
	}
	r.prefetchDomainMappings([]store.TargetSpec{{Raw: "API.Example.com.", Kind: "domain"}})
	if ips, err := st.IPsForDomain("api.example.com"); err != nil || len(ips) != 2 {
		t.Fatalf("naabu 域名映射未记录: %v err=%v", ips, err)
	}

	_ = st.SetSetting("domain_resolve_enabled", "1")
	resolveDomainForScan = func(ctx context.Context, domain string) ([]string, error) {
		t.Fatalf("已启用衍生扫描时不应重复解析: %s", domain)
		return nil, nil
	}
	r.prefetchDomainMappings([]store.TargetSpec{{Raw: "other.example.com", Kind: "domain"}})
}

// TestResolveFscanDomainTargetsNoDomain 纯 IP 任务不应触碰 DNS 与映射。
func TestResolveFscanDomainTargetsNoDomain(t *testing.T) {
	r, _ := newFscanRunner(t)
	old := resolveDomainForScan
	resolveDomainForScan = func(ctx context.Context, domain string) ([]string, error) {
		t.Fatalf("纯 IP 任务不应解析域名: %s", domain)
		return nil, nil
	}
	t.Cleanup(func() { resolveDomainForScan = old })

	specs := []store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}, {Raw: "10.0.0.0/24", Kind: "cidr"}}
	got, failed := r.resolveFscanDomainTargets(0, specs)
	if len(failed) != 0 || len(got) != len(specs) {
		t.Fatalf("纯 IP 任务目标不应变化: got=%+v failed=%v", got, failed)
	}
}
