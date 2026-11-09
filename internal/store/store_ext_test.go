package store

import (
	"path/filepath"
	"testing"
)

func newExtStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "ext.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestInsertVulnsAndSummary(t *testing.T) {
	st := newExtStore(t)
	scanID, _ := st.CreateScan(0, "vuln", "top")
	vulns := []VulnRecord{
		{IP: "192.0.2.1", Port: 445, Vuln: "SMBGhost", Severity: "high"},
		{IP: "192.0.2.1", Port: 445, Vuln: "SMBGhost", Severity: "high"}, // 重复，去重
		{IP: "192.0.2.2", Port: 8080, Vuln: "Struts2", Severity: "high"},
		{IP: "192.0.2.3", Port: 80, Vuln: "info-leak", Severity: "mid"},
	}
	n, err := st.InsertVulns(scanID, vulns)
	if err != nil || n != 3 {
		t.Fatalf("去重后应新增 3: n=%d err=%v", n, err)
	}
	high, mid, samples, err := st.VulnSummary(scanID, 10)
	if err != nil || high != 2 || mid != 1 || len(samples) != 3 {
		t.Fatalf("汇总错误: high=%d mid=%d samples=%d err=%v", high, mid, len(samples), err)
	}
	// 空输入 / 非法 scanID 不写入。
	if n, _ := st.InsertVulns(0, vulns); n != 0 {
		t.Fatal("非法 scanID 应不写入")
	}
	if n, _ := st.InsertVulns(scanID, nil); n != 0 {
		t.Fatal("空输入应不写入")
	}
}

func TestDomainMappings(t *testing.T) {
	st := newExtStore(t)
	m := []DomainMapping{
		{Domain: "www.example.com", IP: "192.0.2.1"},
		{Domain: "www.example.com", IP: "192.0.2.1"}, // 重复
		{Domain: "api.example.com", IP: "192.0.2.1"},
		{Domain: "api.example.com", IP: "192.0.2.2"},
		{Domain: "", IP: "192.0.2.3"}, // 跳过
	}
	n, err := st.InsertDomainMappings(m)
	if err != nil || n != 3 {
		t.Fatalf("去重后应新增 3: n=%d err=%v", n, err)
	}
	domains, _ := st.DomainsForIP("192.0.2.1")
	if len(domains) != 2 {
		t.Fatalf("IP 反查域名应 2: %v", domains)
	}
	ips, _ := st.IPsForDomain("api.example.com")
	if len(ips) != 2 {
		t.Fatalf("域名反查 IP 应 2: %v", ips)
	}
	// 默认来源应为 domain_resolver。
	if n, _ := st.InsertDomainMappings(nil); n != 0 {
		t.Fatal("空映射应不写入")
	}
}

func TestMarkScanSplitAndUpdateName(t *testing.T) {
	st := newExtStore(t)
	id, _ := st.CreateScan(1, "主任务", "top")
	if err := st.MarkScanSplit(id, 3); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateScanName(id, "主任务 [自动拆分]"); err != nil {
		t.Fatal(err)
	}
	sc, _ := st.Scan(id)
	if !sc.IsSplitTask || sc.SplitTotal != 3 || sc.Name != "主任务 [自动拆分]" {
		t.Fatalf("拆分标记/改名错误: %+v", sc)
	}
}

func TestCopySubScanVulns(t *testing.T) {
	st := newExtStore(t)
	parent, _ := st.CreateScan(1, "parent", "top")
	sub, _ := st.CreateScan(1, "sub", "top")
	_, _ = st.InsertVulns(sub, []VulnRecord{{IP: "192.0.2.1", Port: 445, Vuln: "SMBGhost", Severity: "high"}})
	n, err := st.CopySubScanVulns(parent, []int64{sub})
	if err != nil || n != 1 {
		t.Fatalf("首次聚合应 1: n=%d err=%v", n, err)
	}
	// 重复聚合去重应为 0。
	if n, _ := st.CopySubScanVulns(parent, []int64{sub}); n != 0 {
		t.Fatalf("重复聚合应去重: %d", n)
	}
	v, _ := st.VulnsByScan(parent)
	if len(v) != 1 {
		t.Fatalf("主扫描漏洞应 1: %d", len(v))
	}
	if n, _ := st.CopySubScanVulns(parent, nil); n != 0 {
		t.Fatal("空子列表应 0")
	}
}
