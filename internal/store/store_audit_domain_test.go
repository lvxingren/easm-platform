package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAuditLogsAdvancedTypeAndTime(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.Audit("admin", "admin", "终止扫描执行", "#1", "", "10.0.0.1")
	_ = st.Audit("op", "operator", "导入资产", "192.0.2.1", "", "10.0.0.2")
	_ = st.Audit("op", "operator", "登录", "", "", "10.0.0.2")
	_ = st.Audit("op", "operator", "自定义杂项", "", "", "10.0.0.2")

	term, err := st.AuditLogsAdvanced("", "", "终止", "", "", 100)
	if err != nil || len(term) != 1 || term[0].Action != "终止扫描执行" {
		t.Fatalf("类型=终止 应 1 条: %+v err=%v", term, err)
	}
	other, err := st.AuditLogsAdvanced("", "", "其他", "", "", 100)
	if err != nil || len(other) != 1 || other[0].Action != "自定义杂项" {
		t.Fatalf("类型=其他 应 1 条: %+v err=%v", other, err)
	}
	// 组合：操作人 + 类型
	comb, err := st.AuditLogsAdvanced("", "op", "导入资产", "", "", 100)
	if err != nil || len(comb) != 1 {
		t.Fatalf("组合查询应 1 条: %+v err=%v", comb, err)
	}
	// 时间范围：未来起点应无结果
	none, err := st.AuditLogsAdvanced("", "", "", "2999-01-01", "", 100)
	if err != nil || len(none) != 0 {
		t.Fatalf("未来起点应 0 条: %+v err=%v", none, err)
	}
	// 旧签名兼容
	all, err := st.AuditLogsFiltered("", "", 100)
	if err != nil || len(all) != 4 {
		t.Fatalf("旧签名应返回全部 4 条: %+v err=%v", all, err)
	}
}

// TestAuditTimeFilterLocalDay 验证按本地时区的日期筛选能命中同时区写入的 ts：
// 旧实现补 'Z' 后与本地偏移 RFC3339 字典序比较会错位（东八区当天条目被误筛掉）。
func TestAuditTimeFilterLocalDay(t *testing.T) {
	if _, offset := time.Now().Zone(); offset == 0 {
		t.Skip("UTC 时区下 Z 与本地偏移无差异，无法暴露比较错位")
	}
	st, err := Open(filepath.Join(t.TempDir(), "audit_time.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.Audit("admin", "admin", "登录", "", "", "10.0.0.1")
	today := time.Now().Format("2006-01-02")
	hits, err := st.AuditLogsAdvanced("", "", "", today, today, 100)
	if err != nil || len(hits) != 1 {
		t.Fatalf("本地当天区间应命中刚写入的审计: %+v err=%v", hits, err)
	}
	if got := normalizeAuditTime("bad-input", false); got != "" {
		t.Fatalf("非法输入应忽略筛选，得到 %q", got)
	}
}

func TestDomainServices(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "dom.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, _ = st.InsertDomainMappings([]DomainMapping{{Domain: "example.com", IP: "192.0.2.1"}, {Domain: "example.com", IP: "192.0.2.2"}})
	id, _ := st.CreateScan(0, "s", "top")
	_ = st.InsertResults(id, []Result{
		{IP: "192.0.2.1", Port: 80, Proto: "tcp", Service: "HTTP", Status: 1},
		{IP: "192.0.2.1", Port: 22, Proto: "tcp", Service: "SSH", Status: 1},
		{IP: "192.0.2.2", Port: 53, Proto: "udp", Service: "DNS", Status: 1},
		{IP: "192.0.2.9", Port: 80, Proto: "tcp", Service: "HTTP", Status: 1}, // 不在 domain_map
	})
	svc, err := st.DomainServices("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(svc) != 3 { // HTTP/SSH/DNS，去重且排除未映射 IP
		t.Fatalf("服务指纹应 3 种: %+v", svc)
	}
}
