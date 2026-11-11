package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"easm-platform/internal/store"
)

func TestAuditTypeFilterAndTargetLink(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)
	_ = st.Audit("admin", "admin", "终止扫描执行", "#1", "", "10.0.0.1")
	_ = st.Audit("admin", "admin", "导入资产", "192.0.2.1", "", "10.0.0.1")

	body := scanLiveRequest(server, http.MethodGet, "/audit?type="+url.QueryEscape("终止"), "admin").Body.String()
	if !strings.Contains(body, "终止扫描执行") || strings.Contains(body, `href="/exposure?q=192.0.2.1"`) {
		t.Fatal("对象类型筛选应只含终止记录（导入资产行不应出现）")
	}
	if !strings.Contains(body, `name="type"`) || !strings.Contains(body, `name="from"`) {
		t.Fatal("审计页应含对象类型与时间范围筛选")
	}
	if !strings.Contains(body, `href="/scans/1"`) {
		t.Fatal("扫描 ID 对象应为可点击链接")
	}
	allBody := scanLiveRequest(server, http.MethodGet, "/audit", "admin").Body.String()
	if !strings.Contains(allBody, `href="/exposure?q=192.0.2.1"`) {
		t.Fatal("资产 IP 对象应为暴露面链接")
	}
}

func TestDomainDetailAndWhitelistAll(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)
	_, _ = st.ImportTargets([]store.TargetSpec{{Raw: "example.com", Kind: "domain"}}, "", "test")
	_, _ = st.InsertDomainMappings([]store.DomainMapping{{Domain: "example.com", IP: "192.0.2.1"}})
	id, _ := st.CreateScan(0, "s", "top")
	_ = st.InsertResults(id, []store.Result{
		{IP: "192.0.2.1", Port: 80, Proto: "tcp", Service: "HTTP", Status: 1},
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Service: "HTTPS", Status: 1},
	})

	body := scanLiveRequest(server, http.MethodGet, "/assets/domain/example.com", "operator").Body.String()
	if !strings.Contains(body, "关联端口") || !strings.Contains(body, "443") {
		t.Fatal("域名详情应含关联端口面板")
	}
	// 台账域名行应含服务标签与详情链接
	assetsBody := scanLiveRequest(server, http.MethodGet, "/assets", "operator").Body.String()
	if !strings.Contains(assetsBody, "/assets/domain/example.com") || !strings.Contains(assetsBody, "HTTP") {
		t.Fatal("台账域名行应含详情链接与服务标签")
	}

	form := url.Values{}
	form.Set("domain", "example.com")
	rec := scanFormRequest(server, "/api/assets/domain/whitelist", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("域名一键加白状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	entries, _ := st.Whitelist()
	if len(entries) != 2 {
		t.Fatalf("应加白 2 条衍生端口: %+v", entries)
	}
	for _, e := range entries {
		if e.Source != "domain" {
			t.Fatalf("来源应为 domain: %+v", e)
		}
	}
}
