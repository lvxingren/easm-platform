package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestDomainAssetCreateEditExportAndRBAC(t *testing.T) {
	server, st := newScanLiveTestServer(t)

	form := url.Values{}
	form.Set("spec", "example.com")
	form.Set("owner", "张三")
	form.Set("security_device", "WAF")
	form.Set("tags", "生产")

	// viewer 不能新增
	if rec := scanFormRequest(server, "/api/targets", "viewer", form); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 新增资产应 403，实际 %d", rec.Code)
	}
	// operator 新增域名资产
	if rec := scanFormRequest(server, "/api/targets", "operator", form); rec.Code != http.StatusOK {
		t.Fatalf("新增域名资产状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	targets, _ := st.Targets()
	var domainID int64
	found := false
	for _, tg := range targets {
		if tg.IP == "example.com" {
			found = true
			domainID = tg.ID
			if tg.Kind != "domain" || tg.Domain != "example.com" || tg.Owner != "张三" || tg.SecurityDevice != "WAF" || tg.Tags != "生产" {
				t.Fatalf("域名资产字段错误: %+v", tg)
			}
		}
	}
	if !found {
		t.Fatal("域名资产未入库")
	}

	// 非法目标应 400
	bad := url.Values{}
	bad.Set("spec", "这不是合法目标 !!")
	if rec := scanFormRequest(server, "/api/targets", "operator", bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法目标应 400，实际 %d", rec.Code)
	}

	// 编辑维护信息
	edit := url.Values{}
	edit.Set("owner", "李四")
	edit.Set("security_device", "云盾")
	edit.Set("tags", "生产,核心")
	if rec := scanFormRequest(server, "/api/targets/"+strconv.FormatInt(domainID, 10), "operator", edit); rec.Code != http.StatusOK {
		t.Fatalf("编辑资产状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	targets, _ = st.Targets()
	for _, tg := range targets {
		if tg.ID == domainID {
			if tg.Owner != "李四" || tg.SecurityDevice != "云盾" || tg.Tags != "生产,核心" {
				t.Fatalf("编辑未生效: %+v", tg)
			}
		}
	}

	// 导出 CSV 含新列与域名/维护信息
	exp := scanLiveRequest(server, http.MethodGet, "/assets/export", "operator")
	if exp.Code != http.StatusOK {
		t.Fatalf("导出资产状态=%d", exp.Code)
	}
	body := exp.Body.String()
	for _, want := range []string{"维护人员", "安全设备", "域名", "example.com", "李四", "云盾"} {
		if !strings.Contains(body, want) {
			t.Fatalf("导出 CSV 缺少 %q", want)
		}
	}

	// 审计：新增与编辑资产均应记录
	logs, _ := st.AuditLogs(20)
	foundCreate, foundEdit := false, false
	for _, entry := range logs {
		if entry.Action == "新增资产" {
			foundCreate = true
		}
		if entry.Action == "编辑资产" {
			foundEdit = true
		}
	}
	if !foundCreate || !foundEdit {
		t.Fatalf("新增/编辑资产审计缺失: create=%v edit=%v", foundCreate, foundEdit)
	}
}
