package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestWhitelistImportRemarkAndInlineEdit 验证白名单备注能力：
// 批量导入携带批量备注（手动与自动匹配条目均写入）、列表行内编辑备注（含清空）、
// 编辑不改动匹配规则、viewer 无权限、不存在条目返回 404。
func TestWhitelistImportRemarkAndInlineEdit(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)

	// 导入携带批量备注。
	form := url.Values{}
	form.Set("entries", "10.20.0.1 22,80\n10.20.0.2 3306")
	form.Set("remark", "2026-11 合规放行业务")
	rec := scanFormRequest(server, "/api/whitelist/import", "admin", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("导入状态=%d: %s", rec.Code, rec.Body.String())
	}
	entries, _ := st.Whitelist()
	if len(entries) != 2 {
		t.Fatalf("应导入 2 条，实际 %d", len(entries))
	}
	var firstID int64
	for _, e := range entries {
		if e.Remark != "2026-11 合规放行业务" {
			t.Fatalf("导入条目备注未写入: %+v", e)
		}
		if e.IPSpec == "10.20.0.1" {
			firstID = e.ID
		}
	}

	// viewer 无编辑权限。
	editForm := url.Values{}
	editForm.Set("reason", "复核放行")
	editForm.Set("remark", "越权修改")
	if rec := scanFormRequest(server, "/api/whitelist/"+strconv.FormatInt(firstID, 10)+"/remark", "viewer", editForm); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 编辑备注应 403，实际 %d", rec.Code)
	}

	// 行内编辑：改原因+备注，匹配规则不变。
	editForm.Set("reason", "工单 #1024 复核通过")
	editForm.Set("remark", "已人工确认合规")
	rec = scanFormRequest(server, "/api/whitelist/"+strconv.FormatInt(firstID, 10)+"/remark", "operator", editForm)
	if rec.Code != http.StatusOK {
		t.Fatalf("编辑原因/备注状态=%d: %s", rec.Code, rec.Body.String())
	}
	entries, _ = st.Whitelist()
	for _, e := range entries {
		if e.ID != firstID {
			continue
		}
		if e.Remark != "已人工确认合规" {
			t.Fatalf("备注未更新: %+v", e)
		}
		if e.Reason != "工单 #1024 复核通过" {
			t.Fatalf("原因未更新: %+v", e)
		}
		if e.IPSpec != "10.20.0.1" || e.PortSpec != "22,80" || e.Proto != "tcp" {
			t.Fatalf("编辑改动了匹配规则: %+v", e)
		}
	}

	// 原因必填：置空原因应 400。
	badForm := url.Values{}
	badForm.Set("reason", "")
	badForm.Set("remark", "x")
	if rec := scanFormRequest(server, "/api/whitelist/"+strconv.FormatInt(firstID, 10)+"/remark", "admin", badForm); rec.Code != http.StatusBadRequest {
		t.Fatalf("空原因应 400，实际 %d", rec.Code)
	}

	// 原因非空、备注留空 = 清除备注。
	editForm.Set("remark", "")
	if rec := scanFormRequest(server, "/api/whitelist/"+strconv.FormatInt(firstID, 10)+"/remark", "admin", editForm); rec.Code != http.StatusOK {
		t.Fatalf("清空备注状态=%d", rec.Code)
	}
	entries, _ = st.Whitelist()
	for _, e := range entries {
		if e.ID == firstID && e.Remark != "" {
			t.Fatalf("备注应被清空: %q", e.Remark)
		}
	}

	// 不存在的条目返回 404（原因非空才能走到存储层）。
	editForm.Set("remark", "x")
	if rec := scanFormRequest(server, "/api/whitelist/99999/remark", "admin", editForm); rec.Code != http.StatusNotFound {
		t.Fatalf("不存在条目应 404，实际 %d", rec.Code)
	}

	// 页面渲染：行内备注按钮与编辑弹窗存在（operator 可见）。
	page := newAuthedGet(server, "/whitelist", "admin")
	if body := page.Body.String(); !strings.Contains(body, "editWlRemark(") || !strings.Contains(body, "wl-remark-modal") || !strings.Contains(body, "批量备注") {
		t.Fatalf("白名单页缺少备注编辑入口/导入批量备注字段")
	}
}
