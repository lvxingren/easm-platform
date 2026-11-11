package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"easm-platform/internal/store"
)

func TestAssetsPaginationAPI(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	var specs []store.TargetSpec
	for i := 1; i <= 45; i++ {
		specs = append(specs, store.TargetSpec{Raw: fmt.Sprintf("10.0.0.%d", i), Kind: "ip"})
	}
	if _, err := st.ImportTargets(specs, "", "test"); err != nil {
		t.Fatal(err)
	}

	rec := scanLiveRequest(server, http.MethodGet, "/api/assets?page_size=20", "operator")
	if rec.Code != http.StatusOK {
		t.Fatalf("api/assets 状态=%d", rec.Code)
	}
	var p1 struct {
		Items    []store.Target `json:"items"`
		Total    int            `json:"total"`
		Page     int            `json:"page"`
		PageSize int            `json:"page_size"`
		Pages    int            `json:"pages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p1); err != nil {
		t.Fatal(err)
	}
	if p1.Total != 45 || p1.Pages != 3 || len(p1.Items) != 20 || p1.PageSize != 20 {
		t.Fatalf("分页错误: total=%d pages=%d items=%d size=%d", p1.Total, p1.Pages, len(p1.Items), p1.PageSize)
	}
	// 末页
	rec = scanLiveRequest(server, http.MethodGet, "/api/assets?page_size=20&page=3", "operator")
	_ = json.Unmarshal(rec.Body.Bytes(), &p1)
	if len(p1.Items) != 5 || p1.Page != 3 {
		t.Fatalf("末页应 5 条: items=%d page=%d", len(p1.Items), p1.Page)
	}
	// page_size 上限 100
	rec = scanLiveRequest(server, http.MethodGet, "/api/assets?page_size=500", "operator")
	_ = json.Unmarshal(rec.Body.Bytes(), &p1)
	if p1.PageSize != 100 {
		t.Fatalf("page_size 应钳制 100: %d", p1.PageSize)
	}
	// 页面渲染含分页控件
	body := scanLiveRequest(server, http.MethodGet, "/assets?page_size=50", "operator").Body.String()
	if !strings.Contains(body, "page-size") || !strings.Contains(body, "共 45 条") {
		t.Fatal("资产页应含分页控件与总数")
	}
}

func TestWhitelistImportAutoMatch(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	// 台账内 IP + 历史开放端口
	if _, err := st.ImportTargets([]store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}}, "", "test"); err != nil {
		t.Fatal(err)
	}
	scanID, _ := st.CreateScan(0, "s", "top")
	_ = st.InsertResults(scanID, []store.Result{
		{IP: "192.0.2.1", Port: 80, Proto: "tcp", Status: 1},
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Status: 1},
	})

	form := url.Values{}
	form.Set("entries", "192.0.2.1\n192.0.2.9 22\n10.0.0.0/24\n")
	form.Set("auto_match", "on")
	rec := scanFormRequest(server, "/api/whitelist/import", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("导入状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ManualAdded int      `json:"manual_added"`
		AutoAdded   int      `json:"auto_added"`
		Skipped     []string `json:"skipped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ManualAdded != 1 || resp.AutoAdded != 2 {
		t.Fatalf("手动应1自动应2: %+v", resp)
	}
	if len(resp.Skipped) != 1 { // CIDR 跳过
		t.Fatalf("CIDR 应跳过: %+v", resp.Skipped)
	}
	entries, _ := st.Whitelist()
	auto := 0
	for _, e := range entries {
		if e.Source == "auto_match" {
			auto++
		}
	}
	if auto != 2 {
		t.Fatalf("auto_match 条目应 2: %d", auto)
	}
}

func TestWhitelistImportNoAutoMatchRejectsIPOnly(t *testing.T) {
	server, _ := newScanLiveTestServer(t)
	form := url.Values{}
	form.Set("entries", "192.0.2.1\n") // 无端口且未勾选自动匹配
	rec := scanFormRequest(server, "/api/whitelist/import", "operator", form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未勾选自动匹配时纯 IP 行应报错: %d", rec.Code)
	}
}
