package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"easm-platform/internal/store"
)

// TestBaselinePreviewAndApply 基线预览返回未加白端口，应用后写入 owner=baseline + business；viewer 拒绝。
func TestBaselinePreviewAndApply(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	scanID, err := st.CreateScan(1, "完成扫描", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartScanExecution(scanID, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertResults(scanID, []store.Result{
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Service: "https", Status: 1},
		{IP: "192.0.2.1", Port: 80, Proto: "tcp", Status: 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScanStatus(scanID, "done", 2, ""); err != nil {
		t.Fatal(err)
	}

	// viewer 无写权限
	if rec := scanLiveRequest(server, http.MethodGet, "/api/baseline/preview", "viewer"); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 预览状态=%d，期望 403", rec.Code)
	}

	// operator 预览：应返回 2 条未加白端口
	rec := scanLiveRequest(server, http.MethodGet, "/api/baseline/preview", "operator")
	if rec.Code != http.StatusOK {
		t.Fatalf("预览状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	var preview struct {
		Total   int   `json:"total"`
		ScanID  int64 `json:"scan_id"`
		Entries []struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Total != 2 || preview.ScanID != scanID || len(preview.Entries) != 2 {
		t.Fatalf("预览结果异常: %+v", preview)
	}

	// 应用勾选的一条，带业务归属
	form := url.Values{}
	form.Set("business", "核心业务")
	form.Add("ip", "192.0.2.1")
	form.Add("port", "443")
	form.Add("proto", "tcp")
	form.Add("service", "https")
	if rec := scanFormRequest(server, "/api/baseline/apply", "viewer", form); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 应用基线状态=%d，期望 403", rec.Code)
	}
	rec = scanFormRequest(server, "/api/baseline/apply", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("应用基线状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	var applied struct {
		Added int `json:"added"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &applied)
	if applied.Added != 1 {
		t.Fatalf("应用新增数=%d，期望 1", applied.Added)
	}
	wl, _ := st.Whitelist()
	var found bool
	for _, e := range wl {
		if e.IPSpec == "192.0.2.1" && e.PortSpec == "443" {
			found = true
			if e.Owner != "baseline" || e.Business != "核心业务" {
				t.Fatalf("基线条目 owner/business 错误: %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("基线条目未写入白名单")
	}

	// 再次预览：已加白的 443 应被排除，仅剩 80
	rec = scanLiveRequest(server, http.MethodGet, "/api/baseline/preview", "operator")
	_ = json.Unmarshal(rec.Body.Bytes(), &preview)
	if preview.Total != 1 || preview.Entries[0].Port != 80 {
		t.Fatalf("已加白端口应从预览排除: %+v", preview)
	}
}

// TestCustomPortTaskValidation 自定义端口任务：非法端口/空端口拒绝，合法端口保存并读回。
func TestCustomPortTaskValidation(t *testing.T) {
	server, st := newScanLiveTestServer(t)

	// 非法端口
	bad := url.Values{}
	bad.Set("name", "自定义端口任务")
	bad.Set("mode", "custom")
	bad.Set("custom_ports", "99999")
	bad.Set("target_type", "all")
	if rec := scanFormRequest(server, "/api/tasks", "operator", bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法端口应 400，实际 %d，响应=%s", rec.Code, rec.Body.String())
	}

	// 空端口
	empty := url.Values{}
	empty.Set("name", "自定义端口任务")
	empty.Set("mode", "custom")
	empty.Set("custom_ports", "")
	empty.Set("target_type", "all")
	if rec := scanFormRequest(server, "/api/tasks", "operator", empty); rec.Code != http.StatusBadRequest {
		t.Fatalf("空自定义端口应 400，实际 %d", rec.Code)
	}

	// 合法端口
	good := url.Values{}
	good.Set("name", "自定义端口任务")
	good.Set("mode", "custom")
	good.Set("custom_ports", "22,80,8000-9000")
	good.Set("target_type", "all")
	rec := scanFormRequest(server, "/api/tasks", "operator", good)
	if rec.Code != http.StatusOK {
		t.Fatalf("合法自定义端口任务状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	task, err := st.ScanTask(resp.ID)
	if err != nil || task == nil {
		t.Fatalf("读取任务失败: %v", err)
	}
	if task.Mode != "custom" || task.CustomPorts != "22,80,8000-9000" {
		t.Fatalf("自定义端口任务保存错误: %+v", task)
	}
}

// TestScanResyncAction 手动同步：非活动的悬空 running 执行被修正为 stopped；viewer 拒绝。
func TestScanResyncAction(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	scanID, err := st.CreateScan(1, "悬空执行", "top") // status=running，但服务未在跑该扫描
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/scans/" + strconv.FormatInt(scanID, 10) + "/resync"
	if rec := scanFormRequest(server, path, "viewer", url.Values{}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 同步状态=%d，期望 403", rec.Code)
	}
	rec := scanFormRequest(server, path, "operator", url.Values{})
	if rec.Code != http.StatusOK {
		t.Fatalf("同步状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	sc, _ := st.Scan(scanID)
	if sc == nil || sc.Status != "stopped" {
		t.Fatalf("悬空执行未修正为 stopped: %+v", sc)
	}
	if !strings.Contains(sc.Err, "同步") {
		t.Fatalf("同步说明缺失: %q", sc.Err)
	}
	// 审计应记录
	logs, _ := st.AuditLogs(20)
	var audited bool
	for _, entry := range logs {
		if strings.Contains(entry.Action, "同步扫描执行状态") {
			audited = true
			break
		}
	}
	if !audited {
		t.Fatal("状态同步未写审计")
	}
}
