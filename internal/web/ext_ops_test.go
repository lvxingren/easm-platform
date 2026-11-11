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

// TestBatchDeleteTargetsRBACAndAudit 批量删除资产：viewer 拒绝、operator 生效、审计落库。
func TestBatchDeleteTargetsRBACAndAudit(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	if _, err := st.ImportTargets([]store.TargetSpec{
		{Raw: "192.0.2.10", Kind: "ip"},
		{Raw: "192.0.2.11", Kind: "ip"},
	}, "", "测试导入"); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, 2)
	for _, tg := range mustTargets(t, st) {
		ids = append(ids, strconv.FormatInt(tg.ID, 10))
	}

	form := url.Values{}
	for _, id := range ids {
		form.Add("ids", id)
	}
	if rec := scanFormRequest(server, "/api/targets/batch-delete", "viewer", form); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 批量删除状态=%d，期望 403", rec.Code)
	}
	rec := scanFormRequest(server, "/api/targets/batch-delete", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator 批量删除状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Deleted int `json:"deleted"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Deleted != 2 {
		t.Fatalf("批量删除数=%d，期望 2", resp.Deleted)
	}
	if left := mustTargets(t, st); len(left) != 0 {
		t.Fatalf("批量删除后剩余资产=%d，期望 0", len(left))
	}
	logs, _ := st.AuditLogs(20)
	found := false
	for _, entry := range logs {
		if strings.Contains(entry.Action, "批量删除资产") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("批量删除未写审计: %+v", logs)
	}
}

// TestExposureWhitelistBatchAndRBAC 暴露面批量加白：viewer 拒绝、缺端口条目跳过、审计落库。
func TestExposureWhitelistBatchAndRBAC(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	form := url.Values{}
	form.Add("ip", "192.0.2.1")
	form.Add("port", "443")
	form.Add("proto", "tcp")
	form.Add("service", "https")
	form.Add("ip", "203.0.113.7")
	form.Add("port", "")
	form.Add("proto", "tcp")
	form.Add("service", "")
	if rec := scanFormRequest(server, "/api/exposure/whitelist", "viewer", form); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 暴露面加白状态=%d，期望 403", rec.Code)
	}
	// 缺少必填原因应 400
	if rec := scanFormRequest(server, "/api/exposure/whitelist", "operator", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("未填原因应 400，实际 %d 响应=%s", rec.Code, rec.Body.String())
	}
	form.Set("reason", "业务官方服务")
	form.Set("remark", "已核实")
	rec := scanFormRequest(server, "/api/exposure/whitelist", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator 暴露面加白状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Added   int `json:"added"`
		Skipped int `json:"skipped"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Added != 1 || resp.Skipped != 1 {
		t.Fatalf("加白结果异常: %+v（期望 added=1 skipped=1）", resp)
	}
	entries, err := st.Whitelist()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].IPSpec != "192.0.2.1" || entries[0].PortSpec != "443" {
		t.Fatalf("白名单落库异常: %+v", entries)
	}
	if entries[0].Reason != "业务官方服务" || entries[0].Remark != "已核实" {
		t.Fatalf("加白原因/备注未落库: %+v", entries[0])
	}
	logs, _ := st.AuditLogs(20)
	found := false
	for _, entry := range logs {
		if strings.Contains(entry.Action, "暴露面批量加白") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("暴露面批量加白未写审计: %+v", logs)
	}
}

// TestExportResultsCSV 扫描结果导出：viewer 可读、CSV 头与内容正确、审计落库。
func TestExportResultsCSV(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	scanID, err := st.CreateScan(1, "导出验证执行", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InsertResults(scanID, []store.Result{
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Service: "https", Status: 1},
	}); err != nil {
		t.Fatal(err)
	}
	rec := scanLiveRequest(server, http.MethodGet, "/results/export", "viewer")
	if rec.Code != http.StatusOK {
		t.Fatalf("导出扫描结果状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "results.csv") {
		t.Fatalf("导出文件名异常: %s", rec.Header().Get("Content-Disposition"))
	}
	for _, want := range []string{"IP", "192.0.2.1", "https", "常用端口 top-1000", "导出验证执行"} {
		if !strings.Contains(body, want) {
			t.Fatalf("导出内容缺少 %q，正文=%s", want, body)
		}
	}
}

// TestExportWhitelistCSV 白名单导出：viewer 可读、内容正确。
func TestExportWhitelistCSV(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	if _, err := st.AddWhitelist(store.WLEntry{IPSpec: "1.2.3.4", PortSpec: "22,443", Proto: "tcp", Owner: "tester", Remark: "测试"}); err != nil {
		t.Fatal(err)
	}
	rec := scanLiveRequest(server, http.MethodGet, "/whitelist/export", "viewer")
	if rec.Code != http.StatusOK {
		t.Fatalf("导出白名单状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "IP/网段") || !strings.Contains(body, "1.2.3.4") {
		t.Fatalf("白名单导出内容异常: %s", body)
	}
}

// TestExportAuditAdminOnlyAndFilter 审计导出：viewer 拒绝、admin 可导出且支持关键词筛选。
func TestExportAuditAdminOnlyAndFilter(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)
	form := url.Values{}
	form.Set("spec", "1.2.3.4")
	form.Set("owner", "张三")
	if rec := scanFormRequest(server, "/api/targets", "operator", form); rec.Code != http.StatusOK {
		t.Fatalf("新增资产状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	if rec := scanLiveRequest(server, http.MethodGet, "/audit/export", "viewer"); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 导出审计状态=%d，期望 403", rec.Code)
	}
	rec := scanLiveRequest(server, http.MethodGet, "/audit/export?q=%E6%96%B0%E5%A2%9E%E8%B5%84%E4%BA%A7", "admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin 导出审计状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "新增资产") || !strings.Contains(body, "操作") {
		t.Fatalf("审计导出内容异常: %s", body)
	}
}

// TestAuditLogsFilteredStore 审计筛选（store 层）：关键词命中与用户名过滤。
func TestAuditLogsFilteredStore(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	form := url.Values{}
	form.Set("spec", "1.2.3.4")
	if rec := scanFormRequest(server, "/api/targets", "operator", form); rec.Code != http.StatusOK {
		t.Fatalf("新增资产状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	logs, err := st.AuditLogsFiltered("新增资产", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatalf("按关键词筛选无结果")
	}
	byUser, err := st.AuditLogsFiltered("", "operator", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range byUser {
		if entry.Username != "operator" {
			t.Fatalf("按用户名筛选混入其他用户: %+v", entry)
		}
	}
	if len(byUser) == 0 {
		t.Fatalf("按用户名筛选无结果")
	}
	none, err := st.AuditLogsFiltered("不存在的关键词xyz", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("无关关键词应无结果: %+v", none)
	}
}

// TestWhitelistSingleAddRequiresReason 单条新增白名单：reason 必填，缺失 400，填写后与 remark 分开落库。
func TestWhitelistSingleAddRequiresReason(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)
	form := url.Values{}
	form.Set("ip_spec", "10.1.0.1")
	form.Set("port_spec", "443")
	form.Set("proto", "tcp")
	if rec := scanFormRequest(server, "/api/whitelist", "admin", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺原因应 400，实际 %d 响应=%s", rec.Code, rec.Body.String())
	}
	form.Set("reason", "业务官方服务")
	form.Set("remark", "备注x")
	if rec := scanFormRequest(server, "/api/whitelist", "admin", form); rec.Code != http.StatusOK {
		t.Fatalf("带原因应 200，实际 %d 响应=%s", rec.Code, rec.Body.String())
	}
	entries, _ := st.Whitelist()
	if len(entries) != 1 || entries[0].Reason != "业务官方服务" || entries[0].Remark != "备注x" {
		t.Fatalf("原因/备注未正确落库: %+v", entries)
	}
}

// TestTasksPageResumeEntry 任务页在存在可续扫执行（stopped/partial 且有未完成目标）时显示「继续扫描」入口并链到详情页；无则隐藏。
func TestTasksPageResumeEntry(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)
	if body := newAuthedGet(server, "/tasks", "operator").Body.String(); strings.Contains(body, "继续扫描") {
		t.Fatal("无未完成执行时不应显示继续扫描入口")
	}
	sid, _ := st.CreateScan(0, "终止任务", "top")
	_ = st.InitTargetStatus(sid, []store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}, {Raw: "192.0.2.2", Kind: "ip"}}, 1)
	_ = st.MarkBatchTargetStatus(sid, 0, store.TargetDone)
	_ = st.FinishScanStatus(sid, "stopped", 1, "用户终止")
	body := newAuthedGet(server, "/tasks", "operator").Body.String()
	if !strings.Contains(body, "继续扫描") || !strings.Contains(body, "/scans/"+strconv.FormatInt(sid, 10)) {
		t.Fatal("存在可续扫执行时应显示继续扫描入口并链接详情页")
	}
	// 已完成（done）的执行不应触发入口。
	doneID, _ := st.CreateScan(0, "已完成", "top")
	_ = st.InitTargetStatus(doneID, []store.TargetSpec{{Raw: "192.0.2.3", Kind: "ip"}}, 1)
	_ = st.MarkBatchTargetStatus(doneID, 0, store.TargetDone)
	_ = st.FinishScanStatus(doneID, "done", 1, "")
	if sc, _ := st.LatestResumableScan(); sc == nil || sc.ID != sid {
		t.Fatalf("LatestResumableScan 应返回最近的可续扫执行 #%d，实际 %+v", sid, sc)
	}
}
