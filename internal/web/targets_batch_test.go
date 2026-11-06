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

func mustTargets(t *testing.T, st *store.Store) []store.Target {
	t.Helper()
	targets, err := st.Targets()
	if err != nil {
		t.Fatal(err)
	}
	return targets
}

func TestBatchTargetTagsSetAppendAndIPMapping(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	if _, err := st.ImportTargets([]store.TargetSpec{
		{Raw: "192.0.2.10", Kind: "ip"},
		{Raw: "192.0.2.11", Kind: "ip"},
	}, "", "测试导入"); err != nil {
		t.Fatal(err)
	}
	targets := mustTargets(t, st)
	if len(targets) != 2 {
		t.Fatalf("导入资产数=%d，期望 2", len(targets))
	}
	ids := make([]string, 0, len(targets))
	for _, tg := range targets {
		ids = append(ids, strconv.FormatInt(tg.ID, 10))
	}

	// viewer 无写权限
	form := url.Values{}
	form.Set("mode", "append")
	form.Set("tags", "生产")
	for _, id := range ids {
		form.Add("target_ids", id)
	}
	if rec := scanFormRequest(server, "/api/targets/batch-tags", "viewer", form); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 批量改标签状态=%d，期望 403", rec.Code)
	}

	// operator 追加标签
	rec := scanFormRequest(server, "/api/targets/batch-tags", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator 追加标签状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Updated int `json:"updated"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Updated != 2 {
		t.Fatalf("追加更新数=%d，期望 2", resp.Updated)
	}
	for _, tg := range mustTargets(t, st) {
		if !strings.Contains(tg.Tags, "生产") {
			t.Fatalf("资产 %d 标签未追加: %q", tg.ID, tg.Tags)
		}
	}

	// 覆盖标签（含空格应被清洗）
	setForm := url.Values{}
	setForm.Set("mode", "set")
	setForm.Set("tags", "核心, 生产")
	for _, id := range ids {
		setForm.Add("target_ids", id)
	}
	if rec := scanFormRequest(server, "/api/targets/batch-tags", "operator", setForm); rec.Code != http.StatusOK {
		t.Fatalf("覆盖标签状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	for _, tg := range mustTargets(t, st) {
		if tg.Tags != "核心,生产" {
			t.Fatalf("覆盖后标签=%q，期望 核心,生产", tg.Tags)
		}
	}

	// 按 IP 匹配（告警关联资产场景），其中一个 IP 不在台账
	ipForm := url.Values{}
	ipForm.Set("mode", "append")
	ipForm.Set("tags", "告警核查")
	ipForm.Add("ips", "192.0.2.10")
	ipForm.Add("ips", "203.0.113.99")
	rec = scanFormRequest(server, "/api/targets/batch-tags", "operator", ipForm)
	if rec.Code != http.StatusOK {
		t.Fatalf("按 IP 批量状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	var ipResp struct {
		Updated     int `json:"updated"`
		MatchedByIP int `json:"matched_by_ip"`
		IPCount     int `json:"ip_count"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ipResp)
	if ipResp.MatchedByIP != 1 || ipResp.IPCount != 2 || ipResp.Updated != 1 {
		t.Fatalf("IP 映射结果异常: %+v", ipResp)
	}

	// 追加模式标签为空应拒绝
	emptyForm := url.Values{}
	emptyForm.Set("mode", "append")
	emptyForm.Set("tags", "  ")
	emptyForm.Add("target_ids", ids[0])
	if rec := scanFormRequest(server, "/api/targets/batch-tags", "operator", emptyForm); rec.Code != http.StatusBadRequest {
		t.Fatalf("追加空标签应 400，实际 %d", rec.Code)
	}

	// 审计应记录批量标签操作
	logs, _ := st.AuditLogs(20)
	found := false
	for _, entry := range logs {
		if strings.Contains(entry.Action, "批量") && strings.Contains(entry.Action, "标签") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("批量改标签未写审计: %+v", logs)
	}
}
