package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestSettingsPanelsAndSectionHeading 校验设置页拆分为独立面板 + 分类跳转，
// 以及顶栏「领域 eyebrow + 模块大标题」两级层级。
func TestSettingsPanelsAndSectionHeading(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)

	// viewer 不能访问设置页
	if rec := scanLiveRequest(server, http.MethodGet, "/settings", "viewer"); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 访问设置页状态=%d，期望 403", rec.Code)
	}

	// 设置页（admin）应含各独立面板锚点与分类跳转
	body := scanLiveRequest(server, http.MethodGet, "/settings", "admin").Body.String()
	for _, want := range []string{
		`id="set-network"`, `id="set-cert"`, `id="set-notify"`, `id="set-naabu"`, `id="set-ai"`, `id="set-help"`,
		`class="subnav"`, "通知与告警", "naabu 扫描参数", "AI 分析", `name="scan_concurrency"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("设置页缺少元素 %q", want)
		}
	}

	// 顶栏领域 eyebrow：资产→资产、告警→风险、白名单→防护、设置→系统管理
	cases := map[string]string{
		"/assets":    "资产",
		"/alerts":    "风险",
		"/whitelist": "防护",
		"/tasks":     "扫描",
	}
	for path, section := range cases {
		b := scanLiveRequest(server, http.MethodGet, path, "operator").Body.String()
		if !strings.Contains(b, `class="page-eyebrow">`+section+"<") {
			t.Fatalf("%s 顶栏缺少领域 eyebrow %q", path, section)
		}
	}
	sb := scanLiveRequest(server, http.MethodGet, "/settings", "admin").Body.String()
	if !strings.Contains(sb, `class="page-eyebrow">系统管理<`) {
		t.Fatal("设置页顶栏缺少「系统管理」eyebrow")
	}
}

// TestSettingsPartialSavePreservesOtherCategories 校验按类别部分保存：
// 提交某一类字段只更新该类，其余类别保持原值不被清空。
func TestSettingsPartialSavePreservesOtherCategories(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)

	// ① 保存 naabu 类
	naabuForm := url.Values{}
	naabuForm.Set("naabu_path", "/usr/local/bin/naabu")
	naabuForm.Set("naabu_rate", "1500")
	naabuForm.Set("naabu_retries", "2")
	naabuForm.Set("naabu_workers", "25")
	naabuForm.Set("naabu_timeout", "1s")
	naabuForm.Set("scan_timeout_min", "60")
	naabuForm.Set("naabu_scan_type", "c")
	naabuForm.Set("scan_concurrency", "5")
	if rec := scanFormRequest(server, "/api/settings", "admin", naabuForm); rec.Code != http.StatusOK {
		t.Fatalf("保存 naabu 配置状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	if got := st.Setting("naabu_rate"); got != "1500" {
		t.Fatalf("naabu_rate 未保存: %q", got)
	}
	if got := st.Setting("scan_concurrency"); got != "5" {
		t.Fatalf("scan_concurrency 未保存: %q", got)
	}

	// ② 只保存通知类，naabu 应保持不变
	notifyForm := url.Values{}
	notifyForm.Set("feishu_webhook", "https://open.feishu.cn/open-apis/bot/v2/hook/abc")
	notifyForm.Set("feishu_secret", "sec")
	notifyForm.Set("realert_days", "10")
	if rec := scanFormRequest(server, "/api/settings", "admin", notifyForm); rec.Code != http.StatusOK {
		t.Fatalf("保存通知配置状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	if got := st.Setting("naabu_rate"); got != "1500" {
		t.Fatalf("通知保存后 naabu_rate 被覆盖: %q", got)
	}
	if got := st.Setting("realert_days"); got != "10" {
		t.Fatalf("realert_days 未保存: %q", got)
	}
	if st.Setting("feishu_webhook") == "" {
		t.Fatal("feishu_webhook 未保存")
	}

	// ③ 只保存 AI 类，naabu 与通知均应保持不变
	aiForm := url.Values{}
	aiForm.Set("ai_endpoint", "https://api.example.com/v1")
	aiForm.Set("ai_model", "gpt-4o-mini")
	aiForm.Set("ai_timeout_sec", "60")
	aiForm.Set("ai_temperature", "0.2")
	if rec := scanFormRequest(server, "/api/settings", "admin", aiForm); rec.Code != http.StatusOK {
		t.Fatalf("保存 AI 配置状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	if got := st.Setting("naabu_rate"); got != "1500" {
		t.Fatalf("AI 保存后 naabu_rate 被覆盖: %q", got)
	}
	if got := st.Setting("realert_days"); got != "10" {
		t.Fatalf("AI 保存后 realert_days 被覆盖: %q", got)
	}
	if got := st.Setting("ai_model"); got != "gpt-4o-mini" {
		t.Fatalf("ai_model 未保存: %q", got)
	}

	// ④ 空提交应拒绝
	if rec := scanFormRequest(server, "/api/settings", "admin", url.Values{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("空提交应 400，实际 %d", rec.Code)
	}

	// ⑤ 审计应记录设置变更
	logs, _ := st.AuditLogs(30)
	found := false
	for _, entry := range logs {
		if strings.Contains(entry.Action, "修改系统设置") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("设置变更未写审计")
	}
}
