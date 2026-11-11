package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestSettingsPanelsAndSectionHeading 校验设置页拆分为独立面板 + 分类标签页，
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

// TestSettingsTabsDefaultNetworkAndSidebarGroup 校验：系统管理侧栏与安全运营一样可折叠；
// 设置页顶部胶囊为标签页，默认只显示网络监听，其余面板隐藏，点击对应分类才显示。
func TestSettingsTabsDefaultNetworkAndSidebarGroup(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)

	body := scanLiveRequest(server, http.MethodGet, "/settings", "admin").Body.String()
	if !strings.Contains(body, `id="sec-admin"`) || !strings.Contains(body, `toggleNavGroup('sec-admin')`) {
		t.Fatal("系统管理应按安全运营模式提供可折叠分组")
	}
	if !strings.Contains(body, `class="panel settings-panel" id="set-network" role="tabpanel">`) {
		t.Fatal("网络监听面板应默认可见")
	}
	for _, id := range []string{"set-cert", "set-notify", "set-naabu", "set-fscan", "set-ai", "set-help"} {
		if !strings.Contains(body, `id="`+id+`" role="tabpanel" hidden>`) {
			t.Fatalf("%s 面板默认应折叠隐藏", id)
		}
	}
	if !strings.Contains(body, `data-settings-tab="set-network"`) || !strings.Contains(body, "function showSettingsPanel(") {
		t.Fatal("设置页顶部分类应改为标签页切换")
	}

	// 非管理员不应看到系统管理分组
	opBody := scanLiveRequest(server, http.MethodGet, "/exposure", "operator").Body.String()
	if strings.Contains(opBody, `id="sec-admin"`) {
		t.Fatal("非管理员侧栏不应出现系统管理分组")
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

// TestSettingsFeishuSecretNotEchoedAndBlankKeeps 校验加签密钥与 AI Token 一致：
// 页面不回显明文（不渲染 value），留空提交视为不修改，避免误清空。
func TestSettingsFeishuSecretNotEchoedAndBlankKeeps(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)

	form := url.Values{}
	form.Set("feishu_webhook", "https://open.feishu.cn/open-apis/bot/v2/hook/abc")
	form.Set("feishu_secret", "s3cr3t-signing-key")
	if rec := scanFormRequest(server, "/api/settings", "admin", form); rec.Code != http.StatusOK {
		t.Fatalf("保存通知配置状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	if got := st.Setting("feishu_secret"); got != "s3cr3t-signing-key" {
		t.Fatalf("feishu_secret 未保存: %q", got)
	}

	body := scanLiveRequest(server, http.MethodGet, "/settings", "admin").Body.String()
	if strings.Contains(body, "s3cr3t-signing-key") {
		t.Fatal("设置页不得回显加签密钥明文")
	}
	if !strings.Contains(body, `type="password" name="feishu_secret"`) || !strings.Contains(body, "已配置，留空则不修改") {
		t.Fatal("加签密钥输入框应隐藏明文并提示已配置")
	}

	// 表单每次提交都会带上空的 feishu_secret 输入框，留空必须保持原值。
	blank := url.Values{}
	blank.Set("feishu_webhook", "https://open.feishu.cn/open-apis/bot/v2/hook/abc")
	blank.Set("feishu_secret", "")
	if rec := scanFormRequest(server, "/api/settings", "admin", blank); rec.Code != http.StatusOK {
		t.Fatalf("留空保存状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	if got := st.Setting("feishu_secret"); got != "s3cr3t-signing-key" {
		t.Fatalf("留空提交清空了已存密钥: %q", got)
	}

	// 填写新值仍可正常轮换。
	rotate := url.Values{}
	rotate.Set("feishu_webhook", "https://open.feishu.cn/open-apis/bot/v2/hook/abc")
	rotate.Set("feishu_secret", "rotated-key")
	if rec := scanFormRequest(server, "/api/settings", "admin", rotate); rec.Code != http.StatusOK {
		t.Fatalf("轮换密钥状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	if got := st.Setting("feishu_secret"); got != "rotated-key" {
		t.Fatalf("密钥轮换失败: %q", got)
	}
}

// TestSettingsSaveLogAndFscanCategories 回归：日志级别与 fscan/域名两类各自独立提交时必须能命中
// 处理分支并保存，不得返回「没有可保存的配置项」（仅提交 log_level / fscan_* 字段）。
func TestSettingsSaveLogAndFscanCategories(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)

	// 日志类：只提交 log_level
	logForm := url.Values{}
	logForm.Set("log_level", "warn")
	if rec := scanFormRequest(server, "/api/settings", "admin", logForm); rec.Code != http.StatusOK {
		t.Fatalf("保存日志级别状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	if got := st.Setting("log_level"); got != "warn" {
		t.Fatalf("log_level 未保存: %q", got)
	}

	// fscan/域名类：只提交 fscan_* 字段
	fscanForm := url.Values{}
	fscanForm.Set("fscan_path", "/usr/local/bin/fscan")
	fscanForm.Set("fscan_workers", "120")
	fscanForm.Set("fscan_mode", "port")
	if rec := scanFormRequest(server, "/api/settings", "admin", fscanForm); rec.Code != http.StatusOK {
		t.Fatalf("保存 fscan 配置状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	if got := st.Setting("fscan_mode"); got != "port" {
		t.Fatalf("fscan_mode 未保存: %q", got)
	}
	if got := st.Setting("fscan_workers"); got != "120" {
		t.Fatalf("fscan_workers 未保存: %q", got)
	}

	// 日志级别非法值应拒绝且不写入
	badForm := url.Values{}
	badForm.Set("log_level", "verbose")
	if rec := scanFormRequest(server, "/api/settings", "admin", badForm); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法日志级别应 400，实际 %d", rec.Code)
	}
	if got := st.Setting("log_level"); got != "warn" {
		t.Fatalf("非法提交不应覆盖已存 log_level，当前 %q", got)
	}
}

// TestSettingsSaveUnknownFieldsEchoedInError 验证无任何已知字段时，400 响应回显收到的字段名，
// 便于区分「客户端发了未知/空表单」与「服务端版本过旧」两类成因。
func TestSettingsSaveUnknownFieldsEchoedInError(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)
	form := url.Values{}
	form.Set("future_setting", "x")
	rec := scanFormRequest(server, "/api/settings", "admin", form)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知字段应 400，实际 %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "future_setting") {
		t.Fatalf("400 响应应回显收到的未知字段名，实际: %s", body)
	}
}

// scanMultipartFormRequest 模拟浏览器真实行为：fetch(url, {body: new FormData(form)}) 发出的是
// multipart/form-data 而非 urlencoded。历史 bug：apiSaveSettings 用 r.ParseForm() 只解析
// urlencoded 进 PostForm，multipart 下所有 has() 全 false，保存任何分类都报「没有可保存的配置项」。
// 既有测试辅助 scanFormRequest 硬编码 urlencoded，正是这个盲区掩盖了该 bug。
func scanMultipartFormRequest(t *testing.T, server *Server, path, username string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, vals := range form {
		for _, v := range vals {
			if err := writer.WriteField(key, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "easm_sid", Value: "test-" + username})
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	return recorder
}

// TestSettingsSaveMultipartForm 回归：前端各设置表单经 FormData 提交（multipart/form-data），
// 每个分类都必须命中处理分支并保存成功，不得再出现「没有可保存的配置项」。
func TestSettingsSaveMultipartForm(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)

	cases := []struct {
		name string
		form url.Values
		key  string
		want string
	}{
		{"日志级别", url.Values{"log_level": {"error"}}, "log_level", "error"},
		{"通知", url.Values{"feishu_webhook": {"https://open.feishu.cn/open-apis/bot/v2/hook/mp"}, "realert_days": {"7"}}, "realert_days", "7"},
		{"naabu", url.Values{"naabu_path": {"/usr/bin/naabu"}, "naabu_rate": {"3000"}, "naabu_retries": {"2"}, "naabu_workers": {"100"}, "naabu_timeout": {"1s"}, "scan_timeout_min": {"0"}, "scan_concurrency": {"6"}, "naabu_scan_type": {"c"}}, "naabu_rate", "3000"},
		{"fscan", url.Values{"fscan_path": {"/usr/bin/fscan"}, "fscan_mode": {"mixed"}}, "fscan_mode", "mixed"},
		{"AI", url.Values{"ai_endpoint": {"https://api.example.com/v1"}, "ai_model": {"qwen-plus"}}, "ai_model", "qwen-plus"},
		{"自动拆分", url.Values{"auto_split_on_timeout": {"on"}, "split_batch_size": {"80"}}, "split_batch_size", "80"},
	}
	for _, c := range cases {
		rec := scanMultipartFormRequest(t, server, "/api/settings", "admin", c.form)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s 分类 multipart 保存应 200，实际 %d 响应 %s", c.name, rec.Code, rec.Body.String())
		}
		if got := st.Setting(c.key); got != c.want {
			t.Fatalf("%s 分类保存后 %s 期望 %q 实际 %q", c.name, c.key, c.want, got)
		}
	}
}
