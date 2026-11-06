package web

import (
	"net/http"
	"strings"
	"testing"

	"easm-platform/internal/store"
)

func TestKeyPagesRenderWithNewInteractions(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	if _, err := st.ImportTargets([]store.TargetSpec{{Raw: "192.0.2.20", Kind: "ip"}}, "生产", "测试"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAlert("192.0.2.20", 443, "tcp", "https", true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddWhitelist(store.WLEntry{IPSpec: "192.0.2.20", PortSpec: "443", Proto: "tcp"}); err != nil {
		t.Fatal(err)
	}

	// 关键页面（含标签筛选）均应 200
	for _, path := range []string{"/assets", "/assets?filter=tagged", "/assets?filter=untagged", "/whitelist", "/alerts", "/tasks/new"} {
		rec := scanLiveRequest(server, http.MethodGet, path, "operator")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s 状态=%d，响应片段=%.200s", path, rec.Code, rec.Body.String())
		}
	}

	// 资产页应含导入模态、批量改标签、复选框、帮助按钮与标签筛选
	body := scanLiveRequest(server, http.MethodGet, "/assets", "operator").Body.String()
	for _, want := range []string{"import-modal", "batch-tags-modal", "edit-modal", "add-modal", "help-modal", "asset-check", "已打标签", "未打标签", "导入资产", "手动添加", "维护人员", "安全设备"} {
		if !strings.Contains(body, want) {
			t.Fatalf("资产页缺少元素 %q", want)
		}
	}
	// viewer 可看资产页，但不应出现导入/批量等写操作模态
	vbody := scanLiveRequest(server, http.MethodGet, "/assets", "viewer").Body.String()
	if strings.Contains(vbody, "import-modal") || strings.Contains(vbody, "batch-tags-modal") {
		t.Fatal("viewer 资产页不应包含导入或批量改标签模态")
	}

	// 白名单页应按钮化分区
	wbody := scanLiveRequest(server, http.MethodGet, "/whitelist", "operator").Body.String()
	for _, want := range []string{"wl-add-modal", "wl-import-modal", "wl-help-modal", "生成基线"} {
		if !strings.Contains(wbody, want) {
			t.Fatalf("白名单页缺少元素 %q", want)
		}
	}

	// 告警页应含批量改关联资产标签入口
	abody := scanLiveRequest(server, http.MethodGet, "/alerts", "operator").Body.String()
	for _, want := range []string{"alert-tags-modal", "批量改资产标签", "alert-check"} {
		if !strings.Contains(abody, want) {
			t.Fatalf("告警页缺少元素 %q", want)
		}
	}

	// 任务表单页应含手工目标帮助/模板模态
	tbody := scanLiveRequest(server, http.MethodGet, "/tasks/new", "operator").Body.String()
	if !strings.Contains(tbody, "task-help-modal") {
		t.Fatal("任务表单页缺少格式帮助模态")
	}
}
