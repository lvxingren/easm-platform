package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"easm-platform/internal/store"
)

// newAuthedGet 以指定账号会话发起 GET 请求（页面/导出类接口验证用）。
func newAuthedGet(server *Server, path, username string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: "easm_sid", Value: "test-" + username})
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	return recorder
}

// TestUnreachableAlertUIAndGuards 验证网络不可达告警的页面筛选、导出与加白防护：
// 类型筛选互相隔离、不可达告警不允许端口加白（单条/批量）、导出含原因与建议列。
func TestUnreachableAlertUIAndGuards(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)

	portID, err := st.CreateAlert("192.0.2.50", 8080, "tcp", "http", true)
	if err != nil {
		t.Fatal(err)
	}
	unreachID, err := st.CreateUnreachableAlert("bad.example.com", store.ReasonDNSFailure, true)
	if err != nil {
		t.Fatal(err)
	}

	// 类型筛选：unreachable 页只出现不可达目标，port 页只出现端口告警。
	req := newAuthedGet(server, "/alerts?kind=unreachable", "admin")
	if body := req.Body.String(); !strings.Contains(body, "bad.example.com") || strings.Contains(body, "192.0.2.50:8080") {
		snippet := body
		if len(snippet) > 400 {
			snippet = snippet[:400]
		}
		t.Fatalf("unreachable 筛选隔离失败: %s", snippet)
	}
	req = newAuthedGet(server, "/alerts?kind=port", "admin")
	if body := req.Body.String(); !strings.Contains(body, "192.0.2.50:8080") || strings.Contains(body, "bad.example.com") {
		t.Fatalf("port 筛选隔离失败")
	}
	// 不可达行不应渲染加白按钮（处置按钮保留）。
	req = newAuthedGet(server, "/alerts?kind=unreachable", "admin")
	if strings.Contains(req.Body.String(), "alertWhitelist(this)") {
		t.Fatalf("不可达告警行不应出现加白按钮")
	}

	// 单条加白 API：不可达告警拒绝（400），端口告警正常。
	if rec := scanFormRequest(server, "/api/alerts/"+strconv.FormatInt(unreachID, 10)+"/whitelist", "admin", url.Values{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("不可达加白应 400，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if rec := scanFormRequest(server, "/api/alerts/"+strconv.FormatInt(portID, 10)+"/whitelist", "admin", url.Values{}); rec.Code != http.StatusOK {
		t.Fatalf("端口告警加白应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}

	// 批量加白：不可达条目被跳过，不计入加白数。
	unreachID2, _ := st.CreateUnreachableAlert("down.example.com", store.ReasonConnTimeout, true)
	form := idsForm("whitelist", []string{strconv.FormatInt(unreachID2, 10)})
	rec := scanFormRequest(server, "/api/alerts/batch", "admin", form)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"whitelisted":0`) {
		t.Fatalf("批量加白应跳过不可达条目: %d %s", rec.Code, rec.Body.String())
	}
	if a, _ := st.AlertByID(unreachID2); a.Status != "new" {
		t.Fatalf("不可达告警不应被批量加白改为 ignored: %s", a.Status)
	}

	// 导出：含类型/失败原因/排查建议列，且支持 kind 过滤。
	req = newAuthedGet(server, "/alerts/export?kind=unreachable", "admin")
	body := req.Body.String()
	for _, want := range []string{"类型", "失败原因", "排查建议", "网络不可达", "bad.example.com", store.ReasonDNSFailure} {
		if !strings.Contains(body, want) {
			t.Fatalf("导出缺少 %q", want)
		}
	}
	if strings.Contains(body, "192.0.2.50") {
		t.Fatalf("kind=unreachable 导出混入端口告警")
	}
}

// TestImportAssetsDedupEcho 验证导入接口回显「新增/跳过重复/非法示例」，
// 等价 CIDR 与大小写域名在批内与库内都被合并。
func TestImportAssetsDedupEcho(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)

	form := url.Values{}
	form.Set("ips", "10.7.0.1\n10.7.0.0/24\n10.7.0.9/24\nDEMO.example.com\ndemo.example.com.\nnot-a-valid-target!!")
	rec := scanFormRequest(server, "/api/assets/import", "admin", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("导入状态=%d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// 合法 3 条（IP/CIDR/域名）全部新增；等价 CIDR 与尾点域名批内重复 2 条计入跳过；非法 1 条。
	for _, want := range []string{`"added":3`, `"skipped":2`, `"invalid":1`, "invalid_sample"} {
		if !strings.Contains(body, want) {
			t.Fatalf("导入回显缺少 %s: %s", want, body)
		}
	}
	// 二次导入同样内容：全部跳过，新增 0。
	rec = scanFormRequest(server, "/api/assets/import", "admin", form)
	if !strings.Contains(rec.Body.String(), `"added":0`) {
		t.Fatalf("二次导入应新增 0: %s", rec.Body.String())
	}
	tgts, _ := st.Targets()
	if len(tgts) != 3 {
		t.Fatalf("台账应只有 3 条（等价 CIDR/域名已合并），实际 %d", len(tgts))
	}
}
