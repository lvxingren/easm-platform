package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// multipartFormRequest 模拟浏览器 fetch(new FormData(...)) 的提交方式：
// 与 scanFormRequest 的 urlencoded 请求不同，这里使用 multipart/form-data，
// 用于回归「后端只调 ParseForm 导致并列数组字段读不到」这一类问题。
func multipartFormRequest(t *testing.T, server *Server, path, username string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for key, values := range form {
		for _, value := range values {
			if err := w.WriteField(key, value); err != nil {
				t.Fatalf("写入 multipart 字段 %s 失败: %v", key, err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("关闭 multipart 写入器失败: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "easm_sid", Value: "test-" + username})
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	return recorder
}

// TestExposureWhitelistAcceptsMultipartForm 回归：资产暴露面页面的加白弹窗用 FormData 提交，
// 后端曾用 r.ParseForm() 解析（只解析 urlencoded），导致 ip[] 等并列数组为空并报
// 「未选择任何暴露面条目」。必须兼容 multipart 并按行写入白名单。
func TestExposureWhitelistAcceptsMultipartForm(t *testing.T) {
	server, st := newScanLiveTestServer(t)

	form := url.Values{}
	form.Add("ip", "192.0.2.10")
	form.Add("port", "443")
	form.Add("proto", "tcp")
	form.Add("service", "HTTPS")
	form.Add("reason", "业务官方服务")
	form.Set("remark", "工单 #1")

	rec := multipartFormRequest(t, server, "/api/exposure/whitelist", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("multipart 批量加白应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Added   int `json:"added"`
		Skipped int `json:"skipped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应解析失败: %v body=%s", err, rec.Body.String())
	}
	if out.Added != 1 || out.Skipped != 0 {
		t.Fatalf("批量加白结果错误: %+v", out)
	}
	entries := mustWhitelist(t, st)
	if len(entries) != 1 {
		t.Fatalf("应写入 1 条白名单，实际 %d", len(entries))
	}
	got := entries[0]
	if got.IPSpec != "192.0.2.10" || got.PortSpec != "443" || got.Proto != "tcp" || got.Service != "HTTPS" ||
		got.Reason != "业务官方服务" || got.Remark != "工单 #1" || got.Owner != "operator" {
		t.Fatalf("白名单字段未按提交写入: %+v", got)
	}
}

// TestBatchAPIsAcceptMultipartForm 覆盖同一类回归：以下接口都由页面用 FormData 提交并列数组，
// 只有兼容 multipart 才能读到 ip[]/ids[]/target_ids[] 等字段，而不是返回「未选择…」。
func TestBatchAPIsAcceptMultipartForm(t *testing.T) {
	cases := []struct {
		name string
		path string
		form url.Values
	}{
		{
			name: "暴露面批量加白",
			path: "/api/exposure/whitelist",
			form: url.Values{"ip": {"192.0.2.11"}, "port": {"80"}, "proto": {"tcp"}, "reason": {"已确认合规"}},
		},
		{
			name: "基线批量应用",
			path: "/api/baseline/apply",
			form: url.Values{"ip": {"192.0.2.12"}, "port": {"22"}, "proto": {"tcp"}, "business": {"办公网"}},
		},
		{
			name: "白名单导入确认",
			path: "/api/whitelist/import/apply",
			form: url.Values{"ip": {"192.0.2.13"}, "port": {"443"}, "proto": {"tcp"}, "source": {"manual"}},
		},
		{
			name: "批量修改资产标签",
			path: "/api/targets/batch-tags",
			form: url.Values{"target_ids": {"1"}, "tags": {"生产"}, "mode": {"append"}},
		},
		{
			name: "批量删除资产",
			path: "/api/targets/batch-delete",
			form: url.Values{"ids": {"1"}},
		},
		{
			name: "批量处置告警",
			path: "/api/alerts/batch",
			form: url.Values{"ids": {"1"}, "action": {"acked"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newScanLiveTestServer(t)
			rec := multipartFormRequest(t, server, tc.path, "operator", tc.form)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s 的 multipart 提交应 200，实际 %d: %s", tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}
