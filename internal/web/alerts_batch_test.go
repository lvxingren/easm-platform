package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"easm-platform/internal/store"
)

func scanFormRequest(server *Server, path, username string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "easm_sid", Value: "test-" + username})
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	return recorder
}

func addTestAdmin(t *testing.T, server *Server, st *store.Store) {
	t.Helper()
	id, err := st.CreateUser("admin", "test-password", "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	server.sessions["test-admin"] = session{userID: id, username: "admin", role: "admin", exp: time.Now().Add(time.Hour)}
}

func idsForm(action string, ids []string) url.Values {
	form := url.Values{}
	form.Set("action", action)
	for _, id := range ids {
		form.Add("ids", id)
	}
	return form
}

func TestBatchAlertHandlingAndRBAC(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)
	ids := make([]string, 0, 3)
	for i, ip := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		id, err := st.CreateAlert(ip, 443+i, "tcp", "https", true)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, strconv.FormatInt(id, 10))
	}

	if rec := scanFormRequest(server, "/api/alerts/batch", "viewer", idsForm("acked", ids)); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 批量处置状态=%d，期望 403", rec.Code)
	}
	if rec := scanFormRequest(server, "/api/alerts/batch", "operator", idsForm("acked", ids)); rec.Code != http.StatusOK {
		t.Fatalf("operator 批量处置状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	if acked, _ := st.AlertsFiltered("acked", "", 0); len(acked) != 3 {
		t.Fatalf("批量跟进中未生效: %d 条", len(acked))
	}
	if rec := scanFormRequest(server, "/api/alerts/batch", "operator", idsForm("resolved", ids)); rec.Code != http.StatusBadRequest {
		t.Fatalf("批量解决缺说明状态=%d，期望 400", rec.Code)
	}
	if rec := scanFormRequest(server, "/api/alerts/batch", "operator", idsForm("whitelist", ids)); rec.Code != http.StatusOK {
		t.Fatalf("批量加白状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	if wl, _ := st.Whitelist(); len(wl) != 3 {
		t.Fatalf("批量加白未写入白名单: %d 条", len(wl))
	}
	if ignored, _ := st.AlertsFiltered("ignored", "", 0); len(ignored) != 3 {
		t.Fatalf("批量加白后未忽略告警: %d 条", len(ignored))
	}
	logs, _ := st.AuditLogs(20)
	foundBatch := false
	for _, entry := range logs {
		if strings.Contains(entry.Action, "批量") {
			foundBatch = true
			break
		}
	}
	if !foundBatch {
		t.Fatalf("批量处置未写审计: %+v", logs)
	}
}

func TestLogsPageAdminOnly(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)
	_ = st
	if rec := scanLiveRequest(server, http.MethodGet, "/logs", "viewer"); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 访问日志页状态=%d，期望 403", rec.Code)
	}
	if rec := scanLiveRequest(server, http.MethodGet, "/logs", "operator"); rec.Code != http.StatusForbidden {
		t.Fatalf("operator 访问日志页状态=%d，期望 403", rec.Code)
	}
	rec := scanLiveRequest(server, http.MethodGet, "/logs", "admin")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "运行日志") {
		t.Fatalf("admin 日志页渲染失败: 状态=%d", rec.Code)
	}
	apiRec := scanLiveRequest(server, http.MethodGet, "/api/logs?level=error", "admin")
	if apiRec.Code != http.StatusOK {
		t.Fatalf("admin 日志接口状态=%d", apiRec.Code)
	}
	var payload struct {
		Entries []map[string]interface{} `json:"entries"`
	}
	if err := json.Unmarshal(apiRec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Entries == nil {
		t.Fatal("日志接口应返回 entries 数组")
	}
	if rec := scanLiveRequest(server, http.MethodGet, "/api/logs", "viewer"); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 访问日志接口状态=%d，期望 403", rec.Code)
	}
}
