package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"easm-platform/internal/config"
	"easm-platform/internal/engine"
	"easm-platform/internal/scanner"
	"easm-platform/internal/store"
)

func newScanLiveTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, user := range []struct{ name, role string }{{"viewer", "viewer"}, {"operator", "operator"}} {
		if _, err := st.CreateUser(user.name, "test-password", user.role, ""); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AppName: "灵瞰 · 外部攻击面管理平台", NaabuPath: "naabu", NaabuRate: "1000"}
	eng := engine.New(st, cfg)
	server := New(st, cfg, scanner.New(st, cfg, eng), eng)
	for _, username := range []string{"viewer", "operator"} {
		user, err := st.UserByName(username)
		if err != nil {
			t.Fatal(err)
		}
		server.sessions["test-"+username] = session{
			userID: user.ID, username: user.Username, role: user.Role, exp: time.Now().Add(time.Hour),
		}
	}
	return server, st
}

func scanLiveRequest(server *Server, method, path, username string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "easm_sid", Value: "test-" + username})
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	return recorder
}

func TestScanLiveIncrementalResultsEventsAndRBAC(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	scanID, err := st.CreateScan(1, "实时结果执行", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartScanExecution(scanID, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertResults(scanID, []store.Result{
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Status: 1},
		{IP: "192.0.2.2", Port: 80, Proto: "tcp", Status: 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddScanEvent(scanID, "info", "pause", "首次事件"); err != nil {
		t.Fatal(err)
	}

	response := scanLiveRequest(server, http.MethodGet, fmt.Sprintf("/api/scans/%d/live", scanID), "viewer")
	if response.Code != http.StatusOK {
		t.Fatalf("只读账号读取实时接口状态=%d，响应=%s", response.Code, response.Body.String())
	}
	var live struct {
		Scan    store.Scan        `json:"scan"`
		Results []store.Result    `json:"results"`
		Events  []store.ScanEvent `json:"events"`
		Active  bool              `json:"active"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &live); err != nil {
		t.Fatal(err)
	}
	if !live.Active || len(live.Results) != 2 || len(live.Events) != 1 {
		t.Fatalf("首次实时响应不正确: %+v", live)
	}
	lastResultID := live.Results[len(live.Results)-1].ID
	lastEventID := live.Events[len(live.Events)-1].ID
	if err := st.InsertResults(scanID, []store.Result{
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Status: 1},
		{IP: "192.0.2.3", Port: 8443, Proto: "tcp", Status: 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddScanEvent(scanID, "info", "resume", "第二次事件"); err != nil {
		t.Fatal(err)
	}
	incrementalPath := fmt.Sprintf("/api/scans/%d/live?after_id=%d&event_after_id=%d", scanID, lastResultID, lastEventID)
	response = scanLiveRequest(server, http.MethodGet, incrementalPath, "viewer")
	if err := json.Unmarshal(response.Body.Bytes(), &live); err != nil {
		t.Fatal(err)
	}
	if len(live.Results) != 1 || live.Results[0].Port != 8443 || len(live.Events) != 1 || live.Events[0].Type != "resume" {
		t.Fatalf("增量响应包含重复或缺失数据: %+v", live)
	}
	lastResultID = live.Results[0].ID
	lastEventID = live.Events[0].ID
	response = scanLiveRequest(server, http.MethodGet,
		fmt.Sprintf("/api/scans/%d/live?after_id=%d&event_after_id=%d", scanID, lastResultID, lastEventID), "viewer")
	if err := json.Unmarshal(response.Body.Bytes(), &live); err != nil {
		t.Fatal(err)
	}
	if len(live.Results) != 0 || len(live.Events) != 0 {
		t.Fatalf("相同游标重复返回数据: %+v", live)
	}

	response = scanLiveRequest(server, http.MethodGet, fmt.Sprintf("/scans/%d", scanID), "viewer")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "实时结果执行") || !strings.Contains(response.Body.String(), "192.0.2.1") {
		t.Fatalf("执行详情渲染失败: 状态=%d，响应=%s", response.Code, response.Body.String())
	}
	response = scanLiveRequest(server, http.MethodPost, fmt.Sprintf("/api/scans/%d/pause", scanID), "viewer")
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer 控制接口状态=%d，期望 403", response.Code)
	}
	response = scanLiveRequest(server, http.MethodPost, fmt.Sprintf("/api/scans/%d/stop", scanID), "operator")
	if response.Code != http.StatusConflict {
		t.Fatalf("operator 控制非当前执行状态=%d，期望 409，响应=%s", response.Code, response.Body.String())
	}
	logs, err := st.AuditLogs(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Username != "operator" || logs[0].Action != "终止扫描执行" || logs[0].Target != fmt.Sprintf("#%d", scanID) {
		t.Fatalf("扫描控制审计不正确: %+v", logs)
	}
}

func TestScanStatusFiltersAndStoppedDetail(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	runningID, _ := st.CreateScan(1, "运行状态执行", "top")
	pausedID, _ := st.CreateScan(1, "暂停状态执行", "top")
	stoppedID, _ := st.CreateScan(1, "终止状态执行", "full")
	_ = runningID
	if err := st.SetScanActiveStatus(pausedID, "paused"); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScanStatus(stoppedID, "stopped", 1, "用户终止"); err != nil {
		t.Fatal(err)
	}

	response := scanLiveRequest(server, http.MethodGet, "/scans?status=paused", "viewer")
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "暂停状态执行") || strings.Contains(body, "运行状态执行") || strings.Contains(body, "终止状态执行") {
		t.Fatalf("暂停状态筛选不正确: 状态=%d，响应=%s", response.Code, body)
	}
	response = scanLiveRequest(server, http.MethodGet, "/scans?status=stopped", "viewer")
	body = response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "终止状态执行") || strings.Contains(body, "暂停状态执行") {
		t.Fatalf("终止状态筛选不正确: 状态=%d，响应=%s", response.Code, body)
	}
	response = scanLiveRequest(server, http.MethodGet, fmt.Sprintf("/scans/%d", stoppedID), "viewer")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "停止前已经发现并入库的结果") {
		t.Fatalf("终止详情说明缺失: 状态=%d，响应=%s", response.Code, response.Body.String())
	}
}
