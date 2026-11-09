package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"easm-platform/internal/store"
)

// gateAcceptance 是启动 API 的受理响应：request_id 是后续查询的唯一凭据。
type gateAcceptance struct {
	Preparing bool   `json:"preparing"`
	TaskID    int64  `json:"task_id"`
	RequestID string `json:"request_id"`
	StatusURL string `json:"status_url"`
	Error     string `json:"error"`
	RunError  string `json:"run_error"`
}

// gateStatus 是 run-status 的响应；Done 与 Error 必须严格按 request_id 关联。
type gateStatus struct {
	RequestID string   `json:"request_id"`
	TaskID    int64    `json:"task_id"`
	Preparing bool     `json:"preparing"`
	Done      bool     `json:"done"`
	ScanID    int64    `json:"scan_id"`
	Error     string   `json:"error"`
	Advice    []string `json:"advice"`
}

func newGateTask(t *testing.T, st *store.Store, name string) int64 {
	t.Helper()
	taskID, err := st.CreateScanTask(store.ScanTask{Name: name, Mode: "top", TargetType: "all"})
	if err != nil {
		t.Fatal(err)
	}
	return taskID
}

func postRunTask(t *testing.T, server *Server, taskID int64) (*httptest.ResponseRecorder, gateAcceptance) {
	t.Helper()
	rec := scanFormRequest(server, fmt.Sprintf("/api/tasks/%d/run", taskID), "operator", url.Values{})
	var acc gateAcceptance
	if err := json.Unmarshal(rec.Body.Bytes(), &acc); err != nil {
		t.Fatalf("解析启动响应失败: %v，响应=%s", err, rec.Body.String())
	}
	return rec, acc
}

func getGateStatus(t *testing.T, server *Server, taskID int64, requestID, user string) (*httptest.ResponseRecorder, gateStatus) {
	t.Helper()
	path := fmt.Sprintf("/api/tasks/%d/run-status?request_id=%s", taskID, url.QueryEscape(requestID))
	rec := scanLiveRequest(server, http.MethodGet, path, user)
	var status gateStatus
	if body := rec.Body.String(); body != "" {
		if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
			t.Fatalf("解析 run-status 响应失败: %v，响应=%s", err, body)
		}
	}
	return rec, status
}

// waitGateDone 直接轮询内部登记表等待请求终结（不通过 HTTP 读取，便于验证“A 失败未被读取”）。
func waitGateDone(t *testing.T, server *Server, requestID string) startState {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		state, err := server.startStatusFor(requestID)
		if err == nil && state.Done {
			return state
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待启动请求 %s 完成超时（最后一次错误: %v）", requestID, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRunStatusKeepsFailedRequestAfterNextStart 验证 request_id 隔离：
// A 启动失败且未被读取，随后 B 启动成功，A 的失败原因仍可按 A 的编号完整取回；
// B 的成功也不会被 A 的失败污染。
func TestRunStatusKeepsFailedRequestAfterNextStart(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	taskID := newGateTask(t, st, "A/B 启动隔离")

	releaseA := make(chan struct{})
	server.startFn = func(id int64) (int64, error) {
		<-releaseA
		return 0, fmt.Errorf("容量预检未通过：A 请求失败（原始错误必须保留）")
	}
	recA, accA := postRunTask(t, server, taskID)
	if recA.Code != http.StatusAccepted {
		t.Fatalf("A 启动状态=%d，期望 202，响应=%s", recA.Code, recA.Body.String())
	}
	if accA.RequestID == "" || accA.StatusURL != fmt.Sprintf("/api/tasks/%d/run-status?request_id=%s", taskID, accA.RequestID) {
		t.Fatalf("A 启动响应缺少 request_id 或 status_url 不正确: %+v", accA)
	}
	// 让 A 失败，但此刻不通过 HTTP 读取它的状态。
	close(releaseA)
	stateA := waitGateDone(t, server, accA.RequestID)
	if stateA.Err == "" {
		t.Fatal("A 请求应记录失败原因")
	}

	// B 使用同一任务再次启动并成功：不得覆盖 A 的失败。
	server.startFn = func(id int64) (int64, error) { return 4242, nil }
	recB, accB := postRunTask(t, server, taskID)
	if recB.Code != http.StatusAccepted {
		t.Fatalf("B 启动状态=%d，期望 202，响应=%s", recB.Code, recB.Body.String())
	}
	if accB.RequestID == "" || accB.RequestID == accA.RequestID {
		t.Fatalf("B 必须拿到独立 request_id: A=%q B=%q", accA.RequestID, accB.RequestID)
	}
	stateB := waitGateDone(t, server, accB.RequestID)
	if stateB.Err != "" {
		t.Fatalf("B 请求应成功，实际错误: %s", stateB.Err)
	}

	// A 的失败仍可读取，且只属于 A。
	recAStatus, statusA := getGateStatus(t, server, taskID, accA.RequestID, "viewer")
	if recAStatus.Code != http.StatusOK {
		t.Fatalf("读取 A 状态=%d，期望 200，响应=%s", recAStatus.Code, recAStatus.Body.String())
	}
	if !statusA.Done || !strings.Contains(statusA.Error, "A 请求失败") || statusA.ScanID != 0 {
		t.Fatalf("B 启动后 A 的失败被覆盖或丢失: %+v", statusA)
	}
	if len(statusA.Advice) == 0 {
		t.Fatal("A 的容量类失败应保留可操作建议")
	}
	// B 的成功不被 A 的失败污染。
	_, statusB := getGateStatus(t, server, taskID, accB.RequestID, "viewer")
	if !statusB.Done || statusB.Error != "" || statusB.ScanID != 4242 {
		t.Fatalf("B 的状态不正确: %+v", statusB)
	}
}

// TestRunStatusUnknownExpiredAndMismatchedTask 验证不可知状态必须显式报错：
// 缺少 request_id → 400，未知编号 → 404，任务不匹配 → 404，TTL 过期 → 410；
// 任何情况下都不得返回 done=true 的成功语义。
func TestRunStatusUnknownExpiredAndMismatchedTask(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	taskID := newGateTask(t, st, "过期语义任务")
	otherTaskID := newGateTask(t, st, "另一个任务")

	// 缺少 request_id。
	if rec := scanLiveRequest(server, http.MethodGet, fmt.Sprintf("/api/tasks/%d/run-status", taskID), "viewer"); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺少 request_id 状态=%d，期望 400", rec.Code)
	}
	// 从未受理的编号。
	rec, status := getGateStatus(t, server, taskID, "never-issued-request", "viewer")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未知编号状态=%d，期望 404，响应=%s", rec.Code, rec.Body.String())
	}
	if status.Done || status.Preparing || status.Error == "" {
		t.Fatalf("未知编号必须返回明确错误而不是成功: %+v", status)
	}

	// 过期：把 TTL 调小，完成后再等待超过 TTL。
	server.startGate.ttl = 20 * time.Millisecond
	server.startFn = func(id int64) (int64, error) { return 77, nil }
	if rec, acc := postRunTask(t, server, taskID); rec.Code != http.StatusAccepted || acc.RequestID == "" {
		t.Fatalf("启动失败: %d %s", rec.Code, rec.Body.String())
	} else {
		// 任务不匹配：编号属于 taskID，不得通过 otherTaskID 读取。
		if recMismatch, _ := getGateStatus(t, server, otherTaskID, acc.RequestID, "viewer"); recMismatch.Code != http.StatusNotFound {
			t.Fatalf("任务不匹配状态=%d，期望 404，响应=%s", recMismatch.Code, recMismatch.Body.String())
		}
		waitGateDone(t, server, acc.RequestID)
		time.Sleep(80 * time.Millisecond)
		expiredRec, expired := getGateStatus(t, server, taskID, acc.RequestID, "viewer")
		if expiredRec.Code != http.StatusGone {
			t.Fatalf("过期编号状态=%d，期望 410，响应=%s", expiredRec.Code, expiredRec.Body.String())
		}
		if expired.Done || expired.Preparing || expired.Error == "" {
			t.Fatalf("过期编号必须返回明确错误而不是成功: %+v", expired)
		}
	}
}

// TestRunStatusCapacityEvictionBounded 验证完成态按容量有界保留：
// 超出容量后最早的完成请求被清理并明确返回 410，最新请求仍可读取。
func TestRunStatusCapacityEvictionBounded(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	taskID := newGateTask(t, st, "容量保留任务")
	server.startGate.capacity = 2

	var ids []string
	for i := 0; i < 3; i++ {
		scanID := int64(1000 + i)
		server.startFn = func(id int64) (int64, error) { return scanID, nil }
		rec, acc := postRunTask(t, server, taskID)
		if rec.Code != http.StatusAccepted || acc.RequestID == "" {
			t.Fatalf("第 %d 次启动失败: %d %s", i+1, rec.Code, rec.Body.String())
		}
		waitGateDone(t, server, acc.RequestID)
		ids = append(ids, acc.RequestID)
	}
	// 最新两条必须保留。
	for i, id := range ids[1:] {
		rec, status := getGateStatus(t, server, taskID, id, "viewer")
		if rec.Code != http.StatusOK || !status.Done || status.ScanID != int64(1001+i) {
			t.Fatalf("第 %d 条请求状态不正确: code=%d %+v", i+2, rec.Code, status)
		}
	}
	// 最早一条被容量淘汰：410 明确过期，绝不伪报成功。
	rec, status := getGateStatus(t, server, taskID, ids[0], "viewer")
	if rec.Code != http.StatusGone {
		t.Fatalf("被淘汰编号状态=%d，期望 410，响应=%s", rec.Code, rec.Body.String())
	}
	if status.Done || status.Error == "" {
		t.Fatalf("被淘汰编号必须返回明确错误: %+v", status)
	}
}

// TestConcurrentRunRequestsOnlyOneStarts 并发同一任务启动：
// 只有一次受理（202），其余全部 409；启动入口只执行一次；完成后闸门可再次受理。
func TestConcurrentRunRequestsOnlyOneStarts(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	taskID := newGateTask(t, st, "并发启动任务")
	release := make(chan struct{})
	var calls atomic.Int64
	server.startFn = func(id int64) (int64, error) {
		calls.Add(1)
		<-release
		return 555, nil
	}

	const parallel = 8
	codes := make([]int, parallel)
	bodies := make([]string, parallel)
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := scanFormRequest(server, fmt.Sprintf("/api/tasks/%d/run", taskID), "operator", url.Values{})
			codes[i] = rec.Code
			bodies[i] = rec.Body.String()
		}(i)
	}
	wg.Wait()

	acceptedCount, conflictCount := 0, 0
	acceptedID := ""
	for i, code := range codes {
		switch code {
		case http.StatusAccepted:
			acceptedCount++
			var acc gateAcceptance
			if err := json.Unmarshal([]byte(bodies[i]), &acc); err != nil {
				t.Fatalf("解析受理响应失败: %v", err)
			}
			acceptedID = acc.RequestID
		case http.StatusConflict:
			conflictCount++
			var acc gateAcceptance
			if err := json.Unmarshal([]byte(bodies[i]), &acc); err == nil && acc.RequestID != "" {
				t.Fatalf("被拒绝的请求不得返回 request_id: %s", bodies[i])
			}
		}
	}
	if acceptedCount != 1 || conflictCount != parallel-1 {
		t.Fatalf("并发结果不正确: 202=%d 409=%d 期望 1/%d", acceptedCount, conflictCount, parallel-1)
	}
	if calls.Load() != 1 {
		t.Fatalf("启动入口执行 %d 次，期望 1 次", calls.Load())
	}
	if acceptedID == "" {
		t.Fatal("受理响应缺少 request_id")
	}
	close(release)
	waitGateDone(t, server, acceptedID)

	// 上一次请求完成后，闸门必须再次可用。
	server.startFn = func(id int64) (int64, error) { return 556, nil }
	rec, acc := postRunTask(t, server, taskID)
	if rec.Code != http.StatusAccepted || acc.RequestID == "" {
		t.Fatalf("闸门未释放，后续启动状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	waitGateDone(t, server, acc.RequestID)
}

// TestBackgroundStartPanicRecovered 后台启动 panic 必须被收敛为该请求的失败，
// 并在 run-status 中可见；闸门随后仍可正常受理新请求。
func TestBackgroundStartPanicRecovered(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	taskID := newGateTask(t, st, "panic 收敛任务")
	server.startFn = func(id int64) (int64, error) { panic("naabu 自检内部崩溃") }

	rec, acc := postRunTask(t, server, taskID)
	if rec.Code != http.StatusAccepted || acc.RequestID == "" {
		t.Fatalf("启动受理失败: %d %s", rec.Code, rec.Body.String())
	}
	state := waitGateDone(t, server, acc.RequestID)
	if !strings.Contains(state.Err, "内部错误") {
		t.Fatalf("panic 未被收敛为可见错误: %q", state.Err)
	}
	statusRec, status := getGateStatus(t, server, taskID, acc.RequestID, "viewer")
	if statusRec.Code != http.StatusOK || !status.Done || !strings.Contains(status.Error, "内部错误") {
		t.Fatalf("run-status 未暴露 panic 错误: code=%d %+v", statusRec.Code, status)
	}

	// 闸门没有卡在 preparing：换正常入口可以再次启动。
	server.startFn = func(id int64) (int64, error) { return 601, nil }
	rec2, acc2 := postRunTask(t, server, taskID)
	if rec2.Code != http.StatusAccepted || acc2.RequestID == "" {
		t.Fatalf("panic 后闸门未释放: %d %s", rec2.Code, rec2.Body.String())
	}
	if state := waitGateDone(t, server, acc2.RequestID); state.Err != "" || state.ScanID != 601 {
		t.Fatalf("panic 后的新请求状态不正确: %+v", state)
	}
}
