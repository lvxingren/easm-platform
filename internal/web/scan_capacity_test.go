package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"easm-platform/internal/store"
)

// livePayload 是 /api/scans/{id}/live 的响应结构（容量化后的稳定字段）。
type livePayload struct {
	Scan            store.Scan        `json:"scan"`
	Results         []store.Result    `json:"results"`
	Events          []store.ScanEvent `json:"events"`
	Active          bool              `json:"active"`
	Terminal        bool              `json:"terminal"`
	HasMore         bool              `json:"has_more"`
	NextCursor      int64             `json:"next_cursor"`
	ResultCount     int               `json:"result_count"`
	Limit           int               `json:"limit"`
	CapacityBlocked bool              `json:"capacity_blocked"`
	CapacityAdvice  []string          `json:"capacity_advice"`
}

func readScanLive(t *testing.T, server *Server, scanID, afterID int64, limit int) livePayload {
	t.Helper()
	path := fmt.Sprintf("/api/scans/%d/live?after_id=%d", scanID, afterID)
	if limit > 0 {
		path += "&limit=" + strconv.Itoa(limit)
	}
	rec := scanLiveRequest(server, http.MethodGet, path, "viewer")
	if rec.Code != http.StatusOK {
		t.Fatalf("live 接口状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	var payload livePayload
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析 live 响应失败: %v", err)
	}
	return payload
}

func readEmbeddedAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := assets.ReadFile(name)
	if err != nil {
		t.Fatalf("读取内置资源 %s 失败: %v", name, err)
	}
	return string(b)
}

func insertSequentialResults(t *testing.T, st *store.Store, scanID int64, count int) {
	t.Helper()
	rows := make([]store.Result, 0, count)
	for i := 0; i < count; i++ {
		rows = append(rows, store.Result{IP: "198.51.100.10", Port: i%65535 + 1, Proto: "tcp", Status: 1})
	}
	stats, err := st.InsertResultsBatch(scanID, rows)
	if err != nil {
		t.Fatalf("写入结果失败: %v", err)
	}
	if stats.Inserted != count {
		t.Fatalf("写入结果数=%d，期望 %d", stats.Inserted, count)
	}
}

// TestScanDetailFirstRenderBounded 首屏只渲染固定硬上限一页：
// records 50 万行量级的执行（result_count=500000）时，HTML 里也只有 200 行，
// 其余交给页面内的游标续拉，绝不 ResultsByScan 全量装载。
func TestScanDetailFirstRenderBounded(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	scanID, err := st.CreateScan(1, "五十万行等价执行", "full")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartScanExecution(scanID, 500000, 25000); err != nil {
		t.Fatal(err)
	}
	// 只落一页多 60 行真实数据，用 result_count 表达 50 万行的总量；
	// 若详情页仍全量装载，HTML 中就会出现超过硬上限的行。
	insertSequentialResults(t, st, scanID, scanDetailInitialResults+60)
	if err := st.ApplyScanProgress(scanID, store.ScanProgress{Processed: 500000, OpenPorts: 500000, Results: 500000}); err != nil {
		t.Fatal(err)
	}
	page, err := st.ResultsPage(scanID, 0, scanDetailInitialResults)
	if err != nil {
		t.Fatal(err)
	}
	if !page.HasMore {
		t.Fatal("测试前置条件不成立：结果应多于首屏硬上限")
	}

	rec := scanLiveRequest(server, http.MethodGet, fmt.Sprintf("/scans/%d", scanID), "viewer")
	if rec.Code != http.StatusOK {
		t.Fatalf("执行详情状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if rows := strings.Count(body, "data-result-id=\""); rows != scanDetailInitialResults {
		t.Fatalf("首屏渲染行数=%d，期望硬上限 %d（不得全量装载）", rows, scanDetailInitialResults)
	}
	if !strings.Contains(body, `data-cursor="`+strconv.FormatInt(page.NextCursor, 10)+`"`) {
		t.Fatalf("首屏缺少游标 data-cursor=%d", page.NextCursor)
	}
	if !strings.Contains(body, `data-has-more="1"`) {
		t.Fatal("首屏应标记 has-more=1，供前端继续按游标拉取")
	}
	if !strings.Contains(body, ">500000<") {
		t.Fatal("首屏应展示 result_count 总量 500000")
	}
	// 第 200 行在页内，第 201 行（被截断的部分）不得出现。
	lastID := page.Results[len(page.Results)-1].ID
	nextPage, err := st.ResultsPage(scanID, page.NextCursor, 1)
	if err != nil || len(nextPage.Results) == 0 {
		t.Fatalf("读取下一页失败: %v", err)
	}
	if !strings.Contains(body, `data-result-id="`+strconv.FormatInt(lastID, 10)+`"`) {
		t.Fatalf("首屏应包含第 %d 行（id=%d）", scanDetailInitialResults, lastID)
	}
	if strings.Contains(body, `data-result-id="`+strconv.FormatInt(nextPage.Results[0].ID, 10)+`"`) {
		t.Fatalf("首屏不应包含超出硬上限的第 %d 行（id=%d）", scanDetailInitialResults+1, nextPage.Results[0].ID)
	}
}

// TestScanLiveDrainsAfterTerminalWithoutLossOrDuplicate 终态后前端继续按游标拉取，
// 直到排空；全程稳定游标、无遗漏、无重复。
func TestScanLiveDrainsAfterTerminalWithoutLossOrDuplicate(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	scanID, err := st.CreateScan(1, "终态排空执行", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartScanExecution(scanID, 20, 1); err != nil {
		t.Fatal(err)
	}
	const totalRows = 1234
	insertSequentialResults(t, st, scanID, totalRows)
	// 先进入终态：live API 仍必须继续返回未拉取的行，不能因状态完成提前停止。
	if err := st.FinishScanStatus(scanID, "done", totalRows, ""); err != nil {
		t.Fatal(err)
	}

	cursor := int64(0)
	pages := 0
	seen := make(map[int64]bool, totalRows)
	var ordered []int64
	for {
		payload := readScanLive(t, server, scanID, cursor, 200)
		if !payload.Terminal {
			t.Fatalf("终态执行应返回 terminal=true: %+v", payload.Scan.Status)
		}
		if payload.ResultCount != totalRows {
			t.Fatalf("result_count=%d，期望 %d", payload.ResultCount, totalRows)
		}
		if payload.Limit != 200 {
			t.Fatalf("limit=%d，期望回显 200", payload.Limit)
		}
		for _, item := range payload.Results {
			if seen[item.ID] {
				t.Fatalf("游标分页出现重复行 id=%d", item.ID)
			}
			seen[item.ID] = true
			ordered = append(ordered, item.ID)
		}
		if len(payload.Results) > 0 && payload.NextCursor <= cursor {
			t.Fatalf("游标未推进：after=%d next=%d", cursor, payload.NextCursor)
		}
		cursor = payload.NextCursor
		pages++
		if pages > 100 {
			t.Fatal("终态排空页数异常，游标可能未推进")
		}
		if !payload.HasMore {
			break
		}
	}
	if len(ordered) != totalRows {
		t.Fatalf("终态排空后共取到 %d 行，期望 %d 行（不得因状态完成提前停止）", len(ordered), totalRows)
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i] <= ordered[i-1] {
			t.Fatalf("游标顺序非严格递增：%d <= %d", ordered[i], ordered[i-1])
		}
	}
	payload := readScanLive(t, server, scanID, cursor, 200)
	if len(payload.Results) != 0 || payload.HasMore {
		t.Fatalf("排空后重复请求仍返回数据: rows=%d has_more=%v", len(payload.Results), payload.HasMore)
	}
	// limit 超上限按 store 硬上限截断，避免单次响应无界放大。
	clamped := readScanLive(t, server, scanID, 0, store.ResultPageMaxLimit+5000)
	if clamped.Limit != store.ResultPageMaxLimit {
		t.Fatalf("limit 截断=%d，期望 %d", clamped.Limit, store.ResultPageMaxLimit)
	}
}

// TestScanProgressAndResultCountNeverRegress 旧进度快照写入后，API 返回的
// processed/failed/open_ports/result_count 不得回退（存储侧单调合并 + API 兜底）。
func TestScanProgressAndResultCountNeverRegress(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	scanID, err := st.CreateScan(1, "单调进度执行", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartScanExecution(scanID, 100, 5); err != nil {
		t.Fatal(err)
	}
	insertSequentialResults(t, st, scanID, 30)
	if err := st.ApplyScanProgress(scanID, store.ScanProgress{Processed: 80, Failed: 3, OpenPorts: 900, Results: 900}); err != nil {
		t.Fatal(err)
	}
	before := readScanLive(t, server, scanID, 0, 500)
	if before.Scan.ProcessedTargets != 80 || before.Scan.OpenPorts != 900 || before.ResultCount != 900 {
		t.Fatalf("前置进度快照不正确: %+v", before.Scan)
	}
	// 模拟迟到的旧快照：所有计数更小，存储层与 API 都不得回退。
	if err := st.ApplyScanProgress(scanID, store.ScanProgress{Processed: 10, Failed: 0, OpenPorts: 5, Results: 5}); err != nil {
		t.Fatal(err)
	}
	after := readScanLive(t, server, scanID, 0, 500)
	if after.Scan.ProcessedTargets < before.Scan.ProcessedTargets {
		t.Fatalf("processed_targets 回退: %d -> %d", before.Scan.ProcessedTargets, after.Scan.ProcessedTargets)
	}
	if after.Scan.FailedTargets < before.Scan.FailedTargets {
		t.Fatalf("failed_targets 回退: %d -> %d", before.Scan.FailedTargets, after.Scan.FailedTargets)
	}
	if after.Scan.OpenPorts < before.Scan.OpenPorts {
		t.Fatalf("open_ports 回退: %d -> %d", before.Scan.OpenPorts, after.Scan.OpenPorts)
	}
	if after.ResultCount < before.ResultCount {
		t.Fatalf("result_count 回退: %d -> %d", before.ResultCount, after.ResultCount)
	}
}

// TestScanDetailTemplateCursorDrainAndDomCap 用模板/静态资源断言锁定前端契约：
// 游标续拉、DOM 硬上限回收、单调合并、已加载/总数展示。
func TestScanDetailTemplateCursorDrainAndDomCap(t *testing.T) {
	tpl := readEmbeddedAsset(t, "templates/scan_detail.html")
	for _, want := range []string{
		`data-cursor="{{.NextCursor}}"`,
		`data-has-more=`,
		`id="result-loaded"`,
		`id="result-total"`,
		`RESULT_DOM_LIMIT = 400`,
		`RESULT_PAGE_LIMIT = 500`,
		`const scan = mergeScan(raw || {});`,
		`monoMax(progressFloor[key], scan[key])`,
		`if (terminal && !hasMoreResults)`,
		`body.removeChild(body.firstElementChild)`,
	} {
		if !strings.Contains(tpl, want) {
			t.Fatalf("scan_detail.html 缺少关键实现：%s", want)
		}
	}
	// 旧节点回收不得触碰游标：否则被回收的行会被再次拉取或漏拉。
	trimStart := strings.Index(tpl, "function trimResultsDom()")
	trimEnd := strings.Index(tpl, "function updateResultMeta()")
	if trimStart < 0 || trimEnd <= trimStart {
		t.Fatal("未找到 trimResultsDom 实现")
	}
	if body := tpl[trimStart:trimEnd]; strings.Contains(body, "lastResultID") {
		t.Fatal("DOM 回收逻辑不得修改结果游标 lastResultID")
	}
	// 进度合并必须覆盖四类累计计数。
	mergeStart := strings.Index(tpl, "function mergeScan(scan)")
	mergeEnd := strings.Index(tpl, "function updateControls(status)")
	if mergeStart < 0 || mergeEnd <= mergeStart {
		t.Fatal("未找到 mergeScan 实现")
	}
	mergeBody := tpl[mergeStart:mergeEnd]
	if !strings.Contains(mergeBody, "progressFloor") || !strings.Contains(mergeBody, "monoMax") {
		t.Fatal("进度合并没有使用单调下限")
	}
	if !strings.Contains(tpl, "processed_targets: ") || !strings.Contains(tpl, "open_ports: ") || !strings.Contains(tpl, "result_count: ") {
		t.Fatal("进度下限未覆盖 processed/open_ports/result_count")
	}
	// 详情页 JS 必须带单次拉取 limit，服务端才能稳定分页。
	if !strings.Contains(tpl, "&limit=${RESULT_PAGE_LIMIT}") {
		t.Fatal("live 拉取未携带 limit 参数")
	}
}

// TestRunTaskPreparingAsyncDedupAndVisibleError 启动 API 立即返回 preparing，
// 后台启动失败（容量预检拒绝）可通过 run-status 完整看到；重复提交被拦截；权限与 404 保持可见。
func TestRunTaskPreparingAsyncDedupAndVisibleError(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	taskID, err := st.CreateScanTask(store.ScanTask{Name: "启动闸门测试", Mode: "full", TargetType: "all"})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	started := make(chan int64, 1)
	var calls int
	var mu sync.Mutex
	server.startFn = func(id int64) (int64, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		select {
		case started <- id:
		default:
		}
		<-release
		return 0, fmt.Errorf("容量预检未通过，扫描未启动：容量预检未通过：500 个目标 × 65535 端口，预计约 12h，超过任务超时 1h0m0s。可行调整（任选其一）：1) 提高单次任务超时；2) 提高平台总速率预算")
	}
	runPath := fmt.Sprintf("/api/tasks/%d/run", taskID)

	// 权限：viewer 不得启动扫描。
	if rec := scanFormRequest(server, runPath, "viewer", url.Values{}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 启动状态=%d，期望 403", rec.Code)
	}
	// 未登录：JSON 401。
	unauth := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, runPath, strings.NewReader("")))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("未登录启动状态=%d，期望 401", unauth.Code)
	}
	// 不存在的任务：404，且不创建执行记录。
	if rec := scanFormRequest(server, "/api/tasks/999999/run", "operator", url.Values{}); rec.Code != http.StatusNotFound {
		t.Fatalf("不存在任务启动状态=%d，期望 404", rec.Code)
	}

	rec := scanFormRequest(server, runPath, "operator", url.Values{})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("启动状态=%d，期望 202（立即返回 preparing），响应=%s", rec.Code, rec.Body.String())
	}
	var accepted struct {
		Preparing bool   `json:"preparing"`
		TaskID    int64  `json:"task_id"`
		RequestID string `json:"request_id"`
		StatusURL string `json:"status_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	// 启动 API 必须返回 request_id，且 status_url 只认该编号。
	if !accepted.Preparing || accepted.TaskID != taskID || accepted.RequestID == "" ||
		accepted.StatusURL != fmt.Sprintf("/api/tasks/%d/run-status?request_id=%s", taskID, accepted.RequestID) {
		t.Fatalf("启动响应不正确: %+v", accepted)
	}
	select {
	case id := <-started:
		if id != taskID {
			t.Fatalf("后台启动任务 ID=%d，期望 %d", id, taskID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("后台启动未被触发")
	}

	// 后台启动进行中：重复提交必须 409，且不得再次调用启动入口。
	if rec := scanFormRequest(server, runPath, "operator", url.Values{}); rec.Code != http.StatusConflict {
		t.Fatalf("重复启动状态=%d，期望 409，响应=%s", rec.Code, rec.Body.String())
	}

	type runStatus struct {
		RequestID string   `json:"request_id"`
		Preparing bool     `json:"preparing"`
		Done      bool     `json:"done"`
		ScanID    int64    `json:"scan_id"`
		Error     string   `json:"error"`
		Advice    []string `json:"advice"`
	}
	readStatus := func() runStatus {
		statusRec := scanLiveRequest(server, http.MethodGet, accepted.StatusURL, "viewer")
		if statusRec.Code != http.StatusOK {
			t.Fatalf("run-status 状态=%d，响应=%s", statusRec.Code, statusRec.Body.String())
		}
		var status runStatus
		if err := json.Unmarshal(statusRec.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.RequestID != accepted.RequestID {
			t.Fatalf("run-status 返回的 request_id=%q，期望 %q", status.RequestID, accepted.RequestID)
		}
		return status
	}
	if status := readStatus(); !status.Preparing || status.Done {
		t.Fatalf("启动中应返回 preparing=true/done=false: %+v", status)
	}

	close(release)
	deadline := time.Now().Add(3 * time.Second)
	var status runStatus
	for {
		status = readStatus()
		if status.Done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待后台启动结果超时: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// 错误不吞：原始容量预检文本与可操作建议都要可见。
	if !strings.Contains(status.Error, "容量预检") {
		t.Fatalf("run-status 未保留原始错误: %q", status.Error)
	}
	if len(status.Advice) == 0 {
		t.Fatal("容量预检拒绝应返回可操作建议")
	}
	if status.Preparing {
		t.Fatal("启动完成后 preparing 应为 false")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("启动入口被调用 %d 次，重复提交应被闸门拦截", calls)
	}
}

// TestScanDetailCapacityRejectionShowsActionableAdvice 容量预检拒绝（全端口默认 60 分钟）
// 必须在页面与 API 同时展示可操作建议，且保留原始错误文本。
func TestScanDetailCapacityRejectionShowsActionableAdvice(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	addTestAdmin(t, server, st)
	scanID, err := st.CreateScan(1, "全端口容量拒绝", "full")
	if err != nil {
		t.Fatal(err)
	}
	rawErr := "容量预检未通过，扫描未启动：容量预检未通过：500 个目标 × 65535 端口 × 1 次尝试，按生效并发 3、每进程速率 2000/s 预计约 15h，超过任务超时 1h0m0s。平台不会自动缩小目标端口范围，也不会静默接受必然被截断的执行。可行调整（任选其一）：1) 把“单次任务超时”提高到至少 900 分钟；2) 把平台总速率预算提高到至少 50000/s"
	if err := st.FinishScanStatus(scanID, "failed", 0, rawErr); err != nil {
		t.Fatal(err)
	}
	rec := scanLiveRequest(server, http.MethodGet, fmt.Sprintf("/scans/%d", scanID), "operator")
	if rec.Code != http.StatusOK {
		t.Fatalf("执行详情状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"容量预检", "可操作建议", "单次任务超时", "1h0m0s"} {
		if !strings.Contains(body, want) {
			t.Fatalf("容量拒绝详情缺少 %q", want)
		}
	}
	if strings.Contains(body, `href="/settings"`) {
		t.Fatal("operator 不应看到仅管理员可访问的设置链接")
	}
	if !strings.Contains(body, "转交管理员") {
		t.Fatal("operator 应看到「转交管理员」的替代指引")
	}
	adminBody := scanLiveRequest(server, http.MethodGet, fmt.Sprintf("/scans/%d", scanID), "admin").Body.String()
	if !strings.Contains(adminBody, `href="/settings"`) {
		t.Fatal("admin 应看到前往系统设置的链接")
	}

	payload := readScanLive(t, server, scanID, 0, 500)
	if !payload.CapacityBlocked || len(payload.CapacityAdvice) == 0 {
		t.Fatalf("live API 未返回容量建议: blocked=%v advice=%v", payload.CapacityBlocked, payload.CapacityAdvice)
	}
	if !isCapacityRejection(payload.Scan.Err) || !strings.Contains(payload.Scan.Err, "900 分钟") {
		t.Fatalf("live API 未原样保留容量错误文本: %q", payload.Scan.Err)
	}
}

// TestCreateTaskRunNowPreparing 「保存并立即运行」也走后台启动闸门：
// 保存请求立即返回 preparing 与 status_url，不改回同步阻塞启动。
func TestCreateTaskRunNowPreparing(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	release := make(chan struct{})
	server.startFn = func(id int64) (int64, error) {
		<-release
		return 0, nil
	}
	form := url.Values{}
	form.Set("name", "新建并运行任务")
	form.Set("mode", "top")
	form.Set("target_type", "all")
	form.Set("run_now", "on")
	rec := scanFormRequest(server, "/api/tasks", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("保存并运行状态=%d，响应=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID        int64  `json:"id"`
		TaskID    int64  `json:"task_id"`
		RequestID string `json:"request_id"`
		Preparing bool   `json:"preparing"`
		StatusURL string `json:"status_url"`
		RunError  string `json:"run_error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Preparing || resp.RunError != "" || resp.RequestID == "" ||
		resp.StatusURL != fmt.Sprintf("/api/tasks/%d/run-status?request_id=%s", resp.ID, resp.RequestID) || resp.TaskID != resp.ID {
		t.Fatalf("保存并运行未返回 preparing + request_id: %+v", resp)
	}
	if task, err := st.ScanTask(resp.ID); err != nil || task == nil {
		t.Fatalf("任务未保存成功: %v", err)
	}
	// 启动仍在后台进行：重复提交被拦截。
	repeat := scanFormRequest(server, fmt.Sprintf("/api/tasks/%d/run", resp.ID), "operator", url.Values{})
	if repeat.Code != http.StatusConflict {
		t.Fatalf("重复启动状态=%d，期望 409", repeat.Code)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		statusRec := scanLiveRequest(server, http.MethodGet, resp.StatusURL, "viewer")
		var status struct {
			Done  bool   `json:"done"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(statusRec.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Done {
			if status.Error != "" {
				t.Fatalf("启动应成功，实际错误: %s", status.Error)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("等待「保存并运行」后台启动结果超时")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestScanLiveCursorAcrossConcurrentInserts 游标拉取过程中持续有新结果入库：
// 键集游标保证已拉取的行不重复、新写入的行不遗漏。
func TestScanLiveCursorAcrossConcurrentInserts(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	scanID, err := st.CreateScan(1, "边扫边拉执行", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartScanExecution(scanID, 550, 1); err != nil {
		t.Fatal(err)
	}
	insertPorts := func(start, count int) {
		rows := make([]store.Result, 0, count)
		for i := 0; i < count; i++ {
			rows = append(rows, store.Result{IP: "203.0.113.7", Port: start + i, Proto: "tcp", Status: 1})
		}
		if _, err := st.InsertResultsBatch(scanID, rows); err != nil {
			t.Fatalf("写入结果失败: %v", err)
		}
	}
	insertPorts(1, 250)
	first := readScanLive(t, server, scanID, 0, 100)
	if len(first.Results) != 100 || !first.HasMore {
		t.Fatalf("首页应满 100 行且 has_more=true: rows=%d has_more=%v", len(first.Results), first.HasMore)
	}
	seen := map[int64]bool{}
	for _, item := range first.Results {
		seen[item.ID] = true
	}
	// 页间插入新结果：后续游标只能看到更大 id，已读行不会重复出现。
	insertPorts(251, 300)
	cursor := first.NextCursor
	pages := 0
	for {
		payload := readScanLive(t, server, scanID, cursor, 100)
		for _, item := range payload.Results {
			if seen[item.ID] {
				t.Fatalf("页间新写入造成重复行 id=%d", item.ID)
			}
			seen[item.ID] = true
		}
		cursor = payload.NextCursor
		pages++
		if pages > 50 {
			t.Fatal("游标未推进")
		}
		if !payload.HasMore {
			break
		}
	}
	if len(seen) != 550 {
		t.Fatalf("拉取到 %d 行，期望 550（不得遗漏页间写入的行）", len(seen))
	}
}

// TestScanLivePermissions 详情/live/run-status 的读权限边界：
// 未登录 401，viewer 可读但不可启动，operator 可启动。
func TestScanLivePermissions(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	scanID, err := st.CreateScan(1, "权限校验执行", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScanStatus(scanID, "done", 0, ""); err != nil {
		t.Fatal(err)
	}
	livePath := fmt.Sprintf("/api/scans/%d/live", scanID)
	unauth := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, livePath, nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("未登录 live 状态=%d，期望 401", unauth.Code)
	}
	if rec := scanLiveRequest(server, http.MethodGet, livePath, "viewer"); rec.Code != http.StatusOK {
		t.Fatalf("viewer live 状态=%d，期望 200", rec.Code)
	}
	taskID, err := st.CreateScanTask(store.ScanTask{Name: "权限任务", Mode: "top", TargetType: "all"})
	if err != nil {
		t.Fatal(err)
	}
	statusPath := fmt.Sprintf("/api/tasks/%d/run-status", taskID)
	// 缺少 request_id：400（不得返回“空闲/成功”）。
	if rec := scanLiveRequest(server, http.MethodGet, statusPath, "viewer"); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺少 request_id 的 run-status 状态=%d，期望 400", rec.Code)
	}
	// 未知编号：404（不得表示成功）。
	rec := scanLiveRequest(server, http.MethodGet, statusPath+"?request_id=unknown-request", "viewer")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未知 request_id 的 run-status 状态=%d，期望 404，响应=%s", rec.Code, rec.Body.String())
	}
	var idle struct {
		Preparing bool   `json:"preparing"`
		Done      bool   `json:"done"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &idle); err != nil {
		t.Fatal(err)
	}
	if idle.Preparing || idle.Done || idle.Error == "" {
		t.Fatalf("未知启动请求必须返回明确错误而不是成功: %+v", idle)
	}
	if rec := scanFormRequest(server, fmt.Sprintf("/api/tasks/%d/run", taskID), "viewer", url.Values{}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 启动状态=%d，期望 403", rec.Code)
	}
}
