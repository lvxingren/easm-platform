package web

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// startStateTTL 是「已完成」启动请求状态的保留时长。
	// 超过该时长后 run-status 返回 410，明确告知状态已被清理，绝不伪报成功。
	startStateTTL = 30 * time.Minute
	// startStateCapacity 是「已完成」启动请求状态的最大保留条数；
	// 超出后按创建顺序淘汰最早的完成态，避免长期运行的服务无限增长。
	startStateCapacity = 128
	// startTombstoneFactor 决定过期/淘汰编号在墓碑表中保留的时长倍数，
	// 使客户端在状态清理后仍能拿到 410 而不是含混的 404。
	startTombstoneFactor = 2
)

var (
	// errStartRequestUnknown 表示请求编号从未存在（或墓碑已过期）：HTTP 404。
	errStartRequestUnknown = errors.New("启动请求编号不存在")
	// errStartRequestExpired 表示请求编号存在过，但状态已按 TTL/容量清理：HTTP 410。
	errStartRequestExpired = errors.New("启动请求状态已过期")
)

// startState 记录一次后台启动请求的进展。
// 每个请求以 request_id 独立索引，互不覆盖：B 请求完成不会顶掉 A 请求的失败结果。
type startState struct {
	RequestID  string    `json:"request_id"`
	TaskID     int64     `json:"task_id"`
	ScanID     int64     `json:"scan_id"`
	StartedAt  time.Time `json:"-"`
	FinishedAt time.Time `json:"-"`
	Done       bool      `json:"done"`
	Err        string    `json:"error"`
}

// startRegistry 是按 request_id 索引的启动状态表，带防重复启动闸门。
// 零值可用；ttl/capacity/now 仅在测试中注入。
type startRegistry struct {
	mu       sync.Mutex
	entries  map[string]*startState
	order    []string             // 创建顺序，用于容量淘汰
	expired  map[string]time.Time // 已清理编号的到期时间（墓碑），用于区分 404/410
	active   string               // 当前进行中的请求编号，空表示没有
	ttl      time.Duration
	capacity int
	now      func() time.Time
}

func (g *startRegistry) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

func (g *startRegistry) ttlOr() time.Duration {
	if g.ttl > 0 {
		return g.ttl
	}
	return startStateTTL
}

func (g *startRegistry) capacityOr() int {
	if g.capacity > 0 {
		return g.capacity
	}
	return startStateCapacity
}

func (g *startRegistry) initLocked() {
	if g.entries == nil {
		g.entries = make(map[string]*startState)
	}
	if g.expired == nil {
		g.expired = make(map[string]time.Time)
	}
}

func (g *startRegistry) removeOrderLocked(requestID string) {
	for i, id := range g.order {
		if id == requestID {
			g.order = append(g.order[:i], g.order[i+1:]...)
			return
		}
	}
}

// retireLocked 把编号移出状态表并留下墓碑，后续查询按过期处理（410）。
func (g *startRegistry) retireLocked(requestID string, now time.Time) {
	delete(g.entries, requestID)
	g.removeOrderLocked(requestID)
	g.expired[requestID] = now.Add(g.ttlOr() * startTombstoneFactor)
}

// pruneLocked 清理超时与超容量的完成态；进行中的请求永不淘汰。
func (g *startRegistry) pruneLocked(now time.Time) {
	ttl := g.ttlOr()
	for id, st := range g.entries {
		if st.Done && !st.FinishedAt.IsZero() && now.Sub(st.FinishedAt) > ttl {
			g.retireLocked(id, now)
		}
	}
	for id, until := range g.expired {
		if !now.Before(until) {
			delete(g.expired, id)
		}
	}
	capacity := g.capacityOr()
	for len(g.entries) > capacity {
		victim := ""
		for _, id := range g.order {
			if st := g.entries[id]; st != nil && st.Done {
				victim = id
				break
			}
		}
		if victim == "" {
			// 只剩进行中的请求（最多一个），不淘汰，等其完成后下一轮再收敛。
			return
		}
		g.retireLocked(victim, now)
	}
}

// begin 受理一次启动请求并返回它专属的 request_id。
func (g *startRegistry) begin(taskID int64) (requestID string, message string, ok bool) {
	requestID = newStartRequestID()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()
	now := g.clock()
	g.pruneLocked(now)
	if active := g.entries[g.active]; active != nil && !active.Done {
		if active.TaskID == taskID {
			return "", fmt.Sprintf("任务 #%d 的启动请求正在处理中（preparing，请求编号 %s），请勿重复提交", taskID, active.RequestID), false
		}
		return "", fmt.Sprintf("任务 #%d 的启动请求正在处理中，请等待该请求完成后再启动其他任务", active.TaskID), false
	}
	// 兜底：任何残留的进行中请求都不允许并发启动（正常路径下最多一个）。
	for _, st := range g.entries {
		if !st.Done {
			return "", fmt.Sprintf("已有启动请求（任务 #%d）正在处理中，请等待其完成", st.TaskID), false
		}
	}
	g.entries[requestID] = &startState{RequestID: requestID, TaskID: taskID, StartedAt: now}
	g.order = append(g.order, requestID)
	g.active = requestID
	return requestID, "", true
}

// finish 记录指定请求的后台启动结果，只更新该请求自己的状态。
func (g *startRegistry) finish(requestID string, scanID int64, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()
	st := g.entries[requestID]
	if st == nil {
		// 编号已被清理或从未登记：不创建新条目，避免伪造出一条"成功"记录。
		return
	}
	now := g.clock()
	st.ScanID = scanID
	st.Done = true
	st.FinishedAt = now
	st.Err = ""
	if err != nil {
		st.Err = err.Error()
	}
	if g.active == requestID {
		g.active = ""
	}
	g.pruneLocked(now)
}

// lookup 按 request_id 查询状态；未知返回 errStartRequestUnknown，已清理返回 errStartRequestExpired。
func (g *startRegistry) lookup(requestID string) (startState, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()
	now := g.clock()
	g.pruneLocked(now)
	if st := g.entries[requestID]; st != nil {
		return *st, nil
	}
	if until, ok := g.expired[requestID]; ok && now.Before(until) {
		return startState{}, errStartRequestExpired
	}
	return startState{}, errStartRequestUnknown
}

var startRequestSeq atomic.Uint64

// newStartRequestID 生成不可预测的请求编号；随机源异常时退化为时间戳+序号，仍保证唯一。
func newStartRequestID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	return fmt.Sprintf("t%d-%d", time.Now().UnixNano(), startRequestSeq.Add(1))
}

// startStatusPath 生成带 request_id 的状态查询地址；缺少该参数时服务端会明确拒绝。
func startStatusPath(taskID int64, requestID string) string {
	return fmt.Sprintf("/api/tasks/%d/run-status?request_id=%s", taskID, url.QueryEscape(requestID))
}

// beginBackgroundStart 受理一次启动请求。
// 已有扫描在运行、或上一次后台启动尚未完成时拒绝，保证重复点击不会创建多个执行记录。
func (s *Server) beginBackgroundStart(taskID int64) (requestID, message string, ok bool) {
	if s.sc != nil && s.sc.IsRunning() {
		return "", "已有扫描任务运行或暂停中，本次未启动；请等待当前任务结束后在执行记录中查看结果", false
	}
	return s.startGate.begin(taskID)
}

// finishBackgroundStart 记录后台启动的结果，供 run-status 接口按 request_id 读取。
func (s *Server) finishBackgroundStart(requestID string, scanID int64, err error) {
	s.startGate.finish(requestID, scanID, err)
}

// startStatusFor 返回指定启动请求的状态。
// 未知编号返回 errStartRequestUnknown，已按 TTL/容量清理的编号返回 errStartRequestExpired。
func (s *Server) startStatusFor(requestID string) (startState, error) {
	return s.startGate.lookup(requestID)
}

// startEntry 返回实际的启动入口；测试可替换 startFn 以隔离 scanner。
func (s *Server) startEntry() func(int64) (int64, error) {
	if s.startFn != nil {
		return s.startFn
	}
	return s.sc.StartTask
}

// launchBackgroundStart 在后台执行一次启动，避免同步的 naabu 自检与容量预检阻塞 HTTP 响应。
// recover 保证启动流程内部出错时闸门不会永久停在 preparing，错误同样可通过 run-status 看到。
func (s *Server) launchBackgroundStart(requestID string, taskID int64) {
	entry := s.startEntry()
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.finishBackgroundStart(requestID, 0, fmt.Errorf("启动流程发生内部错误，扫描未启动: %v", recovered))
			}
		}()
		scanID, err := entry(taskID)
		s.finishBackgroundStart(requestID, scanID, err)
	}()
}

// apiRunTask 受理运行任务的请求：权限由路由上的 requireWrite 保证，
// 任务存在性同步校验，真正的启动流程放后台执行并立即返回 preparing + request_id。
func (s *Server) apiRunTask(w http.ResponseWriter, r *http.Request) {
	taskID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if taskID <= 0 {
		writeJSON(w, 400, map[string]string{"error": "任务 ID 格式错误"})
		return
	}
	task, err := s.st.ScanTask(taskID)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "读取扫描任务失败: " + err.Error()})
		return
	}
	if task == nil {
		writeJSON(w, 404, map[string]string{"error": "扫描任务不存在或已被删除，未启动"})
		return
	}
	s.audit(r, "运行扫描任务", "#"+strconv.FormatInt(taskID, 10), "")
	requestID, msg, ok := s.beginBackgroundStart(taskID)
	if !ok {
		// 本次请求未被受理：明确拒绝，不返回 request_id，也不表示 preparing。
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error": msg, "preparing": false, "busy": true, "task_id": taskID, "request_id": "",
		})
		return
	}
	s.launchBackgroundStart(requestID, taskID)
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"preparing":  true,
		"task_id":    taskID,
		"request_id": requestID,
		"status_url": startStatusPath(taskID, requestID),
		"message":    "已受理启动请求：正在后台执行 naabu 自检、目标解析与容量预检，完成后自动创建执行记录。",
	})
}

// apiRunStatus 按 request_id 返回后台启动请求的状态与错误（含容量预检的可操作建议）。
// 只读接口，登录即可访问；缺少/未知/过期编号都返回明确错误，绝不表示启动成功。
func (s *Server) apiRunStatus(w http.ResponseWriter, r *http.Request) {
	taskID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if taskID <= 0 {
		writeJSON(w, 400, map[string]string{"error": "任务 ID 格式错误"})
		return
	}
	requestID := strings.TrimSpace(r.URL.Query().Get("request_id"))
	if requestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "缺少 request_id：启动结果必须按启动请求编号查询，请重新发起启动", "task_id": taskID,
			"request_id": "", "preparing": false, "done": false,
		})
		return
	}
	state, err := s.startStatusFor(requestID)
	if err != nil {
		status := http.StatusNotFound
		message := fmt.Sprintf("未找到启动请求编号 %s（从未受理或已被清理），请到执行记录确认本次启动结果", requestID)
		if errors.Is(err, errStartRequestExpired) {
			status = http.StatusGone
			message = fmt.Sprintf("启动请求 %s 的状态已过期（按 TTL/容量清理），请到执行记录确认本次启动结果", requestID)
		}
		writeJSON(w, status, map[string]interface{}{
			"error": message, "task_id": taskID, "request_id": requestID,
			"preparing": false, "done": false, "advice": []string{},
		})
		return
	}
	if state.TaskID != taskID {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   fmt.Sprintf("启动请求编号 %s 不属于任务 #%d", requestID, taskID),
			"task_id": taskID, "request_id": requestID,
			"preparing": false, "done": false, "advice": []string{},
		})
		return
	}
	response := map[string]interface{}{
		"request_id": state.RequestID,
		"task_id":    taskID,
		"preparing":  !state.Done,
		"done":       state.Done,
		"scan_id":    state.ScanID,
		"error":      state.Err,
		"advice":     capacitySuggestions(state.Err),
		"started_at": state.StartedAt.Format(time.RFC3339),
	}
	if state.Done {
		response["finished_at"] = state.FinishedAt.Format(time.RFC3339)
		if state.Err == "" {
			response["message"] = "启动成功，已创建执行记录"
		} else {
			response["message"] = "启动失败，完整原因已写入执行记录"
		}
	} else {
		response["message"] = "正在执行 naabu 自检、目标解析与容量预检"
	}
	writeJSON(w, 200, response)
}
