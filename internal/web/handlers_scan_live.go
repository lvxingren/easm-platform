package web

import (
	"fmt"
	"net/http"
	"strconv"

	"easm-platform/internal/store"
)

// live API 的结果分页硬上限：单次最多返回 store.ResultPageMaxLimit 行，
// 前端按 next_cursor 反复拉取直到 has_more=false，即使执行已进入终态也不提前停止。
const (
	scanLiveResultPageLimit = 500
	scanLiveEventsPageLimit = 200
)

func scanStatusName(status string) string {
	switch status {
	case "done":
		return "完成"
	case "running":
		return "运行中"
	case "paused":
		return "已暂停"
	case "partial":
		return "部分完成"
	case "stopped":
		return "已终止"
	default:
		return "失败"
	}
}

func scanStatusClass(status string) string {
	switch status {
	case "done":
		return "ok"
	case "running", "paused", "partial":
		return "run"
	case "stopped":
		return "mute"
	default:
		return "err"
	}
}

// scanTerminal 判断执行是否已进入终态（终态后结果不再增长，但可能还有未拉取的行）。
func scanTerminal(status string) bool {
	return status != "running" && status != "paused"
}

// clampLiveResultLimit 归一化单次拉取条数：非法值取默认值，超上限按上限截断。
func clampLiveResultLimit(limit int) int {
	if limit <= 0 {
		return scanLiveResultPageLimit
	}
	if limit > store.ResultPageMaxLimit {
		return store.ResultPageMaxLimit
	}
	return limit
}

func (s *Server) apiScanLive(w http.ResponseWriter, r *http.Request) {
	scanID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	afterID, _ := strconv.ParseInt(r.URL.Query().Get("after_id"), 10, 64)
	eventAfterID, _ := strconv.ParseInt(r.URL.Query().Get("event_after_id"), 10, 64)
	if scanID <= 0 || afterID < 0 || eventAfterID < 0 {
		writeJSON(w, 400, map[string]string{"error": "执行 ID 和增量游标格式错误"})
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			writeJSON(w, 400, map[string]string{"error": "增量条数 limit 格式错误，应为正整数"})
			return
		}
		limit = parsed
	}
	limit = clampLiveResultLimit(limit)
	scan, err := s.st.Scan(scanID)
	if err != nil || scan == nil {
		writeJSON(w, 404, map[string]string{"error": "扫描执行不存在"})
		return
	}
	// 键集游标分页：只返回 id > after_id 的行，并发写入只会追加更大 id，
	// 因此翻页过程中不会遗漏已存在行，也不会重复返回同一行。
	page, err := s.st.ResultsPage(scanID, afterID, limit)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "读取实时结果失败: " + err.Error()})
		return
	}
	events, err := s.st.ScanEvents(scanID, eventAfterID, scanLiveEventsPageLimit)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "读取执行事件失败: " + err.Error()})
		return
	}
	terminal := scanTerminal(scan.Status)
	resultCount := monotonicResultCount(s, scanID, scan.ResultCount, page)
	writeJSON(w, 200, map[string]interface{}{
		"scan":              scan,
		"results":           page.Results,
		"events":            events,
		"active":            !terminal,
		"terminal":          terminal,
		"has_more":          page.HasMore,
		"next_cursor":       page.NextCursor,
		"result_count":      resultCount,
		"limit":             limit,
		"capacity_blocked":  isCapacityRejection(scan.Err),
		"capacity_advice":   capacitySuggestions(scan.Err),
		"cursor_after_id":   afterID,
		"event_next_cursor": lastEventCursor(events, eventAfterID),
	})
}

// lastEventCursor 返回事件增量拉取的下一个游标：无事件时保持传入游标不变。
func lastEventCursor(events []store.ScanEvent, fallback int64) int64 {
	if len(events) == 0 {
		return fallback
	}
	return events[len(events)-1].ID
}

// monotonicResultCount 返回本次响应里的结果总数，保证跨页不回退。
// 正常情况下直接使用 scans.result_count（写入侧单调累计）；
// 旧库尚未回填（result_count 小于已返回行数）时，只在最后一页做一次精确 COUNT，
// 避免每页对大表全表统计，也避免「result_count 随分页大小回退」。
func monotonicResultCount(s *Server, scanID int64, stored int, page store.ResultPage) int {
	if stored > 0 && stored >= len(page.Results) {
		return stored
	}
	if page.HasMore {
		// 还有未拉取的行：此时不做全表 COUNT，回退风险由前端单调下限兑付。
		return stored
	}
	n, err := s.st.CountResultsByScan(scanID)
	if err != nil || n < stored {
		n = stored
	}
	if n < len(page.Results) {
		n = len(page.Results)
	}
	return n
}

func (s *Server) apiScanControl(w http.ResponseWriter, r *http.Request) {
	scanID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	action := r.PathValue("action")
	if scanID <= 0 {
		writeJSON(w, 400, map[string]string{"error": "执行 ID 格式错误"})
		return
	}
	var err error
	var actionName string
	switch action {
	case "pause":
		actionName = "暂停扫描执行"
		err = s.sc.Pause(scanID)
	case "resume":
		actionName = "恢复扫描执行"
		err = s.sc.Resume(scanID)
	case "stop":
		actionName = "终止扫描执行"
		err = s.sc.Stop(scanID)
	case "resync":
		actionName = "同步扫描执行状态"
		if s.sc.IsRunning() && s.sc.CurrentScanID() == scanID {
			err = fmt.Errorf("该执行仍是当前活动扫描，状态实时准确，无需同步")
		} else if sc, _ := s.st.Scan(scanID); sc != nil && (sc.Status == "running" || sc.Status == "paused") {
			err = s.st.ForceStopScanIfActive(scanID, "手动同步状态：执行进程已不存在，状态修正为已终止；已入库结果保留，不生成告警。")
		}
	default:
		writeJSON(w, 404, map[string]string{"error": "不支持的扫描控制操作"})
		return
	}
	s.audit(r, actionName, "#"+strconv.FormatInt(scanID, 10), "")
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	scan, _ := s.st.Scan(scanID)
	writeJSON(w, 200, map[string]interface{}{"ok": "1", "scan": scan})
}

// apiScanResume 从被终止/部分完成的执行发起「继续扫描未完成节点」增量续扫。
func (s *Server) apiScanResume(w http.ResponseWriter, r *http.Request) {
	scanID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if scanID <= 0 {
		writeJSON(w, 400, map[string]string{"error": "执行 ID 格式错误"})
		return
	}
	newID, err := s.sc.StartResume(scanID)
	s.audit(r, "续扫未完成目标", "#"+strconv.FormatInt(scanID, 10), fmt.Sprintf("新执行 #%d", newID))
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": "1", "scan_id": newID})
}

// apiScanSubTasks 返回拆分任务的子任务列表。
func (s *Server) apiScanSubTasks(w http.ResponseWriter, r *http.Request) {
	scanID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if scanID <= 0 {
		writeJSON(w, 400, map[string]string{"error": "扫描 ID 格式错误"})
		return
	}
	scan, err := s.st.Scan(scanID)
	if err != nil || scan == nil {
		writeJSON(w, 404, map[string]string{"error": "扫描执行不存在"})
		return
	}
	if !scan.IsSplitTask {
		writeJSON(w, 200, map[string]interface{}{"subtasks": []interface{}{}, "is_split_task": false})
		return
	}
	subTasks, err := s.st.SubTasksByParent(scanID)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": fmt.Sprintf("查询子任务失败: %v", err)})
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"subtasks":        subTasks,
		"is_split_task":   true,
		"split_total":     scan.SplitTotal,
		"split_completed": scan.SplitCompleted,
	})
}
