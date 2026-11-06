package web

import (
	"fmt"
	"net/http"
	"strconv"
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

func (s *Server) apiScanLive(w http.ResponseWriter, r *http.Request) {
	scanID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	afterID, _ := strconv.ParseInt(r.URL.Query().Get("after_id"), 10, 64)
	eventAfterID, _ := strconv.ParseInt(r.URL.Query().Get("event_after_id"), 10, 64)
	if scanID <= 0 || afterID < 0 || eventAfterID < 0 {
		writeJSON(w, 400, map[string]string{"error": "执行 ID 和增量游标格式错误"})
		return
	}
	scan, err := s.st.Scan(scanID)
	if err != nil || scan == nil {
		writeJSON(w, 404, map[string]string{"error": "扫描执行不存在"})
		return
	}
	results, err := s.st.ResultsAfter(scanID, afterID, 500)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "读取实时结果失败: " + err.Error()})
		return
	}
	events, err := s.st.ScanEvents(scanID, eventAfterID, 200)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "读取执行事件失败: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"scan": scan, "results": results, "events": events,
		"active": scan.Status == "running" || scan.Status == "paused",
	})
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
