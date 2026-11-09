package web

import (
	"net/http"
	"strconv"
	"strings"

	"easm-platform/internal/applog"
)

// pageLogs 渲染后台运行日志页：支持按级别筛选、只看报错和关键词检索。仅管理员可见。
func (s *Server) pageLogs(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "运行日志", "logs")
	level := r.URL.Query().Get("level")
	switch level {
	case "", applog.LevelInfo, applog.LevelWarn, applog.LevelError:
	default:
		level = ""
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	entries := applog.Query(level, query, 0, 500)
	infoCount, warnCount, errorCount := applog.Counts()
	tlsToday, tlsWeek, tlsTop := applog.TLSNoiseStats()
	s.render(w, "logs.html", struct {
		pageData
		Entries    []applog.Entry
		Level      string
		Query      string
		InfoCount  int
		WarnCount  int
		ErrorCount int
		TLSToday   int
		TLSWeek    int
		TLSTop     []applog.SegmentCount
	}{bd, entries, level, query, infoCount, warnCount, errorCount, tlsToday, tlsWeek, tlsTop})
}

// apiLogs 返回增量日志，供页面实时追加（after_id 之后的新记录）。
func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	switch level {
	case "", applog.LevelInfo, applog.LevelWarn, applog.LevelError:
	default:
		level = ""
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	afterID, _ := strconv.ParseInt(r.URL.Query().Get("after_id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeJSON(w, 200, map[string]interface{}{"entries": applog.Query(level, query, afterID, limit)})
}
