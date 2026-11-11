package web

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"easm-platform/internal/ai"
	"easm-platform/internal/logparse"
	"easm-platform/internal/store"
)

// storedFile 是一次上传后落盘的原始文件信息。
type storedFile struct {
	filename string
	size     int64
	path     string
}

// aiConfig 从系统设置读取 AI 调用配置（Token 只在内存中使用，不落日志）。
func (s *Server) aiConfig() ai.Config {
	temp, _ := strconv.ParseFloat(s.st.Setting("ai_temperature"), 64)
	timeout, _ := strconv.Atoi(s.st.Setting("ai_timeout_sec"))
	return ai.Config{
		Endpoint:    strings.TrimSpace(s.st.Setting("ai_endpoint")),
		APIKey:      strings.TrimSpace(s.st.Setting("ai_key")),
		Model:       strings.TrimSpace(s.st.Setting("ai_model")),
		TimeoutSec:  timeout,
		Temperature: temp,
	}
}

// analysisGate 是「流量分析」模块总开关守卫：仅当系统设置 analysis_enabled=1 时才放行。
// 关闭时模块入口在侧边栏隐藏，直接访问页面/API 一律返回 404，避免仅靠前端隐藏被绕过。
func (s *Server) analysisGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.analysisModuleEnabled() {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "流量分析模块未启用"})
				return
			}
			http.Error(w, "流量分析模块未启用", http.StatusNotFound)
			return
		}
		next(w, r)
	}
}

func (s *Server) pageAnalysis(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "流量分析", "analysis")
	items, _ := s.st.Analyses(200)
	s.render(w, "analysis.html", struct {
		pageData
		Items []store.Analysis
	}{bd, items})
}

func (s *Server) pageAnalysisDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := s.st.Analysis(id)
	if err != nil || a == nil {
		http.Error(w, "分析记录不存在", http.StatusNotFound)
		return
	}
	files, _ := s.st.AnalysisFiles(id)
	edges, _ := s.st.AnalysisEdges(id, 500)
	bd, _ := s.baseData(r, "流量分析 #"+r.PathValue("id"), "analysis")
	s.render(w, "analysis_detail.html", struct {
		pageData
		A     store.Analysis
		Files []store.AnalysisFile
		Edges []store.AnalysisEdge
	}{bd, *a, files, edges})
}

// apiCreateAnalysis 接收上传日志文件，落盘保留原件，创建分析项目并异步解析 + AI 分析。
func (s *Server) apiCreateAnalysis(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeJSON(w, 400, map[string]string{"error": "读取上传失败（文件过大或表单错误）: " + err.Error()})
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "流量分析 " + time.Now().Format("2006-01-02 15:04")
	}
	sourceType := strings.TrimSpace(r.FormValue("source_type"))
	if sourceType != "cfw" && sourceType != "ecs" && sourceType != "other" {
		sourceType = "other"
	}
	id, err := s.st.CreateAnalysis(name, sourceType)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "创建分析项目失败: " + err.Error()})
		return
	}
	dir := filepath.Join("data", "uploads", fmt.Sprintf("analysis_%d", id))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		_ = s.st.DeleteAnalysis(id)
		writeJSON(w, 500, map[string]string{"error": "创建上传目录失败: " + err.Error()})
		return
	}
	var stored []storedFile
	if r.MultipartForm != nil {
		for _, headers := range r.MultipartForm.File {
			for _, hdr := range headers {
				base := sanitizeFilename(hdr.Filename)
				dst := filepath.Join(dir, base)
				if err := saveUpload(hdr, dst); err != nil {
					continue
				}
				stored = append(stored, storedFile{filename: base, size: hdr.Size, path: dst})
			}
		}
	}
	if len(stored) == 0 {
		_ = s.st.DeleteAnalysis(id)
		_ = os.RemoveAll(dir)
		writeJSON(w, 400, map[string]string{"error": "未收到任何上传文件"})
		return
	}
	s.audit(r, "创建流量分析", "#"+strconv.FormatInt(id, 10), fmt.Sprintf("%d 个文件, 来源=%s", len(stored), sourceType))
	go s.runAnalysis(id, sourceType, stored)
	writeJSON(w, 200, map[string]interface{}{"ok": "1", "id": id})
}

// sanitizeFilename 只取文件名部分，杜绝 ../ 路径穿越。
func sanitizeFilename(name string) string {
	base := filepath.Base(strings.TrimSpace(strings.ReplaceAll(name, "\\", "/")))
	base = strings.ReplaceAll(base, "..", "_")
	if base == "" || base == "." || base == "/" {
		base = fmt.Sprintf("upload_%d", time.Now().UnixNano())
	}
	return base
}

func saveUpload(hdr *multipart.FileHeader, dst string) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(src, 256<<20))
	return err
}

// runAnalysis 异步执行：读取落盘文件 → 解析归一化 → 聚合 → 调用 AI（或降级）→ 落库。
func (s *Server) runAnalysis(id int64, sourceType string, files []storedFile) {
	_ = s.st.SetAnalysisStatus(id, "parsing", "")
	var allFlows []logparse.Flow
	var parseErrs []string
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("%s 读取失败: %v", f.filename, err))
			_ = s.st.AddAnalysisFile(store.AnalysisFile{AnalysisID: id, Filename: f.filename, Size: f.size, StoredPath: f.path})
			continue
		}
		res, perr := logparse.ParseBytes(data, f.filename)
		rows := 0
		format := ""
		if perr != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("%s 解析失败: %v", f.filename, perr))
		} else {
			allFlows = append(allFlows, res.Flows...)
			rows, format = res.Rows, res.Format
		}
		_ = s.st.AddAnalysisFile(store.AnalysisFile{AnalysisID: id, Filename: f.filename, Size: f.size, Format: format, StoredPath: f.path, RowsParsed: rows})
	}
	if len(allFlows) == 0 {
		msg := "未从上传文件解析到任何有效通信记录；请确认文件包含 src_ip/dst_ip（或源/目的 IP）等列或字段。"
		if len(parseErrs) > 0 {
			msg += "\n" + strings.Join(parseErrs, "\n")
		}
		s.failAnalysis(id, msg)
		return
	}
	edges := logparse.Aggregate(allFlows)
	if err := s.st.ReplaceAnalysisEdges(id, toStoreEdges(id, edges)); err != nil {
		s.failAnalysis(id, "保存通信关系失败: "+err.Error())
		return
	}
	_ = s.st.SetAnalysisCounts(id, len(allFlows), len(edges), len(files))
	s.analyzeWithAI(id, sourceType, edges, len(allFlows))
}

// analyzeWithAI 调用 AI（未配置端点则用内置规则降级），写入结构化结果。
func (s *Server) analyzeWithAI(id int64, sourceType string, edges []logparse.Edge, flowCount int) {
	_ = s.st.SetAnalysisStatus(id, "analyzing", "")
	cfg := s.aiConfig()
	report, usedMock, err := ai.Analyze(cfg, edges, flowCount, sourceType)
	if err != nil {
		s.failAnalysis(id, "AI 分析失败: "+err.Error())
		return
	}
	topo, _ := json.Marshal(map[string]interface{}{"nodes": report.Nodes, "edges": report.Edges})
	anom, _ := json.Marshal(report.Anomalies)
	trace, _ := json.Marshal(report.TracePaths)
	_ = s.st.FinishAnalysis(id, store.AnalysisResult{
		Status: "done", Summary: report.TopologySummary, Readable: report.Readable,
		TopologyJSON: string(topo), AnomaliesJSON: string(anom), TraceJSON: string(trace),
		AIModel: cfg.Model, AIEndpoint: cfg.Endpoint, UsedMock: usedMock,
	})
}

func (s *Server) failAnalysis(id int64, msg string) {
	_ = s.st.FinishAnalysis(id, store.AnalysisResult{Status: "failed", Err: msg})
}

// apiAnalysisStatus 供详情页轮询：返回状态与结构化结果（拓扑/异常/溯源以 JSON 原文回传）。
func (s *Server) apiAnalysisStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := s.st.Analysis(id)
	if err != nil || a == nil {
		writeJSON(w, 404, map[string]string{"error": "分析记录不存在"})
		return
	}
	edges, _ := s.st.AnalysisEdges(id, 500)
	files, _ := s.st.AnalysisFiles(id)
	writeJSON(w, 200, map[string]interface{}{
		"id": a.ID, "name": a.Name, "status": a.Status, "error": a.Err, "source_type": a.SourceType,
		"created_at": a.CreatedAt, "finished_at": a.FinishedAt,
		"flow_count": a.FlowCount, "edge_count": a.EdgeCount, "file_count": a.FileCount,
		"ai_model": a.AIModel, "ai_endpoint": a.AIEndpoint, "used_mock": a.UsedMock,
		"summary": a.Summary, "readable": a.Readable,
		"topology":  rawJSON(a.TopologyJSON),
		"anomalies": rawJSON(a.AnomaliesJSON),
		"trace":     rawJSON(a.TraceJSON),
		"edges":     edges,
		"files":     files,
	})
}

func rawJSON(s string) json.RawMessage {
	s = strings.TrimSpace(s)
	if s == "" || !json.Valid([]byte(s)) {
		return json.RawMessage("null")
	}
	return json.RawMessage(s)
}

// apiRetryAnalysis 用已保存的聚合关系重新调用 AI（配置修正或临时失败后重试）。
func (s *Server) apiRetryAnalysis(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := s.st.Analysis(id)
	if err != nil || a == nil {
		writeJSON(w, 404, map[string]string{"error": "分析记录不存在"})
		return
	}
	edges, _ := s.st.AnalysisEdges(id, 0)
	if len(edges) == 0 {
		writeJSON(w, 400, map[string]string{"error": "没有已解析的通信关系，无法重试；请重新上传日志"})
		return
	}
	s.audit(r, "重试流量分析 AI", "#"+strconv.FormatInt(id, 10), "")
	lEdges := toLogparseEdges(edges)
	flowCount := a.FlowCount
	go s.analyzeWithAI(id, a.SourceType, lEdges, flowCount)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiDeleteAnalysis(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := s.st.Analysis(id); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err := s.st.DeleteAnalysis(id); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = os.RemoveAll(filepath.Join("data", "uploads", fmt.Sprintf("analysis_%d", id)))
	s.audit(r, "删除流量分析", "#"+strconv.FormatInt(id, 10), "")
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// apiCreateAlertManual 从分析结果手动创建一条告警处置单（IP+端口）。
func (s *Server) apiCreateAlertManual(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	port, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	proto := strings.ToLower(strings.TrimSpace(r.FormValue("proto")))
	if proto == "" {
		proto = "tcp"
	}
	service := strings.TrimSpace(r.FormValue("service"))
	note := strings.TrimSpace(r.FormValue("note"))
	if ip == "" || port < 1 || port > 65535 {
		writeJSON(w, 400, map[string]string{"error": "IP 或端口非法"})
		return
	}
	id, err := s.st.CreateAlert(ip, port, proto, service, true)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if note != "" {
		_ = s.st.UpdateAlertStatus(id, "acked", note, currentUser(r).username)
	}
	s.audit(r, "从流量分析创建告警", ip+":"+strconv.Itoa(port), note)
	writeJSON(w, 200, map[string]interface{}{"ok": "1", "id": id})
}

// apiTestAI 用已保存的 AI 配置做一次连通性/鉴权校验。
func (s *Server) apiTestAI(w http.ResponseWriter, r *http.Request) {
	cfg := s.aiConfig()
	if err := ai.TestConnection(cfg); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func toStoreEdges(id int64, edges []logparse.Edge) []store.AnalysisEdge {
	out := make([]store.AnalysisEdge, 0, len(edges))
	for _, e := range edges {
		out = append(out, store.AnalysisEdge{
			AnalysisID: id, SrcIP: e.SrcIP, DstIP: e.DstIP, DstPort: e.DstPort,
			Proto: e.Proto, Action: e.Action, Count: e.Count, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen,
		})
	}
	return out
}

func toLogparseEdges(edges []store.AnalysisEdge) []logparse.Edge {
	out := make([]logparse.Edge, 0, len(edges))
	for _, e := range edges {
		out = append(out, logparse.Edge{
			SrcIP: e.SrcIP, DstIP: e.DstIP, DstPort: e.DstPort, Proto: e.Proto,
			Action: e.Action, Count: e.Count, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen,
		})
	}
	return out
}

func analysisStatusName(status string) string {
	switch status {
	case "pending":
		return "待解析"
	case "parsing":
		return "解析中"
	case "analyzing":
		return "AI 分析中"
	case "done":
		return "完成"
	case "failed":
		return "失败"
	default:
		return status
	}
}

func analysisStatusClass(status string) string {
	switch status {
	case "done":
		return "ok"
	case "failed":
		return "err"
	default:
		return "run"
	}
}
