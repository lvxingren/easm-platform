package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"mime/multipart"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xuri/excelize/v2"

	"easm-platform/internal/ai"
	"easm-platform/internal/buildinfo"
	"easm-platform/internal/cert"
	"easm-platform/internal/config"
	"easm-platform/internal/engine"
	"easm-platform/internal/notify"
	"easm-platform/internal/scanner"
	"easm-platform/internal/store"
)

//go:embed templates static
var assets embed.FS

type session struct {
	userID   int64
	username string
	role     string
	exp      time.Time
}

type Server struct {
	st       *store.Store
	cfg      *config.Config
	sc       *scanner.Runner
	eng      *engine.Engine
	tpl      *template.Template
	sessions map[string]session
	mu       sync.Mutex

	// startGate 按 request_id 保存后台启动状态，并承担「防重复启动」闸门职责；
	// 完成态按有限 TTL/容量保留，B 请求不会覆盖 A 请求的结果。
	startGate startRegistry
	// startFn 是后台启动入口，默认指向 scanner.Runner.StartTask，测试可替换以隔离真实扫描。
	startFn func(int64) (int64, error)
}

type pageData struct {
	Title     string
	Section   string
	Active    string
	AppName   string
	Version   string
	User      string
	Role      string
	IsAdmin   bool
	NewAlerts int
	Running   bool
	ScanMode  string
	StartedAt string
	Error     string
}

func New(st *store.Store, cfg *config.Config, sc *scanner.Runner, eng *engine.Engine) *Server {
	funcs := template.FuncMap{
		"fmtTime": func(s string) string {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t.Local().Format("2006-01-02 15:04:05")
			}
			return s
		},
		"modeName": func(m string) string {
			switch m {
			case "full":
				return "全端口 1-65535"
			case "custom":
				return "自定义端口"
			default:
				return "常用端口 top-1000"
			}
		},
		"add1": func(i int) int { return i + 1 },
		"fmtMB": func(value int64) string {
			return fmt.Sprintf("%.1f", float64(value)/(1024*1024))
		},
		"roleName": roleName,
		"targetName": func(t store.ScanTask) string {
			switch t.TargetType {
			case "tag":
				return "标签：" + t.TargetTag
			case "manual":
				return "手工目标"
			default:
				return "全部台账"
			}
		},
		"alertStatusName":     alertStatusName,
		"scanStatusName":      scanStatusName,
		"scanStatusClass":     scanStatusClass,
		"analysisStatusName":  analysisStatusName,
		"analysisStatusClass": analysisStatusClass,
		"weekdayName": func(day int) string {
			names := []string{"周日", "周一", "周二", "周三", "周四", "周五", "周六"}
			if day >= 0 && day < len(names) {
				return names[day]
			}
			return "周日"
		},
		"splitTags": func(s string) []string {
			if strings.TrimSpace(s) == "" {
				return nil
			}
			var out []string
			for _, p := range strings.Split(s, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
			return out
		},
	}
	tpl := template.Must(template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html"))
	srv := &Server{st: st, cfg: cfg, sc: sc, eng: eng, tpl: tpl, sessions: map[string]session{}}
	if sc != nil {
		srv.startFn = sc.StartTask
	}
	return srv
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.pageLogin)
	mux.HandleFunc("POST /login", s.doLogin)
	mux.HandleFunc("GET /logout", s.doLogout)
	mux.Handle("GET /static/", http.FileServerFS(assets))

	// 页面（只读，登录即可）
	mux.HandleFunc("GET /{$}", s.auth(s.pageIndex))
	mux.HandleFunc("GET /assets", s.auth(s.pageAssets))
	mux.HandleFunc("GET /assets/export", s.auth(s.exportAssets))
	mux.HandleFunc("GET /exposure", s.auth(s.pageExposure))
	mux.HandleFunc("GET /exposure/export", s.auth(s.exportExposure))
	mux.HandleFunc("GET /tasks", s.auth(s.pageTasks))
	mux.HandleFunc("GET /tasks/new", s.requireWrite(s.pageTaskForm))
	mux.HandleFunc("GET /tasks/{id}/edit", s.requireWrite(s.pageTaskForm))
	mux.HandleFunc("GET /scans", s.auth(s.pageScans))
	mux.HandleFunc("GET /scans/{id}", s.auth(s.pageScanDetail))
	mux.HandleFunc("GET /results", s.auth(s.pageResults))
	mux.HandleFunc("GET /results/export", s.auth(s.exportResults))
	mux.HandleFunc("GET /whitelist", s.auth(s.pageWhitelist))
	mux.HandleFunc("GET /whitelist/export", s.auth(s.exportWhitelist))
	mux.HandleFunc("GET /alerts", s.auth(s.pageAlerts))
	mux.HandleFunc("GET /alerts/export", s.auth(s.exportAlerts))
	mux.HandleFunc("GET /alerts/{id}", s.requireWrite(s.pageAlertForm))
	mux.HandleFunc("GET /accounts", s.requireAdmin(s.pageAccounts))
	mux.HandleFunc("GET /audit", s.requireAdmin(s.pageAudit))
	mux.HandleFunc("GET /audit/export", s.requireAdmin(s.exportAudit))
	mux.HandleFunc("GET /logs", s.requireAdmin(s.pageLogs))
	mux.HandleFunc("GET /settings", s.requireAdmin(s.pageSettings))
	mux.HandleFunc("GET /help/whitelist", s.auth(s.pageWhitelistHelp))
	mux.HandleFunc("GET /analysis", s.auth(s.pageAnalysis))
	mux.HandleFunc("GET /analysis/{id}", s.auth(s.pageAnalysisDetail))

	// 样例文件下载
	mux.HandleFunc("GET /api/sample/{kind}", s.auth(s.apiSample))

	// 写操作（operator/admin）
	mux.HandleFunc("POST /api/assets/import", s.requireWrite(s.apiImportAssets))
	mux.HandleFunc("POST /api/assets/clear", s.requireWrite(s.apiClearAssets))
	mux.HandleFunc("POST /api/targets", s.requireWrite(s.apiCreateTarget))
	mux.HandleFunc("POST /api/targets/{id}/tags", s.requireWrite(s.apiSetTargetTags))
	mux.HandleFunc("POST /api/targets/batch-tags", s.requireWrite(s.apiBatchTargetTags))
	mux.HandleFunc("POST /api/targets/batch-delete", s.requireWrite(s.apiBatchDeleteTargets))
	mux.HandleFunc("POST /api/targets/{id}", s.requireWrite(s.apiUpdateTargetMeta))
	mux.HandleFunc("DELETE /api/targets/{id}", s.requireWrite(s.apiDeleteTarget))
	mux.HandleFunc("POST /api/tasks", s.requireWrite(s.apiCreateTask))
	mux.HandleFunc("POST /api/tasks/{id}/run", s.requireWrite(s.apiRunTask))
	// 后台启动状态：启动 API 立即返回 preparing，最终结果（含容量预检拒绝原因）由此读取。
	mux.HandleFunc("GET /api/tasks/{id}/run-status", s.auth(s.apiRunStatus))
	mux.HandleFunc("POST /api/tasks/{id}", s.requireWrite(s.apiUpdateTask))
	mux.HandleFunc("DELETE /api/tasks/{id}", s.requireWrite(s.apiDeleteTask))
	mux.HandleFunc("POST /api/baseline", s.requireWrite(s.apiBaseline))
	mux.HandleFunc("GET /api/baseline/preview", s.requireWrite(s.apiBaselinePreview))
	mux.HandleFunc("POST /api/baseline/apply", s.requireWrite(s.apiBaselineApply))
	mux.HandleFunc("POST /api/exposure/whitelist", s.requireWrite(s.apiExposureWhitelist))
	mux.HandleFunc("POST /api/whitelist", s.requireWrite(s.apiAddWhitelist))
	mux.HandleFunc("POST /api/whitelist/import", s.requireWrite(s.apiImportWhitelist))
	mux.HandleFunc("DELETE /api/whitelist/{id}", s.requireWrite(s.apiDelWhitelist))
	mux.HandleFunc("POST /alerts/{id}", s.requireWrite(s.submitAlertForm))
	mux.HandleFunc("POST /alerts/{id}/whitelist", s.requireWrite(s.submitAlertWhitelist))
	mux.HandleFunc("POST /api/alerts/{id}/ack", s.requireWrite(s.apiAckAlert))
	mux.HandleFunc("POST /api/alerts/{id}/status", s.requireWrite(s.apiUpdateAlert))
	mux.HandleFunc("POST /api/alerts/{id}/whitelist", s.requireWrite(s.apiAlertWhitelist))
	mux.HandleFunc("POST /api/alerts/batch", s.requireWrite(s.apiBatchAlerts))
	mux.HandleFunc("POST /api/alerts/manual", s.requireWrite(s.apiCreateAlertManual))
	mux.HandleFunc("POST /api/analysis", s.requireWrite(s.apiCreateAnalysis))
	mux.HandleFunc("POST /api/analysis/{id}/retry", s.requireWrite(s.apiRetryAnalysis))
	mux.HandleFunc("DELETE /api/analysis/{id}", s.requireWrite(s.apiDeleteAnalysis))
	mux.HandleFunc("POST /api/account/password", s.auth(s.apiChangeOwnPassword))

	// 系统管理（仅 admin）
	mux.HandleFunc("POST /api/users", s.requireAdmin(s.apiCreateUser))
	mux.HandleFunc("POST /api/users/{id}", s.requireAdmin(s.apiUpdateUser))
	mux.HandleFunc("POST /api/users/{id}/password", s.requireAdmin(s.apiResetPassword))
	mux.HandleFunc("DELETE /api/users/{id}", s.requireAdmin(s.apiDeleteUser))
	mux.HandleFunc("POST /api/settings", s.requireAdmin(s.apiSaveSettings))
	mux.HandleFunc("POST /api/settings/network", s.requireAdmin(s.apiSaveNetwork))
	mux.HandleFunc("POST /api/settings/cert", s.requireAdmin(s.apiUploadCert))
	mux.HandleFunc("POST /api/settings/test-feishu", s.requireAdmin(s.apiTestFeishu))
	mux.HandleFunc("POST /api/settings/check-naabu", s.requireAdmin(s.apiCheckNaabu))
	mux.HandleFunc("POST /api/settings/test-ai", s.requireAdmin(s.apiTestAI))

	mux.HandleFunc("GET /api/scans/{id}/live", s.auth(s.apiScanLive))
	mux.HandleFunc("GET /api/analysis/{id}", s.auth(s.apiAnalysisStatus))
	mux.HandleFunc("GET /api/logs", s.requireAdmin(s.apiLogs))
	mux.HandleFunc("POST /api/scans/{id}/{action}", s.requireWrite(s.apiScanControl))
	mux.HandleFunc("GET /api/status", s.auth(s.apiStatus))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		mux.ServeHTTP(w, r)
	})
}

// ---------- auth / RBAC / audit ----------

type ctxKey string

const ctxUserKey ctxKey = "user"

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.getSession(r)
		if !ok {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, 401, map[string]string{"error": "未登录"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserKey, sess)
		next(w, r.WithContext(ctx))
	}
}

// requireAdmin 仅允许 admin 角色访问（账号/审计/系统设置）
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r).role != "admin" {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, 403, map[string]string{"error": "需要管理员权限"})
				return
			}
			http.Error(w, "需要管理员权限", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func currentUser(r *http.Request) session {
	if v, ok := r.Context().Value(ctxUserKey).(session); ok {
		return v
	}
	return session{}
}

func (s *Server) getSession(r *http.Request) (session, bool) {
	c, err := r.Cookie("easm_sid")
	if err != nil {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok || time.Now().After(sess.exp) {
		delete(s.sessions, c.Value)
		return session{}, false
	}
	u, err := s.st.UserByName(sess.username)
	if err != nil || u == nil || !u.Enabled {
		delete(s.sessions, c.Value)
		return session{}, false
	}
	// 角色调整和停用账号应对已登录会话立即生效，不等待 12 小时会话过期。
	sess.userID = u.ID
	sess.role = u.Role
	s.sessions[c.Value] = sess
	return sess, true
}

func (s *Server) newSession(w http.ResponseWriter, u *store.User) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	sid := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[sid] = session{userID: u.ID, username: u.Username, role: u.Role, exp: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "easm_sid", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 12 * 3600})
}

// audit 记录一条操作审计（用户名/角色取自会话，IP 取自请求）
func (s *Server) audit(r *http.Request, action, target, detail string) {
	sess := currentUser(r)
	_ = s.st.Audit(sess.username, sess.role, action, target, detail, clientIP(r))
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

func (s *Server) doLogin(w http.ResponseWriter, r *http.Request) {
	u, err := s.st.Authenticate(strings.TrimSpace(r.FormValue("user")), r.FormValue("pass"))
	if err != nil || u == nil {
		s.render(w, "login.html", map[string]interface{}{"Title": "登录", "AppName": s.cfg.AppName, "Error": "用户名或密码错误"})
		return
	}
	s.newSession(w, u)
	_ = s.st.TouchUserLogin(u.ID)
	_ = s.st.Audit(u.Username, u.Role, "登录", "", "登录成功", clientIP(r))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) doLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("easm_sid"); err == nil {
		s.mu.Lock()
		sess := s.sessions[c.Value]
		delete(s.sessions, c.Value)
		s.mu.Unlock()
		if sess.username != "" {
			_ = s.st.Audit(sess.username, sess.role, "登出", "", "", clientIP(r))
		}
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ---------- render helpers ----------

// sectionOf 由导航高亮项派生页面所属「领域」，用于顶栏大标题上方的 eyebrow 与侧边栏分组，
// 使资产 / 扫描 / 防护 / 风险 / 分析 等子领域在视觉上各自独立、层级清晰。
func sectionOf(active string) string {
	switch active {
	case "index":
		return "概览"
	case "assets", "exposure":
		return "资产"
	case "tasks", "scans", "results":
		return "扫描"
	case "whitelist":
		return "防护"
	case "alerts":
		return "风险"
	case "analysis":
		return "分析"
	case "accounts", "audit", "logs", "settings":
		return "系统管理"
	default:
		return ""
	}
}

func (s *Server) baseData(r *http.Request, title, active string) (pageData, error) {
	n, err := s.st.NewAlertCount()
	if err != nil {
		return pageData{}, err
	}
	sess := currentUser(r)
	return pageData{Title: title, Section: sectionOf(active), Active: active, AppName: s.cfg.AppName, Version: buildinfo.Version, User: sess.username, Role: sess.role, IsAdmin: sess.role == "admin", NewAlerts: n}, nil
}

func (s *Server) render(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("模板渲染失败 %s: %v", name, err)
		http.Error(w, "渲染失败", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------- pages ----------

func (s *Server) pageLogin(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", map[string]interface{}{"Title": "登录", "AppName": s.cfg.AppName})
}

func (s *Server) pageIndex(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "仪表盘", "index")
	bd.Running = s.sc.IsRunning()
	targets, _ := s.st.Targets()
	scans, _ := s.st.Scans(6)
	alerts, _ := s.st.Alerts(8)
	scanCount, _ := s.st.CountScans()
	exposureCount, _ := s.st.CountExposures()
	data := struct {
		pageData
		TargetCount   int
		ScanCount     int
		ExposureCount int
		Scans         []store.Scan
		Alerts        []store.Alert
	}{bd, len(targets), scanCount, exposureCount, scans, alerts}
	s.render(w, "index.html", data)
}

func (s *Server) pageAssets(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "资产台账", "assets")
	targets, _ := s.st.Targets()
	allTags, _ := s.st.AllTags()
	curTag := r.URL.Query().Get("tag")
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	filter := r.URL.Query().Get("filter")
	if filter != "tagged" && filter != "untagged" {
		filter = ""
	}
	total := len(targets)
	targets = filterTargets(targets, query, curTag, filter)
	s.render(w, "assets.html", struct {
		pageData
		Targets []store.Target
		AllTags []string
		CurTag  string
		Query   string
		Filter  string
		Total   int
	}{bd, targets, allTags, curTag, query, filter, total})
}

func (s *Server) pageTasks(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "扫描任务", "tasks")
	tasks, _ := s.st.ScanTasks()
	runningScan, err := s.st.LatestRunningScan()
	if err != nil {
		http.Error(w, "读取任务进度失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	bd.Running = s.sc.IsRunning()
	if !bd.Running || runningScan == nil || runningScan.ID != s.sc.CurrentScanID() {
		runningScan = nil
	}
	s.render(w, "tasks.html", struct {
		pageData
		Tasks       []store.ScanTask
		RunningScan *store.Scan
	}{bd, tasks, runningScan})
}

func (s *Server) pageScans(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "执行记录", "scans")
	status := r.URL.Query().Get("status")
	switch status {
	case "", "running", "paused", "done", "partial", "stopped", "failed":
	default:
		status = ""
	}
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	mode := r.URL.Query().Get("mode")
	if mode != "full" && mode != "top" {
		mode = ""
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	scans, err := s.st.ScansFiltered(status, query, mode, taskID, 0)
	if err != nil {
		http.Error(w, "读取执行记录失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	bd.Running = s.sc.IsRunning()
	s.render(w, "scans.html", struct {
		pageData
		Scans  []store.Scan
		Status string
		Mode   string
		Query  string
		TaskID int64
	}{bd, scans, status, mode, query, taskID})
}

func (s *Server) pageScanDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	sc, err := s.st.Scan(id)
	if err != nil || sc == nil {
		http.Error(w, "扫描记录不存在", http.StatusNotFound)
		return
	}
	// 首屏结果只取固定硬上限一页；剩余结果由页面按游标续拉，
	// 因此 50 万行量级的执行也只会装载这一页，不会全量读入内存并拼进 HTML。
	results, err := s.st.ResultsPage(id, 0, scanDetailInitialResults)
	if err != nil {
		http.Error(w, "读取执行结果失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	events, err := s.st.ScanEvents(id, 0, 200)
	if err != nil {
		http.Error(w, "读取执行事件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var lastEventID int64
	for _, event := range events {
		if event.ID > lastEventID {
			lastEventID = event.ID
		}
	}
	// 总数来自 scans.result_count（单调累计），不以首屏行数为准；
	// 旧库 result_count 尚未回填时以后一页行数兜底，保证「已加载 / 共 N 条」不倒退。
	resultTotal := sc.ResultCount
	if resultTotal < len(results.Results) {
		resultTotal = len(results.Results)
	}
	bd, _ := s.baseData(r, "执行详情 #"+r.PathValue("id"), "scans")
	bd.Running = s.sc.IsRunning() && s.sc.CurrentScanID() == id
	s.render(w, "scan_detail.html", struct {
		pageData
		Scan             store.Scan
		Results          []store.Result
		ResultTotal      int
		NextCursor       int64
		HasMore          bool
		Events           []store.ScanEvent
		LastEventID      int64
		CapacityRejected bool
		CapacityAdvice   []string
	}{bd, *sc, results.Results, resultTotal, results.NextCursor, results.HasMore, events, lastEventID,
		isCapacityRejection(sc.Err), capacitySuggestions(sc.Err)})
}

func (s *Server) pageResults(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "扫描结果", "results")
	mode := r.URL.Query().Get("mode")
	if mode != "full" && mode != "top" {
		mode = ""
	}
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	scanID, _ := strconv.ParseInt(r.URL.Query().Get("scan_id"), 10, 64)
	port, _ := strconv.Atoi(r.URL.Query().Get("port"))
	if port < 1 || port > 65535 {
		port = 0
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	items, err := s.st.ResultsFiltered(query, mode, taskID, scanID, port, 2000)
	if err != nil {
		http.Error(w, "读取扫描结果失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "results.html", struct {
		pageData
		Items  []store.ScanResultRow
		Query  string
		Mode   string
		TaskID int64
		ScanID int64
		Port   int
	}{bd, items, query, mode, taskID, scanID, port})
}

func (s *Server) pageWhitelist(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "白名单", "whitelist")
	wl, _ := s.st.Whitelist()
	// 收集去重业务名，供白名单页按业务筛选
	seen := map[string]struct{}{}
	businesses := make([]string, 0)
	for _, e := range wl {
		b := strings.TrimSpace(e.Business)
		if b == "" {
			continue
		}
		if _, ok := seen[b]; ok {
			continue
		}
		seen[b] = struct{}{}
		businesses = append(businesses, b)
	}
	sort.Strings(businesses)
	s.render(w, "whitelist.html", struct {
		pageData
		Entries    []store.WLEntry
		Businesses []string
	}{bd, wl, businesses})
}

func (s *Server) pageAlerts(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "风险告警", "alerts")
	status := r.URL.Query().Get("status")
	if !validAlertStatus(status) {
		status = ""
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	alerts, _ := s.st.AlertsFiltered(status, query, 500)
	s.render(w, "alerts.html", struct {
		pageData
		Alerts []store.Alert
		Status string
		Query  string
	}{bd, alerts, status, query})
}

func (s *Server) pageSettings(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "系统设置", "settings")
	get := func(k, def string) string {
		if v := s.st.Setting(k); v != "" {
			return v
		}
		return def
	}
	certInfo, _ := cert.Inspect(s.cfg.TLSCert)
	s.render(w, "settings.html", struct {
		pageData
		FeishuWebhook     string
		FeishuSecret      string
		NaabuPath         string
		NaabuRate         string
		NaabuRetries      string
		NaabuWorkers      string
		NaabuTimeout      string
		NaabuScanType     string
		NaabuExcludePorts string
		NaabuInterface    string
		NaabuVerify       bool
		ScanTimeout       string
		ScanConcurrency   string
		RealertDays       string
		AlertOutOfScope   bool
		ResourceMonitor   bool
		ResourceCPU       string
		ResourceMemory    string
		ResourceDuration  string
		HTTPEnabled       bool
		Listen            string
		HTTPSEnabled      bool
		HTTPSListen       string
		TLSCert           string
		TLSKey            string
		TLSHosts          string
		ConfigPath        string
		CertInfo          *cert.Info
		AiEndpoint        string
		AiModel           string
		AiTimeout         string
		AiTemperature     string
		AiKeySet          bool
	}{
		pageData:          bd,
		FeishuWebhook:     get("feishu_webhook", ""),
		FeishuSecret:      get("feishu_secret", ""),
		NaabuPath:         get("naabu_path", s.cfg.NaabuPath),
		NaabuRate:         get("naabu_rate", s.cfg.NaabuRate),
		NaabuRetries:      get("naabu_retries", "2"),
		NaabuWorkers:      get("naabu_workers", "25"),
		NaabuTimeout:      get("naabu_timeout", "1s"),
		NaabuScanType:     get("naabu_scan_type", "c"),
		NaabuExcludePorts: get("naabu_exclude_ports", ""),
		NaabuInterface:    get("naabu_interface", ""),
		NaabuVerify:       get("naabu_verify", "0") == "1",
		ScanTimeout:       get("scan_timeout_min", "60"),
		ScanConcurrency:   get("scan_concurrency", "3"),
		RealertDays:       get("realert_days", strconv.Itoa(s.cfg.RealertDays)),
		AlertOutOfScope:   get("alert_out_of_scope", "1") == "1",
		ResourceMonitor:   get("resource_monitor", "1") == "1",
		ResourceCPU:       get("resource_cpu_percent", "90"),
		ResourceMemory:    get("resource_memory_mb", "1024"),
		ResourceDuration:  get("resource_duration_sec", "30"),
		HTTPEnabled:       s.cfg.HTTPEndpointEnabled(),
		Listen:            s.cfg.Listen,
		HTTPSEnabled:      s.cfg.HTTPSEnabled,
		HTTPSListen:       s.cfg.HTTPSListen,
		TLSCert:           s.cfg.TLSCert,
		TLSKey:            s.cfg.TLSKey,
		TLSHosts:          strings.Join(s.cfg.TLSHosts, ", "),
		ConfigPath:        s.cfg.Path(),
		CertInfo:          certInfo,
		AiEndpoint:        get("ai_endpoint", ""),
		AiModel:           get("ai_model", "gpt-4o-mini"),
		AiTimeout:         get("ai_timeout_sec", "60"),
		AiTemperature:     get("ai_temperature", "0.2"),
		AiKeySet:          s.st.Setting("ai_key") != "",
	})
}

// ---------- APIs ----------

// 导入列名候选（小写比较）：目标 / 维护人员 / 安全设备
var (
	targetColCandidates = []string{"公网ip", "公网地址", "弹性公网ip", "弹性ip", "eip", "ip地址", "ip", "public_ip", "public ip", "floating ip", "域名", "domain", "host", "主机", "主机名", "hostname", "目标", "资产", "地址", "target", "asset"}
	ownerColCandidates  = []string{"维护人员", "负责人", "owner", "联系人", "contact", "业务负责人", "责任人"}
	deviceColCandidates = []string{"安全设备", "安全设备标识", "security_device", "security device", "防护设备", "安全产品", "waf", "device"}
)

func matchImportCol(header string, candidates []string) bool {
	h := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(header, "\ufeff", "")))
	if h == "" {
		return false
	}
	for _, c := range candidates {
		if h == c {
			return true
		}
	}
	return false
}

// parseImportAssets 解析导入来源：文本框为纯目标（每行或逗号/空格分隔）；上传的 CSV/TXT/XLSX
// 支持结构化列（目标 + 维护人员 + 安全设备），按表头识别列，缺列或未提供则留空。支持域名。
func parseImportAssets(r *http.Request) ([]store.ImportAsset, []string, error) {
	var out []store.ImportAsset
	var invalid []string
	seen := map[string]bool{}
	add := func(raw, owner, device string) {
		raw = strings.TrimSpace(strings.ReplaceAll(raw, "\ufeff", ""))
		if raw == "" || strings.HasPrefix(raw, "#") || seen[raw] {
			return
		}
		kind, ok := engine.ClassifyTarget(raw)
		if !ok {
			if !matchImportCol(raw, targetColCandidates) && !matchImportCol(raw, ownerColCandidates) && !matchImportCol(raw, deviceColCandidates) {
				invalid = append(invalid, raw)
			}
			return
		}
		seen[raw] = true
		out = append(out, store.ImportAsset{Raw: raw, Kind: kind, Owner: strings.TrimSpace(owner), SecurityDevice: strings.TrimSpace(device)})
	}
	for _, l := range strings.Split(r.FormValue("ips"), "\n") {
		for _, p := range strings.FieldsFunc(l, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' || c == ';' }) {
			add(p, "", "")
		}
	}
	if file, hdr, err := r.FormFile("file"); err == nil {
		defer file.Close()
		if strings.TrimSpace(hdr.Filename) != "" {
			name := strings.ToLower(hdr.Filename)
			var records [][]string
			var ferr error
			if strings.HasSuffix(name, ".xlsx") || strings.HasSuffix(name, ".xlsm") {
				records, ferr = xlsxRows(file)
			} else {
				records, ferr = csvRows(file)
			}
			if ferr != nil {
				return nil, nil, ferr
			}
			tc, oc, dc, hasHeader := identifyImportColumns(records)
			start := 0
			if hasHeader {
				start = 1
			}
			for _, rec := range records[start:] {
				if tc >= len(rec) {
					continue
				}
				owner, device := "", ""
				if oc >= 0 && oc < len(rec) {
					owner = rec[oc]
				}
				if dc >= 0 && dc < len(rec) {
					device = rec[dc]
				}
				add(rec[tc], owner, device)
			}
		}
	}
	if len(out) == 0 {
		return nil, invalid, fmt.Errorf("未解析到合法目标（支持单 IP、CIDR 网段如 10.0.0.0/24、范围如 1.2.3.1-1.2.3.50、域名如 example.com）")
	}
	return out, invalid, nil
}

// identifyImportColumns 按表头识别 目标/维护人员/安全设备 列；无表头时目标列取合法目标占比最高者。
func identifyImportColumns(records [][]string) (targetCol, ownerCol, deviceCol int, hasHeader bool) {
	targetCol, ownerCol, deviceCol = 0, -1, -1
	if len(records) == 0 {
		return
	}
	matched := false
	for i, h := range records[0] {
		switch {
		case matchImportCol(h, targetColCandidates):
			targetCol, matched = i, true
		case matchImportCol(h, ownerColCandidates):
			ownerCol, matched = i, true
		case matchImportCol(h, deviceColCandidates):
			deviceCol, matched = i, true
		}
	}
	if matched {
		return targetCol, ownerCol, deviceCol, true
	}
	best, bestRatio := 0, 0.0
	maxCols := 0
	for _, row := range records {
		if len(row) > maxCols {
			maxCols = len(row)
		}
	}
	for i := 0; i < maxCols; i++ {
		total, valid := 0, 0
		for _, row := range records {
			if i >= len(row) {
				continue
			}
			if cell := strings.TrimSpace(row[i]); cell != "" {
				total++
				if _, ok := engine.ClassifyTarget(cell); ok {
					valid++
				}
			}
		}
		if total > 0 {
			if ratio := float64(valid) / float64(total); ratio >= 0.6 && ratio > bestRatio {
				best, bestRatio = i, ratio
			}
		}
	}
	return best, -1, -1, false
}

// csvRows 宽松解析 CSV/TXT 为结构化行（允许每行字段数不一致、容错裸引号）。
func csvRows(file multipart.File) ([][]string, error) {
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("CSV 解析失败: %v", err)
	}
	return records, nil
}

// xlsxRows 读取首个工作表的全部行为结构化行。
func xlsxRows(file multipart.File) ([][]string, error) {
	f, err := excelize.OpenReader(file)
	if err != nil {
		return nil, fmt.Errorf("xlsx 解析失败: %v", err)
	}
	defer f.Close()
	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, fmt.Errorf("xlsx 无工作表")
	}
	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("xlsx 无数据行")
	}
	return rows, nil
}

func (s *Server) apiImportAssets(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "导入资产", "", "tag="+strings.TrimSpace(r.FormValue("tag")))
	rows, invalid, err := parseImportAssets(r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	added, err := s.st.ImportAssets(rows, strings.TrimSpace(r.FormValue("tag")), "手动导入")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	invalidSample := invalid
	if len(invalidSample) > 5 {
		invalidSample = invalidSample[:5]
	}
	writeJSON(w, 200, map[string]interface{}{"parsed": len(rows), "added": added, "invalid": len(invalid), "invalid_sample": invalidSample})
}

func (s *Server) apiClearAssets(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "清空资产台账", "", "")
	if err := s.st.DeleteTargets(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// taskFromForm 从表单构建 ScanTask（不含 IPs，由 parseTaskIPs 单独校验后赋值）
func taskFromForm(r *http.Request) store.ScanTask {
	mode := r.FormValue("mode")
	if mode != "full" && mode != "custom" {
		mode = "top"
	}
	schedType := r.FormValue("sched_type")
	if schedType != "weekly" {
		schedType = "daily"
	}
	hour, _ := strconv.Atoi(r.FormValue("hour"))
	minute, _ := strconv.Atoi(r.FormValue("minute"))
	weekday, _ := strconv.Atoi(r.FormValue("weekday"))
	if hour < 0 || hour > 23 {
		hour = 2
	}
	if minute < 0 || minute > 59 {
		minute = 0
	}
	if weekday < 0 || weekday > 6 {
		weekday = -1
	}
	targetType := r.FormValue("target_type")
	if targetType == "" {
		if strings.TrimSpace(r.FormValue("ips")) != "" {
			targetType = "manual"
		} else {
			targetType = "all"
		}
	}
	return store.ScanTask{
		Name:         strings.TrimSpace(r.FormValue("name")),
		Mode:         mode,
		CustomPorts:  strings.TrimSpace(r.FormValue("custom_ports")),
		TargetType:   targetType,
		TargetTag:    strings.TrimSpace(r.FormValue("target_tag")),
		AddToLedger:  r.FormValue("add_to_ledger") == "on",
		SchedEnabled: r.FormValue("sched_enabled") == "on",
		SchedType:    schedType,
		Hour:         hour,
		Minute:       minute,
		Weekday:      weekday,
	}
}

// parseTaskIPs 清洗任务 IP 文本为换行分隔的合法规格；空表示扫描整个台账
func parseTaskIPs(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\ufeff", ""))
	if raw == "" {
		return "", nil
	}
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.FieldsFunc(raw, func(c rune) bool {
		return c == '\n' || c == '\r' || c == ',' || c == ' ' || c == '\t' || c == ';'
	}) {
		tok = strings.TrimSpace(tok)
		if tok == "" || seen[tok] {
			continue
		}
		if _, ok := engine.ClassifyTarget(tok); !ok {
			return "", fmt.Errorf("IP/网段/范围非法: %s（示例 1.2.3.4 / 10.0.0.0/24 / 1.2.3.1-1.2.3.50）", tok)
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return strings.Join(out, "\n"), nil
}

func prepareTask(r *http.Request, t *store.ScanTask) error {
	if t.Name == "" {
		return fmt.Errorf("请填写任务名称，便于后续复用和审计")
	}
	if t.Mode == "custom" {
		if err := scanner.ValidatePortList(t.CustomPorts, "自定义端口"); err != nil {
			return err
		}
	}
	if t.SchedEnabled && t.SchedType == "weekly" && t.Weekday < 0 {
		return fmt.Errorf("每周定时任务请选择星期")
	}
	switch t.TargetType {
	case "all":
		t.IPs = ""
		t.TargetTag = ""
		t.AddToLedger = false
	case "tag":
		if t.TargetTag == "" {
			return fmt.Errorf("请选择用于圈选资产的标签")
		}
		t.IPs = ""
		t.AddToLedger = false
	case "manual":
		ips, err := parseTaskIPs(r.FormValue("ips"))
		if err != nil {
			return err
		}
		if ips == "" {
			return fmt.Errorf("手工目标模式至少填写一个 IP/网段/范围")
		}
		t.IPs = ips
	default:
		return fmt.Errorf("未知目标类型: %s", t.TargetType)
	}
	return nil
}

func (s *Server) apiCreateTask(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "新建扫描任务", strings.TrimSpace(r.FormValue("name")), "")
	t := taskFromForm(r)
	if err := prepareTask(r, &t); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	id, err := s.st.CreateScanTask(t)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	resp := map[string]interface{}{"id": id}
	if r.FormValue("run_now") == "on" {
		// 与「运行」接口一致：启动流程放后台，立即返回 preparing + request_id，
		// 错误只能按该编号通过 run-status 读取，不会被后续启动请求覆盖。
		if requestID, msg, ok := s.beginBackgroundStart(id); !ok {
			resp["run_error"] = msg
			resp["request_id"] = ""
		} else {
			s.launchBackgroundStart(requestID, id)
			resp["task_id"] = id
			resp["request_id"] = requestID
			resp["preparing"] = true
			resp["status_url"] = startStatusPath(id, requestID)
		}
	}
	writeJSON(w, 200, resp)
}

func (s *Server) apiUpdateTask(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	s.audit(r, "修改扫描任务", "#"+r.PathValue("id"), "")
	t := taskFromForm(r)
	if err := prepareTask(r, &t); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	t.ID = id
	if err := s.st.UpdateScanTask(t); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiDeleteTask(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	s.audit(r, "删除扫描任务", "#"+r.PathValue("id"), "")
	if err := s.st.DeleteScanTask(id); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// parseWhitelistLines 解析白名单导入：每行 "IP[/CIDR] + 端口"，端口逗号分隔、支持范围；
// 兼容 "1.2.3.4 22,80"、"1.2.3.4,22,80"、"1.2.3.4:22,80"、行尾 tcp/udp。
func parseWhitelistLines(text string) ([]store.WLEntry, error) {
	var out []store.WLEntry
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\ufeff", ""))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := strings.FieldsFunc(line, func(c rune) bool {
			return c == ' ' || c == '\t' || c == ',' || c == ';'
		})
		if len(tokens) == 0 {
			continue
		}
		ipSpec := tokens[0]
		var ports []string
		// 首 token 可能是 "ip:port" 形式（仅当冒号前是合法白名单 IP、冒号后是端口时才拆）
		if idx := strings.LastIndex(ipSpec, ":"); idx > 0 {
			head, tail := ipSpec[:idx], ipSpec[idx+1:]
			if engine.ValidWhitelistIP(head) && isPortSpec(tail) {
				ipSpec = head
				ports = append(ports, tail)
			}
		}
		if !engine.ValidWhitelistIP(ipSpec) {
			return nil, fmt.Errorf("IP/网段非法: %s（白名单仅支持 单IP / CIDR / *）", ipSpec)
		}
		proto := "tcp"
		for _, tk := range tokens[1:] {
			switch strings.ToLower(tk) {
			case "tcp", "udp":
				proto = strings.ToLower(tk)
				continue
			case "*":
				proto = "*"
				continue
			}
			if !isPortSpec(tk) {
				return nil, fmt.Errorf("端口非法: %s（行: %s）", tk, line)
			}
			ports = append(ports, tk)
		}
		if len(ports) == 0 {
			return nil, fmt.Errorf("未解析到端口（行: %s）", line)
		}
		e := store.WLEntry{IPSpec: ipSpec, PortSpec: strings.Join(ports, ","), Proto: proto, Owner: "import"}
		if err := engine.ValidateEntry(e); err != nil {
			return nil, fmt.Errorf("条目校验失败（行: %s）: %v", line, err)
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("未解析到有效白名单条目")
	}
	return out, nil
}

// isPortSpec 判断是否为单端口 / 端口范围 / 通配
func isPortSpec(s string) bool {
	s = strings.TrimSpace(s)
	if s == "*" {
		return true
	}
	if strings.Contains(s, "-") {
		ab := strings.SplitN(s, "-", 2)
		return allDigits(ab[0]) && allDigits(ab[1])
	}
	return allDigits(s)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (s *Server) apiImportWhitelist(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "导入白名单", "", "")
	entries, err := parseWhitelistLines(r.FormValue("entries"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	n := 0
	for _, e := range entries {
		if _, err := s.st.AddWhitelist(e); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		n++
	}
	writeJSON(w, 200, map[string]interface{}{"parsed": len(entries), "added": n})
}

func (s *Server) apiBaseline(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "生成白名单基线", "", "")
	n, err := s.eng.Baseline()
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"added": n})
}

func (s *Server) apiAddWhitelist(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "新增白名单", strings.TrimSpace(r.FormValue("ip_spec"))+":"+strings.TrimSpace(r.FormValue("port_spec")), "")
	e := store.WLEntry{
		IPSpec:   strings.TrimSpace(r.FormValue("ip_spec")),
		PortSpec: strings.TrimSpace(r.FormValue("port_spec")),
		Proto:    strings.TrimSpace(r.FormValue("proto")),
		Service:  strings.TrimSpace(r.FormValue("service")),
		Owner:    strings.TrimSpace(r.FormValue("owner")),
		Remark:   strings.TrimSpace(r.FormValue("remark")),
		Business: strings.TrimSpace(r.FormValue("business")),
	}
	if err := engine.ValidateEntry(e); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if _, err := s.st.AddWhitelist(e); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiDelWhitelist(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	s.audit(r, "删除白名单", "#"+r.PathValue("id"), "")
	if err := s.st.DeleteWhitelist(id); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiAckAlert(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	s.audit(r, "处理告警", "#"+r.PathValue("id"), "")
	if err := s.st.AckAlert(id); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// apiSaveSettings 按类别部分更新系统设置：请求提交了哪一类字段，就只校验并保存哪一类，
// 未提交的类别保持原值不变。前端「通知与告警 / naabu 参数 / 资源监测 / AI 分析」各自独立表单，
// 均 POST 到本接口而互不覆盖；SaveSettings 只写入 pairs 中存在的键，天然支持部分保存。
func (s *Server) apiSaveSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "表单解析失败"})
		return
	}
	has := func(key string) bool { _, ok := r.PostForm[key]; return ok }
	val := func(key string) string { return strings.TrimSpace(r.PostFormValue(key)) }
	onOff := func(key string) string {
		if r.PostFormValue(key) == "on" {
			return "1"
		}
		return "0"
	}
	pairs := map[string]string{}

	// 通知与告警
	if has("feishu_webhook") || has("feishu_secret") || has("realert_days") || has("alert_out_of_scope") {
		pairs["feishu_webhook"] = val("feishu_webhook")
		pairs["feishu_secret"] = val("feishu_secret")
		pairs["alert_out_of_scope"] = onOff("alert_out_of_scope")
		if has("realert_days") {
			if days, err := strconv.Atoi(val("realert_days")); err != nil || days < 1 || days > 3650 {
				writeJSON(w, 400, map[string]string{"error": "配置未保存：重告警周期必须是 1-3650 的整数天数"})
				return
			}
			pairs["realert_days"] = val("realert_days")
		}
	}

	// naabu 参数 + 资源监测
	if has("naabu_path") {
		settings := scanner.NaabuSettings{
			Path: val("naabu_path"), Rate: val("naabu_rate"), Retries: val("naabu_retries"),
			Workers: val("naabu_workers"), ResponseTimeout: val("naabu_timeout"), OverallTimeout: val("scan_timeout_min"),
			Concurrency: val("scan_concurrency"),
			ScanType:    strings.ToLower(val("naabu_scan_type")), ExcludePorts: val("naabu_exclude_ports"), Interface: val("naabu_interface"),
			Verify:          r.PostFormValue("naabu_verify") == "on",
			ResourceMonitor: r.PostFormValue("resource_monitor") == "on", ResourceCPU: val("resource_cpu_percent"),
			ResourceMemory: val("resource_memory_mb"), ResourceDuration: val("resource_duration_sec"),
		}
		if err := settings.Validate(); err != nil {
			writeJSON(w, 400, map[string]string{"error": "配置未保存：" + err.Error()})
			return
		}
		pairs["naabu_path"] = settings.Path
		pairs["naabu_rate"] = settings.Rate
		pairs["naabu_retries"] = settings.Retries
		pairs["naabu_workers"] = settings.Workers
		pairs["naabu_timeout"] = settings.ResponseTimeout
		pairs["scan_timeout_min"] = settings.OverallTimeout
		pairs["scan_concurrency"] = settings.Concurrency
		pairs["naabu_scan_type"] = settings.ScanType
		pairs["naabu_exclude_ports"] = settings.ExcludePorts
		pairs["naabu_interface"] = settings.Interface
		pairs["naabu_verify"] = onOff("naabu_verify")
		pairs["resource_monitor"] = onOff("resource_monitor")
		pairs["resource_cpu_percent"] = settings.ResourceCPU
		pairs["resource_memory_mb"] = settings.ResourceMemory
		pairs["resource_duration_sec"] = settings.ResourceDuration
	}

	// AI 分析
	if has("ai_endpoint") || has("ai_model") || has("ai_timeout_sec") || has("ai_temperature") || has("ai_key") {
		if ep := val("ai_endpoint"); ep != "" {
			if err := ai.ValidateEndpoint(ep); err != nil {
				writeJSON(w, 400, map[string]string{"error": "配置未保存：" + err.Error()})
				return
			}
		}
		if v := val("ai_timeout_sec"); v != "" {
			if n, err := strconv.Atoi(v); err != nil || n < 5 || n > 600 {
				writeJSON(w, 400, map[string]string{"error": "配置未保存：AI 超时必须是 5-600 秒的整数"})
				return
			}
		}
		if v := val("ai_temperature"); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err != nil || f < 0 || f > 2 {
				writeJSON(w, 400, map[string]string{"error": "配置未保存：AI 温度必须是 0-2 之间的数值"})
				return
			}
		}
		pairs["ai_endpoint"] = val("ai_endpoint")
		pairs["ai_model"] = val("ai_model")
		pairs["ai_timeout_sec"] = val("ai_timeout_sec")
		pairs["ai_temperature"] = val("ai_temperature")
		// AI Token 留空表示不修改（避免每次保存清空已存密钥）
		if k := val("ai_key"); k != "" {
			pairs["ai_key"] = k
		}
	}

	if len(pairs) == 0 {
		writeJSON(w, 400, map[string]string{"error": "没有可保存的配置项"})
		return
	}
	if err := s.st.SaveSettings(pairs); err != nil {
		writeJSON(w, 500, map[string]string{"error": "配置未保存，数据库写入失败：" + err.Error()})
		return
	}
	s.audit(r, "修改系统设置", "", fmt.Sprintf("更新 %d 项配置", len(pairs)))
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiTestFeishu(w http.ResponseWriter, r *http.Request) {
	nf := &notify.Feishu{Webhook: s.st.Setting("feishu_webhook"), Secret: s.st.Setting("feishu_secret")}
	if nf.Webhook == "" {
		writeJSON(w, 400, map[string]string{"error": "未配置飞书 webhook"})
		return
	}
	if err := nf.Send("【灵瞰 EASM 测试告警】这是一条测试消息，收到即代表飞书通道正常。时间: " + time.Now().Format("2006-01-02 15:04:05")); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// apiCheckNaabu 供“系统设置”页手动自检 naabu 是否就绪，复用扫描前的同一检测逻辑。
func (s *Server) apiCheckNaabu(w http.ResponseWriter, r *http.Request) {
	path, version, err := s.sc.CheckNaabu()
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"path": path, "version": version})
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	scanID := s.sc.CurrentScanID()
	response := map[string]interface{}{"running": s.sc.IsRunning(), "scan_id": scanID}
	if scanID > 0 {
		if scan, err := s.st.Scan(scanID); err == nil && scan != nil {
			response["name"] = scan.Name
			response["mode"] = scan.Mode
			response["target_count"] = scan.TargetCount
			response["processed_targets"] = scan.ProcessedTargets
			response["remaining_targets"] = scan.RemainingTargets()
			response["failed_targets"] = scan.FailedTargets
			response["current_batch"] = scan.CurrentBatch
			response["total_batches"] = scan.TotalBatches
			response["open_ports"] = scan.OpenPorts
			response["status"] = scan.Status
			response["paused"] = scan.Status == "paused"
			response["cpu_percent"] = scan.CPUPercent
			response["memory_rss"] = scan.MemoryRSS
			response["max_cpu_percent"] = scan.MaxCPUPercent
			response["max_memory_rss"] = scan.MaxMemoryRSS
		}
	}
	writeJSON(w, 200, response)
}
