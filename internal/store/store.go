package store

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Target struct {
	ID             int64
	IP             string // 主标识：单 IP / CIDR / 范围 / 域名（域名资产以域名填充，保证唯一并供 naabu 直接扫描）
	Kind           string // ip | cidr | range | domain
	Tags           string // 逗号分隔标签
	Source         string
	CreatedAt      string
	Domain         string // 域名资产独立存储；IP 类资产为空
	Owner          string // 维护人员 / 业务负责人
	SecurityDevice string // 安全设备标识（WAF / 云盾 / 防火墙等，自由文本）
}

// ImportAsset 是导入 / 新增单条资产的输入行（含可选维护信息）。
type ImportAsset struct {
	Raw            string
	Kind           string
	Owner          string
	SecurityDevice string
}

type Scan struct {
	ID               int64   `json:"id"`
	TaskID           int64   `json:"task_id"`
	Name             string  `json:"name"`
	Mode             string  `json:"mode"`
	Status           string  `json:"status"`
	StartedAt        string  `json:"started_at"`
	FinishedAt       string  `json:"finished_at"`
	OpenPorts        int     `json:"open_ports"`
	Err              string  `json:"error"`
	TargetCount      int     `json:"target_count"`
	ProcessedTargets int     `json:"processed_targets"`
	FailedTargets    int     `json:"failed_targets"`
	CurrentBatch     int     `json:"current_batch"`
	TotalBatches     int     `json:"total_batches"`
	Command          string  `json:"command"`
	CPUPercent       float64 `json:"cpu_percent"`
	MemoryRSS        int64   `json:"memory_rss"`
	MaxCPUPercent    float64 `json:"max_cpu_percent"`
	MaxMemoryRSS     int64   `json:"max_memory_rss"`
}

// ScanResultRow 是带执行来源的端口结果，供跨任务查询和按扫描模式区分。
type ScanResultRow struct {
	Result
	ScanID    int64
	TaskID    int64
	ScanName  string
	ScanMode  string
	StartedAt string
}

func (s Scan) RemainingTargets() int {
	remaining := s.TargetCount - s.ProcessedTargets
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (s Scan) ProgressPercent() int {
	if s.TargetCount <= 0 {
		return 0
	}
	percent := s.ProcessedTargets * 100 / s.TargetCount
	if percent > 100 {
		return 100
	}
	return percent
}

type Result struct {
	ID      int64  `json:"id"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Status  int    `json:"status"` // 1=开放, 0=未开放
}

// ScanEvent 记录扫描控制与资源事件，不与开放端口风险告警混用。
type ScanEvent struct {
	ID      int64  `json:"id"`
	ScanID  int64  `json:"scan_id"`
	Ts      string `json:"ts"`
	Level   string `json:"level"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Exposure 是跨扫描聚合的开放端口资产，时间表示首次/最近被探明，而非实时在线状态。
type Exposure struct {
	IP          string
	Port        int
	Proto       string
	Service     string
	FirstSeenAt string
	LastSeenAt  string
	LastScanID  int64
	SeenCount   int
	AlertStatus string
	Whitelisted bool
}

// TargetSpec 台账目标：原始文本 + 类型(ip/cidr/range)
type TargetSpec struct {
	Raw  string
	Kind string
}

// ScanTask 可复用/可定时的扫描任务定义；IPs 为空表示扫描整个台账
type ScanTask struct {
	ID           int64
	Name         string
	Mode         string
	CustomPorts  string // mode==custom 时的端口规格，如 22,80,443,8000-9000
	TargetType   string // all | tag | manual
	TargetTag    string
	IPs          string // manual 模式：换行分隔的目标规格(ip/cidr/range)
	AddToLedger  bool
	SchedEnabled bool
	SchedType    string // daily | weekly
	Hour         int
	Minute       int
	Weekday      int // weekly 时生效，0=周日
	CreatedAt    string
	LastRun      string
}

// User 后台账号（密码以 PBKDF2-SHA256 加盐哈希存储）
type User struct {
	ID          int64
	Username    string
	PassHash    string
	Role        string // admin | operator | viewer
	DisplayName string
	Enabled     bool
	CreatedAt   string
	LastLogin   string
}

// AuditLog 操作审计记录
type AuditLog struct {
	ID       int64
	Ts       string
	Username string
	Role     string
	Action   string
	Target   string
	Detail   string
	IP       string
}

type WLEntry struct {
	ID        int64
	IPSpec    string
	PortSpec  string
	Proto     string
	Service   string
	Owner     string
	Remark    string
	Business  string
	CreatedAt string
}

type Alert struct {
	ID          int64
	IP          string
	Port        int
	Proto       string
	Service     string
	InScope     bool
	Status      string // new | acked | resolved | ignored
	FirstSeenAt string
	LastSeenAt  string
	SentFeishu  bool
	CreatedAt   string
	Handler     string
	HandleNote  string
	HandledAt   string
}

type Schedule struct {
	ID        int64
	Name      string
	Mode      string
	SchedType string
	Hour      int
	Minute    int
	Weekday   int
	Enabled   bool
	LastRun   string
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return nil, err
	}
	// 并发写入（如后台清库与运行中服务同时访问）时等待锁而不是立即报 SQLITE_BUSY。
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		return nil, err
	}
	schema := `
CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE, kind TEXT DEFAULT 'ip', tags TEXT DEFAULT '', source TEXT DEFAULT '', created_at TEXT, domain TEXT DEFAULT '', owner TEXT DEFAULT '', security_device TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER DEFAULT 0, name TEXT DEFAULT '', mode TEXT, status TEXT, started_at TEXT, finished_at TEXT, open_ports INTEGER DEFAULT 0, error TEXT DEFAULT '', target_count INTEGER DEFAULT 0, command TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS scan_results (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, ip TEXT, port INTEGER, proto TEXT DEFAULT 'tcp', service TEXT DEFAULT '', status INTEGER DEFAULT 1, UNIQUE(scan_id, ip, port, proto));
CREATE TABLE IF NOT EXISTS whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_spec TEXT, port_spec TEXT, proto TEXT DEFAULT '*', service TEXT DEFAULT '', owner TEXT DEFAULT '', remark TEXT DEFAULT '', business TEXT DEFAULT '', created_at TEXT);
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER, proto TEXT DEFAULT 'tcp', service TEXT DEFAULT '', in_scope INTEGER DEFAULT 1, status TEXT DEFAULT 'new', first_seen_at TEXT, last_seen_at TEXT, sent_feishu INTEGER DEFAULT 0, created_at TEXT, handler TEXT DEFAULT '', handle_note TEXT DEFAULT '', handled_at TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS schedules (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, mode TEXT, sched_type TEXT, hour INTEGER, minute INTEGER, weekday INTEGER DEFAULT -1, enabled INTEGER DEFAULT 1, last_run TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS scan_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT DEFAULT '', mode TEXT DEFAULT 'top', custom_ports TEXT DEFAULT '', target_type TEXT DEFAULT 'all', target_tag TEXT DEFAULT '', ips TEXT DEFAULT '', add_to_ledger INTEGER DEFAULT 0, sched_enabled INTEGER DEFAULT 0, sched_type TEXT DEFAULT 'daily', hour INTEGER DEFAULT 2, minute INTEGER DEFAULT 0, weekday INTEGER DEFAULT -1, created_at TEXT DEFAULT '', last_run TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, pass_hash TEXT NOT NULL, role TEXT DEFAULT 'operator', display_name TEXT DEFAULT '', enabled INTEGER DEFAULT 1, created_at TEXT DEFAULT '', last_login TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT DEFAULT '', username TEXT DEFAULT '', role TEXT DEFAULT '', action TEXT DEFAULT '', target TEXT DEFAULT '', detail TEXT DEFAULT '', ip TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS scan_events (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, ts TEXT DEFAULT '', level TEXT DEFAULT 'info', type TEXT DEFAULT '', message TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS analysis (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT DEFAULT '', source_type TEXT DEFAULT '', status TEXT DEFAULT 'pending', created_at TEXT DEFAULT '', finished_at TEXT DEFAULT '', error TEXT DEFAULT '', flow_count INTEGER DEFAULT 0, edge_count INTEGER DEFAULT 0, file_count INTEGER DEFAULT 0, ai_model TEXT DEFAULT '', ai_endpoint TEXT DEFAULT '', summary TEXT DEFAULT '', readable TEXT DEFAULT '', topology_json TEXT DEFAULT '', anomalies_json TEXT DEFAULT '', trace_json TEXT DEFAULT '', used_mock INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS analysis_files (id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER NOT NULL, filename TEXT DEFAULT '', size INTEGER DEFAULT 0, format TEXT DEFAULT '', stored_path TEXT DEFAULT '', rows_parsed INTEGER DEFAULT 0, uploaded_at TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS analysis_edges (id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER NOT NULL, src_ip TEXT DEFAULT '', dst_ip TEXT DEFAULT '', dst_port INTEGER DEFAULT 0, proto TEXT DEFAULT '', action TEXT DEFAULT '', count INTEGER DEFAULT 0, first_seen TEXT DEFAULT '', last_seen TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_results_scan ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_results_exposure ON scan_results(ip, port, proto, status);
CREATE INDEX IF NOT EXISTS idx_alerts_key ON alerts(ip, port, proto);
CREATE INDEX IF NOT EXISTS idx_analysis_files ON analysis_files(analysis_id);
CREATE INDEX IF NOT EXISTS idx_analysis_edges ON analysis_edges(analysis_id);
`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	// 轻量迁移：为已存在的旧库补充新列（列已存在时忽略）
	for _, m := range []string{
		`ALTER TABLE targets ADD COLUMN kind TEXT DEFAULT 'ip'`,
		`ALTER TABLE targets ADD COLUMN tags TEXT DEFAULT ''`,
		`ALTER TABLE targets ADD COLUMN domain TEXT DEFAULT ''`,
		`ALTER TABLE targets ADD COLUMN owner TEXT DEFAULT ''`,
		`ALTER TABLE targets ADD COLUMN security_device TEXT DEFAULT ''`,
		`ALTER TABLE scans ADD COLUMN task_id INTEGER DEFAULT 0`,
		`ALTER TABLE scans ADD COLUMN name TEXT DEFAULT ''`,
		`ALTER TABLE scans ADD COLUMN target_count INTEGER DEFAULT 0`,
		`ALTER TABLE scans ADD COLUMN processed_targets INTEGER DEFAULT 0`,
		`ALTER TABLE scans ADD COLUMN failed_targets INTEGER DEFAULT 0`,
		`ALTER TABLE scans ADD COLUMN current_batch INTEGER DEFAULT 0`,
		`ALTER TABLE scans ADD COLUMN total_batches INTEGER DEFAULT 0`,
		`ALTER TABLE scans ADD COLUMN command TEXT DEFAULT ''`,
		`ALTER TABLE scans ADD COLUMN cpu_percent REAL DEFAULT 0`,
		`ALTER TABLE scans ADD COLUMN memory_rss INTEGER DEFAULT 0`,
		`ALTER TABLE scans ADD COLUMN max_cpu_percent REAL DEFAULT 0`,
		`ALTER TABLE scans ADD COLUMN max_memory_rss INTEGER DEFAULT 0`,
		`ALTER TABLE scan_results ADD COLUMN status INTEGER DEFAULT 1`,
		`ALTER TABLE scan_tasks ADD COLUMN target_type TEXT DEFAULT ''`,
		`ALTER TABLE scan_tasks ADD COLUMN target_tag TEXT DEFAULT ''`,
		`ALTER TABLE scan_tasks ADD COLUMN custom_ports TEXT DEFAULT ''`,
		`ALTER TABLE whitelist ADD COLUMN business TEXT DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN handler TEXT DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN handle_note TEXT DEFAULT ''`,
		`ALTER TABLE alerts ADD COLUMN handled_at TEXT DEFAULT ''`,
	} {
		if _, err := db.Exec(m); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("schema 迁移忽略: %v", err)
		}
	}
	return &Store{db: db}, nil
}

func now() string { return time.Now().Format(time.RFC3339) }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------- targets ----------
// ImportAssets 导入一批资产；batchTag 非空时作为本批标签（已存在的资产会并入该标签）。
// 域名资产（Kind==domain）同时写入独立的 domain 列；owner/security_device 仅在新增时写入，
// 重复导入不覆盖已有维护信息。返回真正新增的数量（INSERT OR IGNORE 忽略的重复项不计）。
func (s *Store) ImportAssets(rows []ImportAsset, batchTag, source string) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	batchTag = strings.TrimSpace(batchTag)
	n := 0
	for _, row := range rows {
		domain := ""
		if row.Kind == "domain" {
			domain = row.Raw
		}
		res, err := tx.Exec(`INSERT OR IGNORE INTO targets(ip, kind, tags, source, created_at, domain, owner, security_device) VALUES(?,?,?,?,?,?,?,?)`,
			row.Raw, row.Kind, batchTag, source, now(), domain, strings.TrimSpace(row.Owner), strings.TrimSpace(row.SecurityDevice))
		if err != nil {
			return 0, err
		}
		if aff, _ := res.RowsAffected(); aff > 0 {
			n++
		} else if batchTag != "" {
			var existing string
			_ = tx.QueryRow(`SELECT COALESCE(tags,'') FROM targets WHERE ip=?`, row.Raw).Scan(&existing)
			if merged := mergeTags(existing, batchTag); merged != existing {
				if _, err := tx.Exec(`UPDATE targets SET tags=? WHERE ip=?`, merged, row.Raw); err != nil {
					return 0, err
				}
			}
		}
	}
	return n, tx.Commit()
}

// ImportTargets 兼容旧调用（如扫描任务手工目标入台账）：仅目标规格，无维护信息。
func (s *Store) ImportTargets(specs []TargetSpec, tag, source string) (int, error) {
	rows := make([]ImportAsset, 0, len(specs))
	for _, sp := range specs {
		rows = append(rows, ImportAsset{Raw: sp.Raw, Kind: sp.Kind})
	}
	return s.ImportAssets(rows, tag, source)
}

// UpdateTargetMeta 更新单条资产的维护人员、安全设备与标签（不改动 IP/域名主标识）。
func (s *Store) UpdateTargetMeta(id int64, owner, device, tags string) error {
	_, err := s.db.Exec(`UPDATE targets SET owner=?, security_device=?, tags=? WHERE id=?`,
		strings.TrimSpace(owner), strings.TrimSpace(device), mergeTags("", tags), id)
	return err
}

// mergeTags 把 tag 并入逗号分隔列表（去重、去空）
func mergeTags(existing, tag string) string {
	var set []string
	seen := map[string]bool{}
	for _, t := range strings.Split(existing+","+tag, ",") {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		set = append(set, t)
	}
	return strings.Join(set, ",")
}

func (s *Store) Targets() ([]Target, error) {
	rows, err := s.db.Query(`SELECT id, COALESCE(ip,''), COALESCE(kind,'ip'), COALESCE(tags,''), COALESCE(source,''), COALESCE(created_at,''),
		COALESCE(domain,''), COALESCE(owner,''), COALESCE(security_device,'') FROM targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.IP, &t.Kind, &t.Tags, &t.Source, &t.CreatedAt, &t.Domain, &t.Owner, &t.SecurityDevice); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TargetsByTag 按单个标签精确圈选台账资产，供扫描任务使用。
func (s *Store) TargetsByTag(tag string) ([]Target, error) {
	targets, err := s.Targets()
	if err != nil {
		return nil, err
	}
	tag = strings.TrimSpace(tag)
	out := make([]Target, 0)
	for _, t := range targets {
		for _, candidate := range strings.Split(t.Tags, ",") {
			if strings.TrimSpace(candidate) == tag {
				out = append(out, t)
				break
			}
		}
	}
	return out, nil
}

// SetTargetTags 直接设置某目标的标签（逗号分隔）
func (s *Store) SetTargetTags(id int64, tags string) error {
	_, err := s.db.Exec(`UPDATE targets SET tags=? WHERE id=?`, strings.TrimSpace(tags), id)
	return err
}

// SetTargetTagsBatch 批量修改标签：appendMode=false 覆盖（tags 为空即清除），true 追加合并；返回实际更新的资产数。
func (s *Store) SetTargetTagsBatch(ids []int64, tags string, appendMode bool) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	updated := 0
	for _, id := range ids {
		final := mergeTags("", tags) // 覆盖模式：清洗去重
		if appendMode {
			var existing string
			err := tx.QueryRow(`SELECT COALESCE(tags,'') FROM targets WHERE id=?`, id).Scan(&existing)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return 0, err
			}
			final = mergeTags(existing, tags)
		}
		res, err := tx.Exec(`UPDATE targets SET tags=? WHERE id=?`, final, id)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			updated++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return updated, nil
}

// TargetIDsByIPs 按精确 IP 匹配台账资产 ID（用于告警批量改关联资产标签）。
// 注：CIDR / 范围类资产的存储规格与具体告警 IP 不相等，不参与精确匹配。
func (s *Store) TargetIDsByIPs(ips []string) ([]int64, error) {
	seen := map[string]bool{}
	uniq := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		uniq = append(uniq, ip)
	}
	if len(uniq) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(uniq)), ",")
	args := make([]interface{}, len(uniq))
	for i, ip := range uniq {
		args[i] = ip
	}
	rows, err := s.db.Query(`SELECT id FROM targets WHERE ip IN (`+placeholders+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) DeleteTarget(id int64) error {
	_, err := s.db.Exec(`DELETE FROM targets WHERE id=?`, id)
	return err
}

// AllTags 返回台账中出现过的全部标签（去重、排序）
func (s *Store) AllTags() ([]string, error) {
	rows, err := s.db.Query(`SELECT COALESCE(tags,'') FROM targets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var tags string
		if err := rows.Scan(&tags); err != nil {
			return nil, err
		}
		for _, t := range strings.Split(tags, ",") {
			if t = strings.TrimSpace(t); t != "" && !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out, rows.Err()
}

func (s *Store) TargetIPSet() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT ip FROM targets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		m[ip] = true
	}
	return m, rows.Err()
}

func (s *Store) DeleteTargets() error {
	_, err := s.db.Exec(`DELETE FROM targets`)
	return err
}

// ---------- scans ----------
func (s *Store) CreateScan(taskID int64, name, mode string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO scans(task_id, name, mode, status, started_at) VALUES(?,?,?,?,?)`, taskID, name, mode, "running", now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) StartScanExecution(id int64, targetCount, totalBatches int) error {
	_, err := s.db.Exec(`UPDATE scans SET target_count=?, total_batches=? WHERE id=?`, targetCount, totalBatches, id)
	return err
}

func (s *Store) UpdateScanProgress(id int64, processed, failed, currentBatch, openPorts int, command string) error {
	_, err := s.db.Exec(`UPDATE scans SET processed_targets=?, failed_targets=?, current_batch=?, open_ports=?, command=? WHERE id=?`,
		processed, failed, currentBatch, openPorts, command, id)
	return err
}

func (s *Store) FinishScanStatus(id int64, status string, openPorts int, scanErr string) error {
	if status == "done" {
		_, err := s.db.Exec(`UPDATE scans SET status=?, finished_at=?, open_ports=?, error=?,
			processed_targets=target_count, failed_targets=0, current_batch=total_batches WHERE id=?`, status, now(), openPorts, scanErr, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE scans SET status=?, finished_at=?, open_ports=?, error=? WHERE id=?`, status, now(), openPorts, scanErr, id)
	return err
}

func (s *Store) FinishScan(id int64, openPorts int, scanErr string) error {
	return s.FinishScanStatus(id, map[bool]string{true: "failed", false: "done"}[scanErr != ""], openPorts, scanErr)
}

// HealStaleScans 服务启动时把残留的 running/paused 执行修正为 stopped：
// 重启后内存中已无对应 naabu 进程，这些状态必然是悬空的。返回修正条数。
func (s *Store) HealStaleScans() (int64, error) {
	res, err := s.db.Exec(`UPDATE scans SET status='stopped', finished_at=?, error=? WHERE status IN ('running','paused')`,
		now(), "服务重启后自动修正：原扫描进程已不存在，状态置为已终止；已入库结果保留，不生成白名单比对和告警。")
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ForceStopScanIfActive 仅当执行仍处于 running/paused 时将其修正为 stopped（幂等：已结束的执行不受影响）。
func (s *Store) ForceStopScanIfActive(id int64, message string) error {
	_, err := s.db.Exec(`UPDATE scans SET status='stopped', finished_at=?, error=? WHERE id=? AND status IN ('running','paused')`,
		now(), message, id)
	return err
}

func (s *Store) Scans(limit int) ([]Scan, error) {
	return s.ScansFiltered("", "", "", 0, limit)
}

func (s *Store) ScansFiltered(status, query, mode string, taskID int64, limit int) ([]Scan, error) {
	where := []string{"1=1"}
	args := make([]interface{}, 0)
	if status == "active" {
		where = append(where, "status IN ('running','paused')")
	} else if status != "" {
		where = append(where, "status=?")
		args = append(args, status)
	}
	if taskID > 0 {
		where = append(where, "task_id=?")
		args = append(args, taskID)
	}
	if mode == "full" || mode == "top" || mode == "custom" {
		where = append(where, "mode=?")
		args = append(args, mode)
	}
	if query = strings.TrimSpace(query); query != "" {
		where = append(where, "(name LIKE ? OR CAST(id AS TEXT) LIKE ? OR error LIKE ? OR command LIKE ?)")
		like := "%" + query + "%"
		args = append(args, like, like, like, like)
	}
	sqlText := `SELECT id, task_id, COALESCE(name,''), COALESCE(mode,''), COALESCE(status,''), COALESCE(started_at,''),
		COALESCE(finished_at,''), COALESCE(open_ports,0), COALESCE(error,''), COALESCE(target_count,0),
		COALESCE(processed_targets,0), COALESCE(failed_targets,0), COALESCE(current_batch,0), COALESCE(total_batches,0), COALESCE(command,''),
		COALESCE(cpu_percent,0), COALESCE(memory_rss,0), COALESCE(max_cpu_percent,0), COALESCE(max_memory_rss,0)
		FROM scans WHERE ` + strings.Join(where, " AND ") + ` ORDER BY id DESC`
	if limit > 0 {
		sqlText += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		var sc Scan
		if err := rows.Scan(&sc.ID, &sc.TaskID, &sc.Name, &sc.Mode, &sc.Status, &sc.StartedAt, &sc.FinishedAt, &sc.OpenPorts, &sc.Err,
			&sc.TargetCount, &sc.ProcessedTargets, &sc.FailedTargets, &sc.CurrentBatch, &sc.TotalBatches, &sc.Command,
			&sc.CPUPercent, &sc.MemoryRSS, &sc.MaxCPUPercent, &sc.MaxMemoryRSS); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// Scan 返回单次扫描记录（不存在时返回 nil, nil）
func (s *Store) Scan(id int64) (*Scan, error) {
	var sc Scan
	err := s.db.QueryRow(`SELECT id, task_id, COALESCE(name,''), COALESCE(mode,''), COALESCE(status,''), COALESCE(started_at,''),
		COALESCE(finished_at,''), COALESCE(open_ports,0), COALESCE(error,''), COALESCE(target_count,0),
		COALESCE(processed_targets,0), COALESCE(failed_targets,0), COALESCE(current_batch,0), COALESCE(total_batches,0), COALESCE(command,''),
		COALESCE(cpu_percent,0), COALESCE(memory_rss,0), COALESCE(max_cpu_percent,0), COALESCE(max_memory_rss,0) FROM scans WHERE id=?`, id).
		Scan(&sc.ID, &sc.TaskID, &sc.Name, &sc.Mode, &sc.Status, &sc.StartedAt, &sc.FinishedAt, &sc.OpenPorts, &sc.Err,
			&sc.TargetCount, &sc.ProcessedTargets, &sc.FailedTargets, &sc.CurrentBatch, &sc.TotalBatches, &sc.Command,
			&sc.CPUPercent, &sc.MemoryRSS, &sc.MaxCPUPercent, &sc.MaxMemoryRSS)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sc, nil
}

func (s *Store) LatestRunningScan() (*Scan, error) {
	scans, err := s.ScansFiltered("active", "", "", 0, 1)
	if err != nil || len(scans) == 0 {
		return nil, err
	}
	return &scans[0], nil
}

func (s *Store) LatestDoneScan() (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM scans WHERE status='done' ORDER BY id DESC LIMIT 1`).Scan(&id)
	return id, err
}

func (s *Store) CountScans() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&n)
	return n, err
}

func (s *Store) InsertResults(scanID int64, results []Result) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range results {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO scan_results(scan_id, ip, port, proto, service, status) VALUES(?,?,?,?,?,?)`,
			scanID, r.IP, r.Port, r.Proto, r.Service, r.Status); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ResultsFiltered 查询跨执行端口结果，保留任务和扫描模式来源；limit<=0 表示不限制。
func (s *Store) ResultsFiltered(query, mode string, taskID, scanID int64, port, limit int) ([]ScanResultRow, error) {
	where := []string{"1=1"}
	args := make([]interface{}, 0)
	if query = strings.TrimSpace(query); query != "" {
		where = append(where, "(r.ip LIKE ? OR r.service LIKE ? OR sc.name LIKE ? OR CAST(sc.id AS TEXT) LIKE ?)")
		like := "%" + query + "%"
		args = append(args, like, like, like, like)
	}
	if mode == "full" || mode == "top" || mode == "custom" {
		where = append(where, "sc.mode=?")
		args = append(args, mode)
	}
	if taskID > 0 {
		where = append(where, "sc.task_id=?")
		args = append(args, taskID)
	}
	if scanID > 0 {
		where = append(where, "sc.id=?")
		args = append(args, scanID)
	}
	if port > 0 {
		where = append(where, "r.port=?")
		args = append(args, port)
	}
	sqlText := `SELECT r.ip, r.port, r.proto, COALESCE(r.service,''), r.status,
		sc.id, sc.task_id, COALESCE(sc.name,''), COALESCE(sc.mode,''), COALESCE(sc.started_at,'')
		FROM scan_results r JOIN scans sc ON sc.id=r.scan_id WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY sc.id DESC, r.ip, r.port`
	if limit > 0 {
		sqlText += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ScanResultRow, 0)
	for rows.Next() {
		var row ScanResultRow
		if err := rows.Scan(&row.IP, &row.Port, &row.Proto, &row.Service, &row.Status,
			&row.ScanID, &row.TaskID, &row.ScanName, &row.ScanMode, &row.StartedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Store) ResultsByScan(scanID int64) ([]Result, error) {
	rows, err := s.db.Query(`SELECT id, ip, port, proto, service, status FROM scan_results WHERE scan_id=? ORDER BY ip, port`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Result
	for rows.Next() {
		var r Result
		if err := rows.Scan(&r.ID, &r.IP, &r.Port, &r.Proto, &r.Service, &r.Status); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Exposures 聚合所有扫描中探明的开放端口；limit<=0 表示不限制，供导出使用。
func (s *Store) Exposures(query, proto string, port, limit int) ([]Exposure, error) {
	where := []string{"r.status=1"}
	args := make([]interface{}, 0)
	if query = strings.TrimSpace(query); query != "" {
		where = append(where, "(r.ip LIKE ? OR r.service LIKE ?)")
		like := "%" + query + "%"
		args = append(args, like, like)
	}
	if proto != "" {
		where = append(where, "r.proto=?")
		args = append(args, proto)
	}
	if port > 0 {
		where = append(where, "r.port=?")
		args = append(args, port)
	}
	sqlText := `SELECT r.ip, r.port, r.proto, COALESCE(MAX(NULLIF(r.service,'')), ''),
		MIN(sc.started_at), MAX(sc.started_at), MAX(r.scan_id), COUNT(DISTINCT r.scan_id),
		COALESCE((SELECT a.status FROM alerts a WHERE a.ip=r.ip AND a.port=r.port AND a.proto=r.proto ORDER BY a.id DESC LIMIT 1),'')
		FROM scan_results r JOIN scans sc ON sc.id=r.scan_id
		WHERE ` + strings.Join(where, " AND ") + `
		GROUP BY r.ip, r.port, r.proto ORDER BY MAX(sc.started_at) DESC, r.ip, r.port`
	if limit > 0 {
		sqlText += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Exposure
	for rows.Next() {
		var e Exposure
		if err := rows.Scan(&e.IP, &e.Port, &e.Proto, &e.Service, &e.FirstSeenAt, &e.LastSeenAt, &e.LastScanID, &e.SeenCount, &e.AlertStatus); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) CountExposures() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM (SELECT 1 FROM scan_results WHERE status=1 GROUP BY ip,port,proto)`).Scan(&n)
	return n, err
}

// ---------- whitelist ----------
func (s *Store) AddWhitelist(e WLEntry) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO whitelist(ip_spec, port_spec, proto, service, owner, remark, business, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		e.IPSpec, e.PortSpec, e.Proto, e.Service, e.Owner, e.Remark, e.Business, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) Whitelist() ([]WLEntry, error) {
	rows, err := s.db.Query(`SELECT id, ip_spec, port_spec, proto, service, owner, remark, COALESCE(business,''), created_at FROM whitelist ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WLEntry
	for rows.Next() {
		var e WLEntry
		if err := rows.Scan(&e.ID, &e.IPSpec, &e.PortSpec, &e.Proto, &e.Service, &e.Owner, &e.Remark, &e.Business, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) DeleteWhitelist(id int64) error {
	_, err := s.db.Exec(`DELETE FROM whitelist WHERE id=?`, id)
	return err
}

// ---------- alerts ----------
func (s *Store) AlertFind(ip string, port int, proto string) (*Alert, error) {
	return s.alertBy(`ip=? AND port=? AND proto=? ORDER BY id DESC LIMIT 1`, ip, port, proto)
}

func (s *Store) AlertByID(id int64) (*Alert, error) {
	return s.alertBy(`id=?`, id)
}

func (s *Store) alertBy(condition string, args ...interface{}) (*Alert, error) {
	var a Alert
	var inScope, sent int
	err := s.db.QueryRow(`SELECT id, ip, port, proto, COALESCE(service,''), in_scope, COALESCE(status,'new'),
		COALESCE(first_seen_at,''), COALESCE(last_seen_at,''), sent_feishu, COALESCE(created_at,''),
		COALESCE(handler,''), COALESCE(handle_note,''), COALESCE(handled_at,'') FROM alerts WHERE `+condition, args...).
		Scan(&a.ID, &a.IP, &a.Port, &a.Proto, &a.Service, &inScope, &a.Status, &a.FirstSeenAt, &a.LastSeenAt, &sent, &a.CreatedAt, &a.Handler, &a.HandleNote, &a.HandledAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.InScope = inScope == 1
	a.SentFeishu = sent == 1
	return &a, nil
}

func (s *Store) CreateAlert(ip string, port int, proto, service string, inScope bool) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO alerts(ip, port, proto, service, in_scope, status, first_seen_at, last_seen_at, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		ip, port, proto, service, map[bool]int{true: 1, false: 0}[inScope], "new", now(), now(), now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) TouchAlert(id int64) error {
	_, err := s.db.Exec(`UPDATE alerts SET last_seen_at=? WHERE id=?`, now(), id)
	return err
}

func (s *Store) MarkAlertSent(id int64) error {
	_, err := s.db.Exec(`UPDATE alerts SET sent_feishu=1 WHERE id=?`, id)
	return err
}

func (s *Store) Alerts(limit int) ([]Alert, error) {
	return s.AlertsFiltered("", "", limit)
}

func (s *Store) AlertsFiltered(status, query string, limit int) ([]Alert, error) {
	where := []string{"1=1"}
	args := make([]interface{}, 0)
	if status != "" {
		where = append(where, "status=?")
		args = append(args, status)
	}
	if query = strings.TrimSpace(query); query != "" {
		where = append(where, "(ip LIKE ? OR service LIKE ? OR CAST(port AS TEXT) LIKE ? OR handle_note LIKE ? OR handler LIKE ?)")
		like := "%" + query + "%"
		args = append(args, like, like, like, like, like)
	}
	sqlText := `SELECT id, ip, port, proto, service, in_scope, status, first_seen_at, last_seen_at, sent_feishu, created_at,
		COALESCE(handler,''), COALESCE(handle_note,''), COALESCE(handled_at,'') FROM alerts
		WHERE ` + strings.Join(where, " AND ") + ` ORDER BY id DESC`
	if limit > 0 {
		sqlText += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var inScope, sent int
		if err := rows.Scan(&a.ID, &a.IP, &a.Port, &a.Proto, &a.Service, &inScope, &a.Status, &a.FirstSeenAt, &a.LastSeenAt, &sent, &a.CreatedAt, &a.Handler, &a.HandleNote, &a.HandledAt); err != nil {
			return nil, err
		}
		a.InScope = inScope == 1
		a.SentFeishu = sent == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AckAlert(id int64) error {
	return s.UpdateAlertStatus(id, "acked", "", "")
}

func (s *Store) UpdateAlertStatus(id int64, status, note, handler string) error {
	if status == "new" {
		_, err := s.db.Exec(`UPDATE alerts SET status='new', handler='', handle_note='', handled_at='', sent_feishu=0 WHERE id=?`, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE alerts SET status=?, handle_note=?, handler=?, handled_at=? WHERE id=?`, status, strings.TrimSpace(note), handler, now(), id)
	return err
}

// UpdateAlertStatusBatch 批量处置多条告警，返回实际更新条数；语义与单条一致（new 会清空处置信息并重置推送标记）。
func (s *Store) UpdateAlertStatusBatch(ids []int64, status, note, handler string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	updated := 0
	for _, id := range ids {
		var res sql.Result
		if status == "new" {
			res, err = tx.Exec(`UPDATE alerts SET status='new', handler='', handle_note='', handled_at='', sent_feishu=0 WHERE id=?`, id)
		} else {
			res, err = tx.Exec(`UPDATE alerts SET status=?, handle_note=?, handler=?, handled_at=? WHERE id=?`, status, strings.TrimSpace(note), handler, now(), id)
		}
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			updated += int(n)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return updated, nil
}

// ReopenAlert 复用同一告警记录，避免每次重复告警都插入一行。
func (s *Store) ReopenAlert(id int64) error {
	_, err := s.db.Exec(`UPDATE alerts SET status='new', last_seen_at=?, sent_feishu=0, handler='', handle_note='', handled_at='' WHERE id=?`, now(), id)
	return err
}

func (s *Store) NewAlertCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE status='new'`).Scan(&n)
	return n, err
}

// ---------- schedules ----------
func (s *Store) Schedules() ([]Schedule, error) {
	rows, err := s.db.Query(`SELECT id, name, mode, sched_type, hour, minute, weekday, enabled, last_run FROM schedules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		var sc Schedule
		var enabled int
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.Mode, &sc.SchedType, &sc.Hour, &sc.Minute, &sc.Weekday, &enabled, &sc.LastRun); err != nil {
			return nil, err
		}
		sc.Enabled = enabled == 1
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *Store) SeedSchedules() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schedules`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO schedules(name, mode, sched_type, hour, minute, weekday) VALUES
		('每日常用端口扫描', 'top', 'daily', 2, 0, -1),
		('每周全端口扫描', 'full', 'weekly', 3, 0, 0)`)
	return err
}

func (s *Store) MarkScheduleRun(id int64) error {
	_, err := s.db.Exec(`UPDATE schedules SET last_run=? WHERE id=?`, now(), id)
	return err
}

// ---------- scan tasks ----------
func normalizeScanTask(t ScanTask) ScanTask {
	t.TargetTag = strings.TrimSpace(t.TargetTag)
	t.CustomPorts = strings.TrimSpace(t.CustomPorts)
	if t.Mode != "full" && t.Mode != "custom" {
		t.Mode = "top"
	}
	if t.Mode != "custom" {
		t.CustomPorts = ""
	}
	if t.TargetType == "" {
		if strings.TrimSpace(t.IPs) != "" {
			t.TargetType = "manual"
		} else {
			t.TargetType = "all"
		}
	}
	if t.TargetType != "all" && t.TargetType != "tag" && t.TargetType != "manual" {
		t.TargetType = "all"
	}
	return t
}

func (s *Store) CreateScanTask(t ScanTask) (int64, error) {
	t = normalizeScanTask(t)
	res, err := s.db.Exec(`INSERT INTO scan_tasks(name, mode, custom_ports, target_type, target_tag, ips, add_to_ledger, sched_enabled, sched_type, hour, minute, weekday, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.Name, t.Mode, t.CustomPorts, t.TargetType, t.TargetTag, t.IPs, b2i(t.AddToLedger), b2i(t.SchedEnabled), t.SchedType, t.Hour, t.Minute, t.Weekday, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateScanTask(t ScanTask) error {
	t = normalizeScanTask(t)
	_, err := s.db.Exec(`UPDATE scan_tasks SET name=?, mode=?, custom_ports=?, target_type=?, target_tag=?, ips=?, add_to_ledger=?, sched_enabled=?, sched_type=?, hour=?, minute=?, weekday=? WHERE id=?`,
		t.Name, t.Mode, t.CustomPorts, t.TargetType, t.TargetTag, t.IPs, b2i(t.AddToLedger), b2i(t.SchedEnabled), t.SchedType, t.Hour, t.Minute, t.Weekday, t.ID)
	return err
}

func (s *Store) ScanTasks() ([]ScanTask, error) {
	rows, err := s.db.Query(`SELECT id, name, mode, COALESCE(custom_ports,''), COALESCE(target_type,''), COALESCE(target_tag,''), ips, add_to_ledger, sched_enabled, sched_type, hour, minute, weekday, COALESCE(created_at,''), COALESCE(last_run,'') FROM scan_tasks ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanTask
	for rows.Next() {
		var t ScanTask
		var atl, se int
		if err := rows.Scan(&t.ID, &t.Name, &t.Mode, &t.CustomPorts, &t.TargetType, &t.TargetTag, &t.IPs, &atl, &se, &t.SchedType, &t.Hour, &t.Minute, &t.Weekday, &t.CreatedAt, &t.LastRun); err != nil {
			return nil, err
		}
		t.AddToLedger = atl == 1
		t.SchedEnabled = se == 1
		out = append(out, normalizeScanTask(t))
	}
	return out, rows.Err()
}

func (s *Store) ScanTask(id int64) (*ScanTask, error) {
	var t ScanTask
	var atl, se int
	err := s.db.QueryRow(`SELECT id, name, mode, COALESCE(custom_ports,''), COALESCE(target_type,''), COALESCE(target_tag,''), ips, add_to_ledger, sched_enabled, sched_type, hour, minute, weekday, COALESCE(created_at,''), COALESCE(last_run,'') FROM scan_tasks WHERE id=?`, id).
		Scan(&t.ID, &t.Name, &t.Mode, &t.CustomPorts, &t.TargetType, &t.TargetTag, &t.IPs, &atl, &se, &t.SchedType, &t.Hour, &t.Minute, &t.Weekday, &t.CreatedAt, &t.LastRun)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.AddToLedger = atl == 1
	t.SchedEnabled = se == 1
	t = normalizeScanTask(t)
	return &t, nil
}

func (s *Store) DeleteScanTask(id int64) error {
	_, err := s.db.Exec(`DELETE FROM scan_tasks WHERE id=?`, id)
	return err
}

func (s *Store) MarkScanTaskRun(id int64) error {
	_, err := s.db.Exec(`UPDATE scan_tasks SET last_run=? WHERE id=?`, now(), id)
	return err
}

// SeedScanTasks 首次启动时植入两个默认全台账任务模板。
// 默认不启用定时（sched_enabled=0），是否定时由运维在任务页手动勾选；
// 仍预置 sched_type/hour/weekday，勾选「启用定时」后即有合理默认值。
func (s *Store) SeedScanTasks() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM scan_tasks`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	ts := now()
	_, err := s.db.Exec(`INSERT INTO scan_tasks(name, mode, ips, sched_enabled, sched_type, hour, minute, weekday, created_at) VALUES
		('全台账·常用端口', 'top', '', 0, 'daily', 2, 0, -1, ?),
		('全台账·全端口', 'full', '', 0, 'weekly', 3, 0, 0, ?)`, ts, ts)
	return err
}

// ---------- users & auth ----------
const pbkdf2Iter = 120000

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%x$%x", pbkdf2Iter, salt, dk), nil
}

func verifyPassword(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return hmac.Equal(dk, want)
}

// EnsureAdmin 首次启动（users 表为空）时用 config 里的账号创建管理员
func (s *Store) EnsureAdmin(username, password string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if username == "" {
		username = "admin"
	}
	if password == "" {
		password = "admin123"
	}
	h, err := hashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO users(username, pass_hash, role, display_name, enabled, created_at) VALUES(?,?,?,?,1,?)`,
		username, h, "admin", "管理员", now())
	return err
}

func (s *Store) UserByName(username string) (*User, error) {
	var u User
	var en int
	err := s.db.QueryRow(`SELECT id, username, pass_hash, role, COALESCE(display_name,''), enabled, COALESCE(created_at,''), COALESCE(last_login,'') FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.DisplayName, &en, &u.CreatedAt, &u.LastLogin)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.Enabled = en == 1
	return &u, nil
}

// Authenticate 校验用户名密码，成功返回启用中的用户
func (s *Store) Authenticate(username, password string) (*User, error) {
	u, err := s.UserByName(username)
	if err != nil {
		return nil, err
	}
	if u == nil || !verifyPassword(password, u.PassHash) {
		return nil, fmt.Errorf("用户名或密码错误")
	}
	if !u.Enabled {
		return nil, fmt.Errorf("账号已停用，请联系管理员")
	}
	return u, nil
}

func (s *Store) Users() ([]User, error) {
	rows, err := s.db.Query(`SELECT id, username, role, COALESCE(display_name,''), enabled, COALESCE(created_at,''), COALESCE(last_login,'') FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var en int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.DisplayName, &en, &u.CreatedAt, &u.LastLogin); err != nil {
			return nil, err
		}
		u.Enabled = en == 1
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) CreateUser(username, password, role, displayName string) (int64, error) {
	h, err := hashPassword(password)
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`INSERT INTO users(username, pass_hash, role, display_name, enabled, created_at) VALUES(?,?,?,?,1,?)`,
		username, h, role, displayName, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateUser(id int64, role, displayName string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE users SET role=?, display_name=?, enabled=? WHERE id=?`, role, displayName, b2i(enabled), id)
	return err
}

func (s *Store) SetUserPassword(id int64, password string) error {
	h, err := hashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE users SET pass_hash=? WHERE id=?`, h, id)
	return err
}

func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) TouchUserLogin(id int64) error {
	_, err := s.db.Exec(`UPDATE users SET last_login=? WHERE id=?`, now(), id)
	return err
}

// CountEnabledAdmins 用于防止删除/停用最后一个管理员
func (s *Store) CountEnabledAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1`).Scan(&n)
	return n, err
}

// ---------- audit ----------
func (s *Store) Audit(username, role, action, target, detail, ip string) error {
	_, err := s.db.Exec(`INSERT INTO audit_log(ts, username, role, action, target, detail, ip) VALUES(?,?,?,?,?,?,?)`,
		now(), username, role, action, target, detail, ip)
	if err != nil {
		log.Printf("写审计日志失败: %v", err)
	}
	return err
}

func (s *Store) AuditLogs(limit int) ([]AuditLog, error) {
	return s.AuditLogsFiltered("", "", limit)
}

// AuditLogsFiltered 按关键词（操作/对象/详情/来源IP）与用户名筛选审计流水；limit<=0 时默认 5000 条。
func (s *Store) AuditLogsFiltered(query, username string, limit int) ([]AuditLog, error) {
	where := []string{"1=1"}
	args := make([]interface{}, 0, 5)
	if query = strings.TrimSpace(query); query != "" {
		where = append(where, "(action LIKE ? OR target LIKE ? OR detail LIKE ? OR ip LIKE ?)")
		like := "%" + query + "%"
		args = append(args, like, like, like, like)
	}
	if username = strings.TrimSpace(username); username != "" {
		where = append(where, "username LIKE ?")
		args = append(args, "%"+username+"%")
	}
	if limit <= 0 {
		limit = 5000
	}
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT id, ts, username, role, action, COALESCE(target,''), COALESCE(detail,''), COALESCE(ip,'') FROM audit_log WHERE `+strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditLog
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.Ts, &a.Username, &a.Role, &a.Action, &a.Target, &a.Detail, &a.IP); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- settings ----------
func (s *Store) Setting(key string) string {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return ""
	}
	return v
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) SaveSettings(pairs map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range pairs {
		if _, err := tx.Exec(`INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SeedSettings(defaults map[string]string) error {
	for k, v := range defaults {
		if s.Setting(k) == "" {
			if err := s.SetSetting(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }
