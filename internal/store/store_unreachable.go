package store

import (
	"strings"
)

// 本文件实现「网络不可达」告警的数据层：扫描过程中采集的不可达目标
// （DNS 解析失败/连通性探测失败）先落 scan_unreachable 明细表（按扫描去重），
// 收尾时由 engine.ProcessUnreachable 生成/刷新 kind=unreachable 的独立告警，
// 与端口暴露告警（kind=port）分表筛选、互不干扰。

// 不可达原因常量：采集端统一使用，页面/飞书按此展示并映射排查建议。
const (
	ReasonDNSFailure     = "DNS 解析失败"
	ReasonConnTimeout    = "连接超时"
	ReasonNetUnreachable = "网络不可达"
)

// Unreachable 是一次扫描中记录的一条不可达目标明细。
type Unreachable struct {
	ID        int64
	ScanID    int64
	Target    string
	Reason    string
	CreatedAt string
}

// RecordUnreachable 记录一条不可达目标（同一扫描内同目标幂等，保留首次原因）。
// 采集端（批次解析回调/连通性探测）并发调用安全，依赖 UNIQUE(scan_id, target)。
func (s *Store) RecordUnreachable(scanID int64, target, reason string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO scan_unreachable(scan_id, target, reason, created_at) VALUES(?,?,?,?)`,
		scanID, target, strings.TrimSpace(reason), now())
	return err
}

// RecordUnreachableBatch 在一个事务内用预编译语句批量写入不可达明细，返回实际新增行数。
// 批次解析热路径用它替代逐条 RecordUnreachable：避免与 scan_results 的批量写争抢数据库锁、
// 放大 busy_timeout 等待；去重仍由 UNIQUE(scan_id, target) 保证，同批与库内重复均静默忽略。
// 空输入不开事务；逐条原因相同的场景用统一 reason，目标去空白后为空则跳过。
func (s *Store) RecordUnreachableBatch(scanID int64, targets []string, reason string) (int, error) {
	if scanID <= 0 || len(targets) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO scan_unreachable(scan_id, target, reason, created_at) VALUES(?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	ts := now()
	reason = strings.TrimSpace(reason)
	inserted := 0
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		res, err := stmt.Exec(scanID, target, reason, ts)
		if err != nil {
			return inserted, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}
	if err := tx.Commit(); err != nil {
		return inserted, err
	}
	return inserted, nil
}

// PruneUnreachableDetails 按保留期裁剪不可达明细：只保留最近 keepRecent 次执行（按 scans.id 降序）
// 的记录，其余删除；扫描已删除的孤儿明细一并清理，避免表随定时扫描无限增长。
// 本次执行刚写入的明细 ID 必然是最大的 scan_id，天然落在保留窗口内。
// 告警生成/提醒只消费收尾即时读取的明细，历史明细仅供详情页回看，
// 超出保留窗口后删除不影响告警生命周期。返回删除行数。
func (s *Store) PruneUnreachableDetails(keepRecent int) (int, error) {
	if keepRecent <= 0 {
		keepRecent = 1
	}
	res, err := s.db.Exec(`DELETE FROM scan_unreachable WHERE scan_id NOT IN (
		SELECT id FROM scans ORDER BY id DESC LIMIT ?)`, keepRecent)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// Unreachables 读取某次扫描的全部不可达明细（按入库顺序）。
func (s *Store) Unreachables(scanID int64) ([]Unreachable, error) {
	rows, err := s.db.Query(`SELECT id, scan_id, target, COALESCE(reason,''), COALESCE(created_at,'') FROM scan_unreachable WHERE scan_id=? ORDER BY id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Unreachable
	for rows.Next() {
		var u Unreachable
		if err := rows.Scan(&u.ID, &u.ScanID, &u.Target, &u.Reason, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CopySubScanUnreachables 把子扫描的不可达明细复制到主扫描 ID 下（INSERT OR IGNORE 去重），
// 与 CopySubScanResults 同一聚合不变量：拆分任务必须由主扫描统一生成告警。
func (s *Store) CopySubScanUnreachables(parentScanID int64, subScanIDs []int64) (int, error) {
	if len(subScanIDs) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	total := 0
	for _, subID := range subScanIDs {
		res, err := tx.Exec(`INSERT OR IGNORE INTO scan_unreachable(scan_id, target, reason, created_at)
			SELECT ?, target, reason, created_at FROM scan_unreachable WHERE scan_id=?`, parentScanID, subID)
		if err != nil {
			return total, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			total += int(n)
		}
	}
	if err := tx.Commit(); err != nil {
		return total, err
	}
	return total, nil
}

// AlertFindUnreachable 按目标查找网络不可达告警（kind=unreachable，与端口告警键空间隔离）。
func (s *Store) AlertFindUnreachable(target string) (*Alert, error) {
	return s.alertBy(`kind='unreachable' AND ip=? ORDER BY id DESC LIMIT 1`, target)
}

// CreateUnreachableAlert 新建一条网络不可达告警：port=0、proto 空、kind=unreachable，
// reason 记录失败原因，发生时间即 first_seen_at/created_at。
func (s *Store) CreateUnreachableAlert(target, reason string, inScope bool) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO alerts(ip, port, proto, service, in_scope, status, first_seen_at, last_seen_at, created_at, kind, reason)
		VALUES(?,0,'','',?,'new',?,?,?,?,?)`,
		target, b2i(inScope), now(), now(), now(), "unreachable", strings.TrimSpace(reason))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateAlertReason 刷新不可达告警的最新失败原因（重开/间隔提醒时原因可能变化）。
func (s *Store) UpdateAlertReason(id int64, reason string) error {
	_, err := s.db.Exec(`UPDATE alerts SET reason=? WHERE id=?`, strings.TrimSpace(reason), id)
	return err
}

// LedgerIPsWithoutResults 返回本次扫描声明的目标中、且在台账内为单 IP、且本次扫描无任何
// 开放端口结果的资产，供可选的连通性探测使用（CIDR/范围/域名不参与，避免误报与规模失控）。
// 候选集通过 scan_target_status（本次执行的目标规格基线，spec_raw 对 IP 类目标等于 targets.ip）
// 取交集，确保探测范围严格限于本次任务目标，不会因台账中存在无关自有资产而越界主动发包。
func (s *Store) LedgerIPsWithoutResults(scanID int64, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT t.ip FROM targets t WHERE COALESCE(t.kind,'ip')='ip'
		AND EXISTS (SELECT 1 FROM scan_target_status s WHERE s.scan_id=? AND s.spec_raw=t.ip)
		AND NOT EXISTS (SELECT 1 FROM scan_results r WHERE r.scan_id=? AND r.ip=t.ip) ORDER BY t.id LIMIT ?`,
		scanID, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// UnreachableSuggestion 按失败原因给出排查建议（告警详情/导出/飞书共用）。
func UnreachableSuggestion(reason string) string {
	switch {
	case strings.Contains(reason, "DNS"):
		return "检查域名是否过期或拼写错误；核对平台 DNS/DoH 配置与上游解析是否生效；用 dig/nslookup 手工复核。"
	case strings.Contains(reason, "超时"):
		return "检查目标防火墙/安全组是否丢弃探测包；核对路由与链路质量；确认目标主机是否在线。"
	case strings.Contains(reason, "不可达"):
		return "检查本机路由表、网关与中间设备 ACL；确认目标网段是否可达（traceroute 复核）。"
	default:
		return "核对目标资产信息与网络链路；手工 ping/telnet 复核连通性后按实际处置。"
	}
}
