package store

import (
	"strings"
)

// 本文件提供 fscan 漏洞明细（scan_vulns）与域名→IP 映射（domain_map）的存取。
// 两者均为附加表，不改动 scan_results / naabu 现有表结构，保证向后兼容。

// VulnRecord 是一条 fscan 等引擎发现的漏洞明细。
type VulnRecord struct {
	ID       int64  `json:"id"`
	ScanID   int64  `json:"scan_id"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	Service  string `json:"service"`
	Vuln     string `json:"vuln"`
	Severity string `json:"severity"` // high | mid | low
}

// UpdateScanName 更新扫描记录名称（用于拆分时追加 [自动拆分] 后缀）。
func (s *Store) UpdateScanName(id int64, name string) error {
	_, err := s.db.Exec(`UPDATE scans SET name=? WHERE id=?`, name, id)
	return err
}

// MarkScanSplit 把已创建的主扫描标记为拆分任务（复用 scans 拆分字段）。
func (s *Store) MarkScanSplit(id int64, total int) error {
	_, err := s.db.Exec(`UPDATE scans SET is_split_task=1, split_total=?, split_completed=0 WHERE id=?`, total, id)
	return err
}

// CopySubScanVulns 把子扫描的漏洞明细聚合到主扫描（INSERT OR IGNORE 去重），返回新增条数。
func (s *Store) CopySubScanVulns(parentScanID int64, subScanIDs []int64) (int, error) {
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
		res, err := tx.Exec(`INSERT OR IGNORE INTO scan_vulns(scan_id, ip, port, proto, service, vuln, severity)
			SELECT ?, ip, port, proto, service, vuln, severity FROM scan_vulns WHERE scan_id=?`, parentScanID, subID)
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

// InsertVulns 批量写入漏洞明细（INSERT OR IGNORE 去重），返回实际新增条数。
func (s *Store) InsertVulns(scanID int64, vulns []VulnRecord) (int, error) {
	if scanID <= 0 || len(vulns) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO scan_vulns(scan_id, ip, port, proto, service, vuln, severity) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	n := 0
	for _, v := range vulns {
		proto := strings.TrimSpace(v.Proto)
		if proto == "" {
			proto = "tcp"
		}
		sev := v.Severity
		if sev == "" {
			sev = "mid"
		}
		res, err := stmt.Exec(scanID, strings.TrimSpace(v.IP), v.Port, proto, v.Service, v.Vuln, sev)
		if err != nil {
			return 0, err
		}
		if aff, _ := res.RowsAffected(); aff > 0 {
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// VulnsByScan 返回某次执行的全部漏洞明细（按 ip,port 排序）。
func (s *Store) VulnsByScan(scanID int64) ([]VulnRecord, error) {
	rows, err := s.db.Query(`SELECT id, scan_id, ip, port, COALESCE(proto,'tcp'), COALESCE(service,''), COALESCE(vuln,''), COALESCE(severity,'mid')
		FROM scan_vulns WHERE scan_id=? ORDER BY ip, port`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnRecord
	for rows.Next() {
		var v VulnRecord
		if err := rows.Scan(&v.ID, &v.ScanID, &v.IP, &v.Port, &v.Proto, &v.Service, &v.Vuln, &v.Severity); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VulnSummary 统计某次执行的高危/中危漏洞数并返回有界样本（最多 limit 条）。
func (s *Store) VulnSummary(scanID int64, limit int) (high, mid int, samples []VulnRecord, err error) {
	vulns, err := s.VulnsByScan(scanID)
	if err != nil {
		return 0, 0, nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	for _, v := range vulns {
		switch v.Severity {
		case "high":
			high++
		case "mid":
			mid++
		}
		if len(samples) < limit {
			samples = append(samples, v)
		}
	}
	return high, mid, samples, nil
}

// DomainMapping 是域名→IP 的解析映射（来源 domain_resolver / subfinder）。
type DomainMapping struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Source string `json:"source"`
}

// InsertDomainMappings 批量写入域名→IP 映射（去重），返回新增条数。
func (s *Store) InsertDomainMappings(mappings []DomainMapping) (int, error) {
	if len(mappings) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO domain_map(domain, ip, source, created_at) VALUES(?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	n := 0
	for _, m := range mappings {
		if m.Domain == "" || m.IP == "" {
			continue
		}
		src := m.Source
		if src == "" {
			src = "domain_resolver"
		}
		res, err := stmt.Exec(strings.ToLower(m.Domain), m.IP, src, now())
		if err != nil {
			return 0, err
		}
		if aff, _ := res.RowsAffected(); aff > 0 {
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// DomainsForIP 返回某 IP 关联的域名列表（供暴露面「域名」列展示）。
func (s *Store) DomainsForIP(ip string) ([]string, error) {
	rows, err := s.db.Query(`SELECT domain FROM domain_map WHERE ip=? ORDER BY domain`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// IPsForDomain 按域名反向检索其解析出的全部 IP（供按域名检索开放端口）。
func (s *Store) IPsForDomain(domain string) ([]string, error) {
	rows, err := s.db.Query(`SELECT ip FROM domain_map WHERE domain=? ORDER BY ip`, strings.ToLower(strings.TrimSpace(domain)))
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
