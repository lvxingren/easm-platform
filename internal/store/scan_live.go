package store

import "fmt"

// SetScanActiveStatus 只在活动执行期间切换运行和暂停状态。
func (s *Store) SetScanActiveStatus(id int64, status string) error {
	if status != "running" && status != "paused" {
		return fmt.Errorf("非法活动扫描状态 %q", status)
	}
	_, err := s.db.Exec(`UPDATE scans SET status=? WHERE id=? AND status IN ('running','paused')`, status, id)
	return err
}

// UpdateScanOpenPorts 更新开放端口累计数；单调不减，迟到的旧快照不会把已统计到的更高值减回去。
func (s *Store) UpdateScanOpenPorts(id int64, openPorts int) error {
	_, err := s.db.Exec(`UPDATE scans SET open_ports=MAX(COALESCE(open_ports,0), ?) WHERE id=?`, openPorts, id)
	return err
}

// UpdateScanResource 更新当前采样值，并保留整次执行的历史峰值。
func (s *Store) UpdateScanResource(id int64, cpu float64, memoryRSS int64) error {
	_, err := s.db.Exec(`UPDATE scans SET cpu_percent=?, memory_rss=?,
		max_cpu_percent=MAX(COALESCE(max_cpu_percent,0),?),
		max_memory_rss=MAX(COALESCE(max_memory_rss,0),?) WHERE id=?`,
		cpu, memoryRSS, cpu, memoryRSS, id)
	return err
}

func (s *Store) AddScanEvent(scanID int64, level, eventType, message string) error {
	_, err := s.db.Exec(`INSERT INTO scan_events(scan_id,ts,level,type,message) VALUES(?,?,?,?,?)`,
		scanID, now(), level, eventType, message)
	return err
}

// CountScanEvents 统计某执行指定类型的事件数，用于任务结束汇总里的资源告警次数。
func (s *Store) CountScanEvents(scanID int64, eventType string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM scan_events WHERE scan_id=? AND type=?`, scanID, eventType).Scan(&n)
	return n, err
}

// BackupTo 用 VACUUM INTO 生成一份一致性快照（即使 WAL 活跃也安全），供清库前备份。
func (s *Store) BackupTo(path string) error {
	_, err := s.db.Exec(`VACUUM INTO ?`, path)
	return err
}

// ClearBusinessData 清空业务数据（资产、任务、执行、结果、事件、告警、不可达明细、白名单、旧调度），
// 保留账号 users、系统设置 settings 与操作审计 audit_log；同时重置相关表的自增计数。
func (s *Store) ClearBusinessData() error {
	tables := []string{"scan_events", "scan_results", "scan_unreachable", "alerts", "scans", "scan_tasks", "whitelist", "targets", "schedules"}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range tables {
		if _, err := tx.Exec(`DELETE FROM ` + table); err != nil {
			return err
		}
	}
	for _, table := range tables {
		if _, err := tx.Exec(`DELETE FROM sqlite_sequence WHERE name=?`, table); err != nil {
			// sqlite_sequence 可能尚无该表记录，忽略即可
			continue
		}
	}
	return tx.Commit()
}

func (s *Store) ScanEvents(scanID, afterID int64, limit int) ([]ScanEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT id,scan_id,COALESCE(ts,''),COALESCE(level,''),COALESCE(type,''),COALESCE(message,'')
		FROM scan_events WHERE scan_id=? AND id>? ORDER BY id LIMIT ?`, scanID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ScanEvent, 0)
	for rows.Next() {
		var event ScanEvent
		if err := rows.Scan(&event.ID, &event.ScanID, &event.Ts, &event.Level, &event.Type, &event.Message); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

// ResultsAfter 保留旧签名：按自增 ID 返回增量结果，内部走键集分页 ResultsPage。
// 新代码建议直接用 ResultsPage，以便拿到 NextCursor/HasMore。
func (s *Store) ResultsAfter(scanID, afterID int64, limit int) ([]Result, error) {
	page, err := s.ResultsPage(scanID, afterID, limit)
	if err != nil {
		return nil, err
	}
	return page.Results, nil
}
