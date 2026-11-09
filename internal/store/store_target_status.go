package store

import (
	"strings"
)

// 本文件提供「按目标规格记录处理状态」的存取，用于终止后区分已完成/未开始/扫描中/失败，
// 并支撑「继续扫描未完成节点」的增量续扫。状态机：pending → running → done/failed。

// 目标规格处理状态。
const (
	TargetPending = "pending" // 尚未开始
	TargetRunning = "running" // 正在扫描（终止时仍为 running 视为未完成）
	TargetDone    = "done"    // 已扫描完成
	TargetFailed  = "failed"  // 尝试但失败（解析/存储/进程异常）
)

// TargetStatus 是单个目标规格在某次执行中的处理状态。
type TargetStatus struct {
	ID         int64  `json:"id"`
	ScanID     int64  `json:"scan_id"`
	SpecRaw    string `json:"spec_raw"`
	SpecKind   string `json:"spec_kind"`
	BatchIndex int    `json:"batch_index"`
	Status     string `json:"status"`
	UpdatedAt  string `json:"updated_at"`
}

// InitTargetStatus 为一次执行初始化全部目标规格为 pending（幂等：已存在不覆盖）。
func (s *Store) InitTargetStatus(scanID int64, specs []TargetSpec, batchSize int) error {
	if scanID <= 0 || len(specs) == 0 {
		return nil
	}
	if batchSize < 1 {
		batchSize = 1
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO scan_target_status(scan_id, spec_raw, spec_kind, batch_index, status, updated_at) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i, sp := range specs {
		if _, err := stmt.Exec(scanID, sp.Raw, sp.Kind, i/batchSize, TargetPending, now()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkBatchTargetStatus 把某批次内的全部目标规格置为指定状态。
func (s *Store) MarkBatchTargetStatus(scanID int64, batchIndex int, status string) error {
	_, err := s.db.Exec(`UPDATE scan_target_status SET status=?, updated_at=? WHERE scan_id=? AND batch_index=?`,
		status, now(), scanID, batchIndex)
	return err
}

// MarkTargetStatusByRaw 按规格原文更新单个目标状态（用于 fscan 单批或精细标记）。
func (s *Store) MarkTargetStatusByRaw(scanID int64, raw, status string) error {
	_, err := s.db.Exec(`UPDATE scan_target_status SET status=?, updated_at=? WHERE scan_id=? AND spec_raw=?`,
		status, now(), scanID, raw)
	return err
}

// TargetStatusByScan 返回某次执行的全部目标规格状态（按 id 升序）。
func (s *Store) TargetStatusByScan(scanID int64) ([]TargetStatus, error) {
	rows, err := s.db.Query(`SELECT id, scan_id, spec_raw, COALESCE(spec_kind,'ip'), batch_index, COALESCE(status,'pending'), COALESCE(updated_at,'')
		FROM scan_target_status WHERE scan_id=? ORDER BY id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetStatus
	for rows.Next() {
		var t TargetStatus
		if err := rows.Scan(&t.ID, &t.ScanID, &t.SpecRaw, &t.SpecKind, &t.BatchIndex, &t.Status, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TargetStatusCounts 统计某次执行各状态的目标数。
func (s *Store) TargetStatusCounts(scanID int64) (done, pending, running, failed int, err error) {
	rows, err := s.db.Query(`SELECT COALESCE(status,'pending'), COUNT(*) FROM scan_target_status WHERE scan_id=? GROUP BY status`, scanID)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return 0, 0, 0, 0, err
		}
		switch st {
		case TargetDone:
			done = n
		case TargetRunning:
			running = n
		case TargetFailed:
			failed = n
		default:
			pending += n
		}
	}
	return done, pending, running, failed, rows.Err()
}

// UnfinishedSpecs 返回未完成（pending/running/failed）的目标规格，供增量续扫。
// done 之外的状态都视为未覆盖，确保续扫后所有目标最终都被处理。
func (s *Store) UnfinishedSpecs(scanID int64) ([]TargetSpec, error) {
	rows, err := s.db.Query(`SELECT spec_raw, COALESCE(spec_kind,'ip') FROM scan_target_status
		WHERE scan_id=? AND status != ? ORDER BY id`, scanID, TargetDone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetSpec
	for rows.Next() {
		var sp TargetSpec
		if err := rows.Scan(&sp.Raw, &sp.Kind); err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

// SetScanResumeOf 记录续扫执行的父执行 ID。
func (s *Store) SetScanResumeOf(id, parentID int64) error {
	_, err := s.db.Exec(`UPDATE scans SET resume_of=? WHERE id=?`, parentID, id)
	return err
}

// HasTargetStatus 报告某次执行是否已记录目标规格状态（旧库/旧执行可能没有）。
func (s *Store) HasTargetStatus(scanID int64) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM scan_target_status WHERE scan_id=?`, scanID).Scan(&n)
	return n > 0
}

// TargetStatusName 返回状态中文标签，供页面展示。
func TargetStatusName(status string) string {
	switch strings.TrimSpace(status) {
	case TargetDone:
		return "已完成"
	case TargetRunning:
		return "扫描中"
	case TargetFailed:
		return "失败"
	default:
		return "未开始"
	}
}
