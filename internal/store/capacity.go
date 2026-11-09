package store

import (
	"errors"
	"fmt"
	"strings"
)

// 容量相关硬上限：单次批量写入调用的最大行数、单个分块事务的最大行数，
// 以及分页读取的默认页大小与最大页大小。
// 所有上限都是显式常量，目的是保证任何一次写入都不会构造超大 SQL、
// 也不会开启一个行数无界的长事务。
const (
	// ResultInsertChunkSize 单个分块事务内最多写入的结果行数。
	// 分块内部使用「预编译语句 + 逐行 Exec」，不会把多行拼成一条超大 INSERT。
	ResultInsertChunkSize = 500
	// ResultInsertMaxBatch 单次批量写入调用允许提交的最大行数（硬上限）。
	// 超过该上限直接拒绝并返回 ErrResultBatchTooLarge，由调用方自行切分。
	ResultInsertMaxBatch = 20000
	// ResultPageDefaultLimit 分页读取未指定页大小时的默认值。
	ResultPageDefaultLimit = 500
	// ResultPageMaxLimit 分页读取允许的最大页大小（硬上限）。
	ResultPageMaxLimit = 2000
)

var (
	// ErrResultBatchTooLarge 表示一次批量写入的行数超过 ResultInsertMaxBatch 硬上限。
	ErrResultBatchTooLarge = errors.New("结果批量写入超过单次硬上限")
	// ErrScanIDRequired 表示写入/读取结果时 scan_id 非法（<=0）。
	ErrScanIDRequired = errors.New("scan_id 必须大于 0")
)

// ResultInsertStats 描述一次批量写入的实际情况。
// Inserted 是数据库「实际新增」的行数：重复行被 UNIQUE(scan_id, ip, port, proto)
// 与 INSERT OR IGNORE 忽略，不计入其中。
//
// 统计语义按「只计已成功 Commit 的分块」定义：失败分块整体回滚，
// 其行数既不进入 Inserted，也不计入 Chunks；失败前已提交分块的数据与计数保留。
type ResultInsertStats struct {
	Submitted int // 本次调用提交的行数（无论成功失败都等于 len(results)）
	Inserted  int // 已成功提交到数据库的实际新增行数（失败分块整块回滚，不计入）
	Chunks    int // 已成功提交的分块事务数（失败分块不计入）
}

// ResultPage 是一页结果与继续翻页所需的游标。
// Cursor 语义：本页最后一行的 scan_results.id；下一页把它作为 afterID 传入即可。
// 游标按自增主键递增，因此并发写入期间分页不会遗漏已存在行、也不会重复。
type ResultPage struct {
	Results    []Result
	NextCursor int64
	HasMore    bool
}

// ScanProgress 是一次进度快照。所有计数字段按「单调不减」合并进数据库：
// 旧快照（数值更小）永远不会覆盖已经写入的更高值。
type ScanProgress struct {
	Processed    int    // 已处理目标数 -> scans.processed_targets
	Failed       int    // 异常目标数 -> scans.failed_targets
	CurrentBatch int    // 已完成批次数 -> scans.current_batch
	OpenPorts    int    // 开放端口累计数 -> scans.open_ports
	Results      int    // 结果行累计数 -> scans.result_count
	Command      string // 非空才覆盖 command，空串表示保留原命令文本
}

// InsertResultsBatch 批量写入某次执行的端口结果，返回数据库实际新增条数。
//
// 语义：
//   - 依赖 scan_results 的 UNIQUE(scan_id, ip, port, proto) 与 INSERT OR IGNORE 去重，
//     同一次调用内重复、以及与库中已有行重复都不会重复计数；
//   - 内部按 ResultInsertChunkSize 分块，每块一个独立事务；块内使用预编译语句逐行 Exec，
//     不拼接多值 INSERT，因此不会产生超大 SQL；
//   - 单次调用硬上限 ResultInsertMaxBatch，超出返回 ErrResultBatchTooLarge 且不写入任何行；
//   - 实际新增行会同步累加 scans.result_count（与 ApplyScanProgress 的单调合并一致）；
//   - 任一分块失败（Begin/Prepare/逐行 Exec/计数 UPDATE/Commit 任一环节出错）时立即返回错误：
//     该分块整体回滚，对 scan_results 与 scans.result_count 均无贡献，也不计入 Inserted/Chunks；
//     失败前已成功 Commit 的分块数据与 result_count 保留，返回值只累计这些成功分块；
//     Submitted 始终是本次调用提交的总行数，不代表已成功写入的行数；
//   - 空输入返回零值统计且不开启事务。
func (s *Store) InsertResultsBatch(scanID int64, results []Result) (ResultInsertStats, error) {
	stats := ResultInsertStats{Submitted: len(results)}
	if scanID <= 0 {
		return stats, ErrScanIDRequired
	}
	if len(results) > ResultInsertMaxBatch {
		return stats, fmt.Errorf("%w：提交 %d 行，硬上限 %d 行", ErrResultBatchTooLarge, len(results), ResultInsertMaxBatch)
	}
	for start := 0; start < len(results); start += ResultInsertChunkSize {
		end := start + ResultInsertChunkSize
		if end > len(results) {
			end = len(results)
		}
		inserted, err := s.insertResultChunk(scanID, results[start:end])
		if err != nil {
			// 失败分块已整体回滚（insertResultChunk 保证返回 inserted=0），
			// 不进入 Chunks/Inserted；此前已成功 Commit 的分块统计保持不变。
			return stats, err
		}
		stats.Chunks++
		stats.Inserted += inserted
	}
	return stats, nil
}

// insertResultChunk 在一个事务内写入一段结果并返回该段实际新增行数。
//
// 所有错误路径都必须返回 (0, err)：本块尚未 Commit，defer 的 Rollback 会把
// 已 Exec 的行、result_count 的 UPDATE 全部撤销，因此该块对数据库的真实贡献为 0。
// 若在失败路径返回局部累计值，外层会把它当成已落库行数累计，导致
// Inserted 与实际行数、result_count 不一致。
func (s *Store) insertResultChunk(scanID int64, chunk []Result) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO scan_results(scan_id, ip, port, proto, service, status) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	inserted := 0
	for _, r := range chunk {
		proto := strings.TrimSpace(r.Proto)
		if proto == "" {
			proto = "tcp"
		}
		res, err := stmt.Exec(scanID, strings.TrimSpace(r.IP), r.Port, proto, r.Service, r.Status)
		if err != nil {
			return 0, err
		}
		if aff, _ := res.RowsAffected(); aff > 0 {
			inserted++
		}
	}
	if inserted > 0 {
		// result_count 只增不减，与 ApplyScanProgress 的 MAX 合并语义保持一致。
		if _, err := tx.Exec(`UPDATE scans SET result_count=COALESCE(result_count,0)+? WHERE id=?`, inserted, scanID); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

// ResultsPage 按自增主键顺序分页读取某次执行的结果，供 scanner 补齐、
// engine 后处理与 web 详情增量使用，避免一次性全量加载。
//
// 语义：
//   - 返回 id > afterID 的结果，按 id 升序，最多 limit 行；
//   - limit<=0 取 ResultPageDefaultLimit，limit>ResultPageMaxLimit 截断为 ResultPageMaxLimit；
//   - NextCursor 为本页最后一行 id，HasMore 表示后面还有行；
//     无数据时返回空切片、NextCursor=afterID、HasMore=false；
//   - 使用键集游标（WHERE id > ?），并发写入只会追加更大 id，不会造成遗漏或重复。
func (s *Store) ResultsPage(scanID, afterID int64, limit int) (ResultPage, error) {
	if scanID <= 0 {
		return ResultPage{}, ErrScanIDRequired
	}
	if limit <= 0 {
		limit = ResultPageDefaultLimit
	}
	if limit > ResultPageMaxLimit {
		limit = ResultPageMaxLimit
	}
	rows, err := s.db.Query(`SELECT id, ip, port, COALESCE(proto,'tcp'), COALESCE(service,''), status
		FROM scan_results WHERE scan_id=? AND id>? ORDER BY id LIMIT ?`, scanID, afterID, limit+1)
	if err != nil {
		return ResultPage{}, err
	}
	defer rows.Close()
	out := make([]Result, 0, limit)
	for rows.Next() {
		var result Result
		if err := rows.Scan(&result.ID, &result.IP, &result.Port, &result.Proto, &result.Service, &result.Status); err != nil {
			return ResultPage{}, err
		}
		out = append(out, result)
	}
	if err := rows.Err(); err != nil {
		return ResultPage{}, err
	}
	page := ResultPage{NextCursor: afterID}
	if len(out) > limit {
		out = out[:limit]
		page.HasMore = true
	}
	page.Results = out
	if n := len(out); n > 0 {
		page.NextCursor = out[n-1].ID
	}
	return page, nil
}

// CountResultsByScan 统计某次执行的结果行数，用于分页总数展示与容量核对。
func (s *Store) CountResultsByScan(scanID int64) (int, error) {
	if scanID <= 0 {
		return 0, ErrScanIDRequired
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM scan_results WHERE scan_id=?`, scanID).Scan(&n)
	return n, err
}

// ApplyScanProgress 以「单调不减」语义合并一次进度快照：
// processed/failed/current_batch/open_ports/result_count 均取 max(已有值, 快照值)，
// 因此迟到的旧快照不会把已经写入的更高值覆盖回去。command 仅在非空时覆盖。
// 整个合并是单条 UPDATE，由 SQLite 写入锁串行化，可安全并发调用。
func (s *Store) ApplyScanProgress(id int64, p ScanProgress) error {
	if id <= 0 {
		return ErrScanIDRequired
	}
	_, err := s.db.Exec(`UPDATE scans SET
		processed_targets=MAX(COALESCE(processed_targets,0), ?),
		failed_targets=MAX(COALESCE(failed_targets,0), ?),
		current_batch=MAX(COALESCE(current_batch,0), ?),
		open_ports=MAX(COALESCE(open_ports,0), ?),
		result_count=MAX(COALESCE(result_count,0), ?),
		command=CASE WHEN ?<>'' THEN ? ELSE COALESCE(command,'') END
		WHERE id=?`,
		p.Processed, p.Failed, p.CurrentBatch, p.OpenPorts, p.Results, p.Command, p.Command, id)
	return err
}
