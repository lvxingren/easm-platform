package store

import (
	"database/sql"
	"strings"
)

// Analysis 是一次网络流量 / 安全设备日志分析项目。
type Analysis struct {
	ID            int64
	Name          string
	SourceType    string // cfw | ecs | other
	Status        string // pending | parsing | analyzing | done | failed
	CreatedAt     string
	FinishedAt    string
	Err           string
	FlowCount     int
	EdgeCount     int
	FileCount     int
	AIModel       string
	AIEndpoint    string
	Summary       string
	Readable      string
	TopologyJSON  string
	AnomaliesJSON string
	TraceJSON     string
	UsedMock      bool
}

// AnalysisFile 是分析项目下保留的原始上传文件记录（供复核与导出）。
type AnalysisFile struct {
	ID         int64  `json:"id"`
	AnalysisID int64  `json:"analysis_id"`
	Filename   string `json:"filename"`
	Size       int64  `json:"size"`
	Format     string `json:"format"`
	StoredPath string `json:"-"`
	RowsParsed int    `json:"rows_parsed"`
	UploadedAt string `json:"uploaded_at"`
}

// AnalysisEdge 是解析聚合后的资产间通信关系（src → dst:port/proto）。
type AnalysisEdge struct {
	ID         int64  `json:"id"`
	AnalysisID int64  `json:"analysis_id"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	DstPort    int    `json:"dst_port"`
	Proto      string `json:"proto"`
	Action     string `json:"action"`
	Count      int    `json:"count"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
}

// AnalysisResult 承载 AI 分析产出，写入 analysis 主表。
type AnalysisResult struct {
	Status        string
	Err           string
	Summary       string
	Readable      string
	TopologyJSON  string
	AnomaliesJSON string
	TraceJSON     string
	AIModel       string
	AIEndpoint    string
	UsedMock      bool
}

const analysisCols = `id, COALESCE(name,''), COALESCE(source_type,''), COALESCE(status,''), COALESCE(created_at,''), COALESCE(finished_at,''),
	COALESCE(error,''), COALESCE(flow_count,0), COALESCE(edge_count,0), COALESCE(file_count,0), COALESCE(ai_model,''), COALESCE(ai_endpoint,''),
	COALESCE(summary,''), COALESCE(readable,''), COALESCE(topology_json,''), COALESCE(anomalies_json,''), COALESCE(trace_json,''), COALESCE(used_mock,0)`

func scanAnalysis(scanner interface{ Scan(...interface{}) error }) (Analysis, error) {
	var a Analysis
	var usedMock int
	err := scanner.Scan(&a.ID, &a.Name, &a.SourceType, &a.Status, &a.CreatedAt, &a.FinishedAt, &a.Err,
		&a.FlowCount, &a.EdgeCount, &a.FileCount, &a.AIModel, &a.AIEndpoint, &a.Summary, &a.Readable,
		&a.TopologyJSON, &a.AnomaliesJSON, &a.TraceJSON, &usedMock)
	a.UsedMock = usedMock == 1
	return a, err
}

func (s *Store) CreateAnalysis(name, sourceType string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO analysis(name, source_type, status, created_at) VALUES(?,?,?,?)`,
		strings.TrimSpace(name), strings.TrimSpace(sourceType), "pending", now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) SetAnalysisStatus(id int64, status, errMsg string) error {
	_, err := s.db.Exec(`UPDATE analysis SET status=?, error=? WHERE id=?`, status, errMsg, id)
	return err
}

func (s *Store) SetAnalysisCounts(id int64, flowCount, edgeCount, fileCount int) error {
	_, err := s.db.Exec(`UPDATE analysis SET flow_count=?, edge_count=?, file_count=? WHERE id=?`, flowCount, edgeCount, fileCount, id)
	return err
}

func (s *Store) AddAnalysisFile(f AnalysisFile) error {
	_, err := s.db.Exec(`INSERT INTO analysis_files(analysis_id, filename, size, format, stored_path, rows_parsed, uploaded_at) VALUES(?,?,?,?,?,?,?)`,
		f.AnalysisID, f.Filename, f.Size, f.Format, f.StoredPath, f.RowsParsed, now())
	return err
}

// ReplaceAnalysisEdges 覆盖写入某分析聚合出的通信关系。
func (s *Store) ReplaceAnalysisEdges(analysisID int64, edges []AnalysisEdge) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM analysis_edges WHERE analysis_id=?`, analysisID); err != nil {
		return err
	}
	for _, e := range edges {
		if _, err := tx.Exec(`INSERT INTO analysis_edges(analysis_id, src_ip, dst_ip, dst_port, proto, action, count, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?)`,
			analysisID, e.SrcIP, e.DstIP, e.DstPort, e.Proto, e.Action, e.Count, e.FirstSeen, e.LastSeen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FinishAnalysis 写入 AI 分析结果并置终态（status 为空时默认 done）。
func (s *Store) FinishAnalysis(id int64, res AnalysisResult) error {
	status := res.Status
	if status == "" {
		status = "done"
	}
	_, err := s.db.Exec(`UPDATE analysis SET status=?, error=?, finished_at=?, summary=?, readable=?, topology_json=?, anomalies_json=?, trace_json=?, ai_model=?, ai_endpoint=?, used_mock=? WHERE id=?`,
		status, res.Err, now(), res.Summary, res.Readable, res.TopologyJSON, res.AnomaliesJSON, res.TraceJSON, res.AIModel, res.AIEndpoint, b2i(res.UsedMock), id)
	return err
}

func (s *Store) Analysis(id int64) (*Analysis, error) {
	a, err := scanAnalysis(s.db.QueryRow(`SELECT `+analysisCols+` FROM analysis WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) Analyses(limit int) ([]Analysis, error) {
	q := `SELECT ` + analysisCols + ` FROM analysis ORDER BY id DESC`
	args := make([]interface{}, 0, 1)
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Analysis
	for rows.Next() {
		a, err := scanAnalysis(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AnalysisFiles(analysisID int64) ([]AnalysisFile, error) {
	rows, err := s.db.Query(`SELECT id, analysis_id, COALESCE(filename,''), COALESCE(size,0), COALESCE(format,''), COALESCE(stored_path,''), COALESCE(rows_parsed,0), COALESCE(uploaded_at,'')
		FROM analysis_files WHERE analysis_id=? ORDER BY id`, analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnalysisFile
	for rows.Next() {
		var f AnalysisFile
		if err := rows.Scan(&f.ID, &f.AnalysisID, &f.Filename, &f.Size, &f.Format, &f.StoredPath, &f.RowsParsed, &f.UploadedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) AnalysisEdges(analysisID int64, limit int) ([]AnalysisEdge, error) {
	q := `SELECT id, analysis_id, COALESCE(src_ip,''), COALESCE(dst_ip,''), COALESCE(dst_port,0), COALESCE(proto,''), COALESCE(action,''), COALESCE(count,0), COALESCE(first_seen,''), COALESCE(last_seen,'')
		FROM analysis_edges WHERE analysis_id=? ORDER BY count DESC, id`
	args := []interface{}{analysisID}
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnalysisEdge
	for rows.Next() {
		var e AnalysisEdge
		if err := rows.Scan(&e.ID, &e.AnalysisID, &e.SrcIP, &e.DstIP, &e.DstPort, &e.Proto, &e.Action, &e.Count, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteAnalysis 删除分析项目及其文件记录与聚合关系（磁盘原始文件由调用方另行清理）。
func (s *Store) DeleteAnalysis(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM analysis_edges WHERE analysis_id=?`,
		`DELETE FROM analysis_files WHERE analysis_id=?`,
		`DELETE FROM analysis WHERE id=?`,
	} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
