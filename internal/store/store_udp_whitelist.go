package store

import "strings"

// 本文件提供任务级 UDP 快照标记与白名单「自动匹配已识别端口」所需的历史开放端口查询。

// SetScanUDPEnabled 记录本次执行是否启用 UDP 端口扫描（任务级快照，可追溯）。
func (s *Store) SetScanUDPEnabled(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE scans SET udp_enabled=? WHERE id=?`, v, id)
	return err
}

// DomainServices 返回域名经 DNS 解析衍生 IP 在历史扫描中的服务指纹（去重、非空），
// 供台账域名行内展示服务标签。
func (s *Store) DomainServices(domain string) ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT COALESCE(r.service,'') FROM scan_results r
		JOIN domain_map d ON d.ip = r.ip
		WHERE d.domain = ? AND r.status=1 AND COALESCE(r.service,'') != '' ORDER BY 1`, strings.ToLower(strings.TrimSpace(domain)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var svc string
		if err := rows.Scan(&svc); err != nil {
			return nil, err
		}
		out = append(out, svc)
	}
	return out, rows.Err()
}

// OpenPortsByIPs 查询给定 IP 在所有历史扫描中出现过的开放端口（去重 ip+port+proto），
// 供白名单「自动匹配已识别端口」。仅返回 status=1 的开放端口。
// 分片查询（每片 ≤500 占位符）避免超多 IP 撞 SQLite 变量上限；每 IP 端口数设上限
// 防御异常结果集放大。
func (s *Store) OpenPortsByIPs(ips []string) ([]Result, error) {
	const chunkSize = 500
	const perIPCap = 4096
	if len(ips) == 0 {
		return nil, nil
	}
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
	var out []Result
	perIP := map[string]int{}
	for start := 0; start < len(uniq); start += chunkSize {
		end := start + chunkSize
		if end > len(uniq) {
			end = len(uniq)
		}
		batch := uniq[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",")
		args := make([]interface{}, len(batch))
		for i, ip := range batch {
			args[i] = ip
		}
		rows, err := s.db.Query(`SELECT DISTINCT ip, port, COALESCE(proto,'tcp'), COALESCE(service,'') FROM scan_results
			WHERE status=1 AND ip IN (`+placeholders+`) ORDER BY ip, port`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r Result
			if err := rows.Scan(&r.IP, &r.Port, &r.Proto, &r.Service); err != nil {
				rows.Close()
				return nil, err
			}
			r.Status = 1
			if perIP[r.IP] >= perIPCap {
				continue
			}
			perIP[r.IP]++
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}
