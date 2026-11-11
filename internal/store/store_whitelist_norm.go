package store

import (
	"database/sql"
	"strings"
)

// 本文件提供白名单匹配规则的去重基础设施：写入端归一化 + 唯一索引 + 启动期存量合并，
// 使"重复提交/并发导入/多人同时加白"在数据库层天然幂等，而不是依赖应用层 check-then-act。

// normalizeWhitelistRule 生成白名单匹配键三字段（IP/网段、端口、协议）的规范存储形态：
// 去首尾空白 + 小写。与 WhitelistRuleKey 的归一化口径一致，确保 UNIQUE(ip_spec,port_spec,proto)
// 唯一索引与导入去重键判定完全等价——同一规则无论大小写/空白差异都归并到同一条。
func normalizeWhitelistRule(ipSpec, portSpec, proto string) (string, string, string) {
	return strings.ToLower(strings.TrimSpace(ipSpec)),
		strings.ToLower(strings.TrimSpace(portSpec)),
		strings.ToLower(strings.TrimSpace(proto))
}

// normalizeAndDedupeWhitelist 启动时一次性把存量白名单规则归一化并去重，然后建立唯一索引：
//   - 逐行按 normalizeWhitelistRule 改写为非规范形态（大小写/空白差异）；
//   - 归一化后与更早入库的行同键 → 删除当前行（保留最早 id，与 INSERT OR IGNORE 语义一致）；
//   - 全部处理完后 CREATE UNIQUE INDEX IF NOT EXISTS，供后续写入的 INSERT OR IGNORE 命中。
//
// 全程单事务，失败回滚不产生半成品；建索引在提交后单独执行（若历史仍有残留重复则报错交上层记日志）。
// 返回归一化/删除的行数。索引已存在时为幂等空操作。
func normalizeAndDedupeWhitelist(db *sql.DB) (int, error) {
	type row struct {
		id                      int64
		ipSpec, portSpec, proto string
	}
	var rows []row
	qr, err := db.Query(`SELECT id, COALESCE(ip_spec,''), COALESCE(port_spec,''), COALESCE(proto,'') FROM whitelist ORDER BY id`)
	if err != nil {
		return 0, err
	}
	for qr.Next() {
		var r row
		if err := qr.Scan(&r.id, &r.ipSpec, &r.portSpec, &r.proto); err != nil {
			qr.Close()
			return 0, err
		}
		rows = append(rows, r)
	}
	if err := qr.Err(); err != nil {
		qr.Close()
		return 0, err
	}
	qr.Close()

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	seen := map[string]int64{} // 归一化键 -> 保留行 id（最早）
	changed := 0
	for _, r := range rows {
		ip, port, proto := normalizeWhitelistRule(r.ipSpec, r.portSpec, r.proto)
		key := ip + "|" + port + "|" + proto
		if _, ok := seen[key]; ok {
			// 与更早保留行同规则：删除当前重复行。
			if _, err := tx.Exec(`DELETE FROM whitelist WHERE id=?`, r.id); err != nil {
				return changed, err
			}
			changed++
			continue
		}
		seen[key] = r.id
		if ip != r.ipSpec || port != r.portSpec || proto != r.proto {
			if _, err := tx.Exec(`UPDATE whitelist SET ip_spec=?, port_spec=?, proto=? WHERE id=?`, ip, port, proto, r.id); err != nil {
				return changed, err
			}
			changed++
		}
	}
	if err := tx.Commit(); err != nil {
		return changed, err
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_whitelist_key ON whitelist(ip_spec, port_spec, proto)`); err != nil {
		return changed, err
	}
	return changed, nil
}
