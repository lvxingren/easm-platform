package store

import (
	"database/sql"
	"net/netip"
	"strings"
)

// NormalizeTargetSpec 把资产规格归一化为唯一键形态，供导入/手动添加全局去重：
//   - 单 IP：去 IPv4 映射前缀（::ffff:a.b.c.d → a.b.c.d）、IPv6 压缩小写；
//   - CIDR：掩码对齐（10.0.0.5/24 → 10.0.0.0/24），等价网段不再重复入库；
//   - 范围：两端各自归一后拼接（去空白、去映射前缀）；
//   - 域名：小写、去尾点（*. 通配前缀保留）。
//
// 无法解析的输入原样返回（合法性由上游 engine.ClassifyTarget 校验），
// 本函数只负责等价形态合并，不承担校验职责。
func NormalizeTargetSpec(raw string) (norm, kind string) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\ufeff", ""))
	if raw == "" {
		return "", ""
	}
	if idx := strings.Index(raw, "-"); idx > 0 {
		a, err1 := netip.ParseAddr(strings.TrimSpace(raw[:idx]))
		b, err2 := netip.ParseAddr(strings.TrimSpace(raw[idx+1:]))
		if err1 == nil && err2 == nil && a.Is4() == b.Is4() && a.Unmap().Compare(b.Unmap()) <= 0 {
			return a.Unmap().String() + "-" + b.Unmap().String(), "range"
		}
		// 非合法范围（如含连字符的域名 my-domain.com）继续走后续分支。
	}
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked().String(), "cidr"
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return a.Unmap().String(), "ip"
	}
	host := strings.ToLower(raw)
	host = strings.TrimSuffix(host, ".")
	if strings.HasPrefix(host, "*.") {
		return host, "domain"
	}
	if strings.Contains(host, ".") && !strings.ContainsAny(host, " \t/\\?#@:;,") {
		return host, "domain"
	}
	return raw, ""
}

// normalizeExistingTargets 启动时一次性把存量台账归一化：
//   - 规范形态已存在另一行 → 把旧行标签并入保留行（维护信息空则补齐），删除旧行；
//   - 不存在 → 直接把旧行主标识改写为规范形态。
//
// 全程单事务，失败回滚不产生半成品；返回合并/改写的行数。按 id 升序处理，
// 等价重复保留最早一条（与导入时 INSERT OR IGNORE 保留先入库者的语义一致）。
func normalizeExistingTargets(db *sql.DB) (int, error) {
	type row struct {
		id               int64
		ip, tags, domain string
		owner, device    string
	}
	var rows []row
	qr, err := db.Query(`SELECT id, COALESCE(ip,''), COALESCE(tags,''), COALESCE(domain,''), COALESCE(owner,''), COALESCE(security_device,'') FROM targets ORDER BY id`)
	if err != nil {
		return 0, err
	}
	for qr.Next() {
		var r row
		if err := qr.Scan(&r.id, &r.ip, &r.tags, &r.domain, &r.owner, &r.device); err != nil {
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
	changed := 0
	for _, r := range rows {
		norm, _ := NormalizeTargetSpec(r.ip)
		if norm == "" || norm == r.ip {
			continue
		}
		var existID int64
		var existTags, existOwner, existDevice string
		err := tx.QueryRow(`SELECT id, COALESCE(tags,''), COALESCE(owner,''), COALESCE(security_device,'') FROM targets WHERE ip=? AND id<>?`, norm, r.id).
			Scan(&existID, &existTags, &existOwner, &existDevice)
		if err == nil {
			owner, device := existOwner, existDevice
			if owner == "" {
				owner = r.owner
			}
			if device == "" {
				device = r.device
			}
			if _, err := tx.Exec(`UPDATE targets SET tags=?, owner=?, security_device=? WHERE id=?`, mergeTags(existTags, r.tags), owner, device, existID); err != nil {
				return changed, err
			}
			if _, err := tx.Exec(`DELETE FROM targets WHERE id=?`, r.id); err != nil {
				return changed, err
			}
			changed++
			continue
		}
		if err != sql.ErrNoRows {
			return changed, err
		}
		domain := r.domain
		if domain != "" {
			domain = norm
		}
		if _, err := tx.Exec(`UPDATE targets SET ip=?, domain=? WHERE id=?`, norm, domain, r.id); err != nil {
			return changed, err
		}
		changed++
	}
	if err := tx.Commit(); err != nil {
		return changed, err
	}
	return changed, nil
}
