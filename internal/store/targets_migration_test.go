package store

import (
	"database/sql"
	"testing"
)

// TestTargetsLegacyMigrationAndDomainFields 验证旧库 targets 表自动补 domain/owner/security_device 列，
// 旧行以 COALESCE 兜底为空可读，并验证域名资产与维护信息的写入/编辑。
func TestTargetsLegacyMigrationAndDomainFields(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE, kind TEXT DEFAULT 'ip', tags TEXT DEFAULT '', source TEXT DEFAULT '', created_at TEXT);
INSERT INTO targets(ip,kind,tags,source,created_at) VALUES('1.1.1.1','ip','旧标签','手动','2026-01-01T00:00:00Z');`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("旧库迁移失败: %v", err)
	}
	defer st.Close()

	targets, err := st.Targets()
	if err != nil {
		t.Fatalf("迁移后读取失败（应 COALESCE 兜底新列）: %v", err)
	}
	if len(targets) != 1 || targets[0].IP != "1.1.1.1" || targets[0].Tags != "旧标签" {
		t.Fatalf("旧行读取错误: %+v", targets)
	}
	if targets[0].Domain != "" || targets[0].Owner != "" || targets[0].SecurityDevice != "" {
		t.Fatalf("旧行新字段应默认为空: %+v", targets[0])
	}

	if _, err := st.ImportAssets([]ImportAsset{{Raw: "example.com", Kind: "domain", Owner: "张三", SecurityDevice: "WAF"}}, "生产", "测试"); err != nil {
		t.Fatal(err)
	}
	targets, _ = st.Targets()
	var domainID int64
	found := false
	for _, tg := range targets {
		if tg.IP == "example.com" {
			found = true
			domainID = tg.ID
			if tg.Kind != "domain" || tg.Domain != "example.com" || tg.Owner != "张三" || tg.SecurityDevice != "WAF" || tg.Tags != "生产" {
				t.Fatalf("域名资产字段错误: %+v", tg)
			}
		}
	}
	if !found {
		t.Fatal("域名资产未写入")
	}

	if err := st.UpdateTargetMeta(domainID, "李四", "云盾", "生产,核心"); err != nil {
		t.Fatal(err)
	}
	targets, _ = st.Targets()
	for _, tg := range targets {
		if tg.ID == domainID {
			if tg.Owner != "李四" || tg.SecurityDevice != "云盾" || tg.Tags != "生产,核心" {
				t.Fatalf("编辑维护信息未生效: %+v", tg)
			}
			if tg.Domain != "example.com" || tg.IP != "example.com" {
				t.Fatalf("编辑不应改动主标识/域名: %+v", tg)
			}
		}
	}
}
