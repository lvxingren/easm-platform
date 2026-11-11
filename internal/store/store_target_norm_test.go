package store

import (
	"path/filepath"
	"testing"
)

func TestNormalizeTargetSpec(t *testing.T) {
	cases := []struct {
		raw, wantNorm, wantKind string
	}{
		{"10.0.0.1", "10.0.0.1", "ip"},
		{" 10.0.0.1 ", "10.0.0.1", "ip"},
		{"::ffff:10.0.0.1", "10.0.0.1", "ip"},
		{"10.0.0.5/24", "10.0.0.0/24", "cidr"},
		{"10.0.0.0/24", "10.0.0.0/24", "cidr"},
		{"1.2.3.1-1.2.3.50", "1.2.3.1-1.2.3.50", "range"},
		{"1.2.3.1 - 1.2.3.50", "1.2.3.1-1.2.3.50", "range"},
		{"EXAMPLE.COM", "example.com", "domain"},
		{"example.com.", "example.com", "domain"},
		{"*.Example.COM", "*.example.com", "domain"},
		{"my-domain.com", "my-domain.com", "domain"},
	}
	for _, c := range cases {
		norm, kind := NormalizeTargetSpec(c.raw)
		if norm != c.wantNorm || kind != c.wantKind {
			t.Errorf("NormalizeTargetSpec(%q) = (%q,%q)，期望 (%q,%q)", c.raw, norm, kind, c.wantNorm, c.wantKind)
		}
	}
}

func newNormTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "norm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestImportAssetsDetailedDedup 验证全局去重：批内重复、等价 CIDR、大小写/尾点域名
// 均视为同一资产；跳过数量完整回传，标签对已存在资产做并入而非覆盖。
func TestImportAssetsDetailedDedup(t *testing.T) {
	st := newNormTestStore(t)
	rows := []ImportAsset{
		{Raw: "10.0.0.1", Kind: "ip"},
		{Raw: "10.0.0.0/24", Kind: "cidr"},
		{Raw: "10.0.0.5/24", Kind: "cidr"}, // 与上一条等价 → 跳过
		{Raw: "EXAMPLE.com", Kind: "domain"},
		{Raw: "example.com.", Kind: "domain"}, // 归一化后等价 → 跳过
		{Raw: "10.0.0.1", Kind: "ip"},         // 批内重复 → 跳过
	}
	added, skipped, err := st.ImportAssetsDetailed(rows, "b1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if added != 3 || skipped != 3 {
		t.Fatalf("added=%d skipped=%d，期望 3/3", added, skipped)
	}
	// 二次导入全部命中已有资产：新增 0，跳过 6，标签并入。
	added, skipped, err = st.ImportAssetsDetailed(rows, "b2", "test")
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || skipped != 6 {
		t.Fatalf("二次导入 added=%d skipped=%d，期望 0/6", added, skipped)
	}
	tgts, err := st.Targets()
	if err != nil || len(tgts) != 3 {
		t.Fatalf("台账应有 3 条资产，实际 %d（err=%v）", len(tgts), err)
	}
	for _, tg := range tgts {
		if tg.Tags != "b1,b2" {
			t.Errorf("资产 %s 标签=%q，期望 b1,b2（重复导入并入标签）", tg.IP, tg.Tags)
		}
		if tg.IP == "EXAMPLE.com" || tg.IP == "example.com." {
			t.Errorf("域名未归一化入库: %s", tg.IP)
		}
	}
}

// TestNormalizeExistingTargetsMigration 验证存量旧库迁移：非规范形态改写为唯一键，
// 等价重复行合并（保留最早一条，标签并入、维护信息补齐）。
func TestNormalizeExistingTargetsMigration(t *testing.T) {
	st := newNormTestStore(t)
	// 直接以非规范形态写入，模拟历史数据。
	for _, raw := range []string{"10.0.0.0/24", "10.0.0.9/24", "LEGACY.example.com"} {
		if _, err := st.db.Exec(`INSERT INTO targets(ip, kind, tags, source, created_at, domain, owner, security_device) VALUES(?,?,?,?,?,?,?,?)`,
			raw, "cidr", "old-"+raw, "legacy", now(), "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.db.Exec(`UPDATE targets SET tags='first', owner='张三' WHERE ip='10.0.0.0/24'`); err != nil {
		t.Fatal(err)
	}
	changed, err := normalizeExistingTargets(st.db)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 2 {
		t.Fatalf("迁移改写/合并 %d 条，期望 2", changed)
	}
	tgts, _ := st.Targets()
	if len(tgts) != 2 {
		t.Fatalf("迁移后台账应有 2 条，实际 %d", len(tgts))
	}
	var cidr *Target
	for i := range tgts {
		if tgts[i].IP == "10.0.0.0/24" {
			cidr = &tgts[i]
		}
		if tgts[i].IP == "LEGACY.example.com" {
			t.Errorf("大写域名未被归一化")
		}
	}
	if cidr == nil {
		t.Fatal("缺少归一化后的 CIDR 资产")
	}
	if cidr.Tags != "first,old-10.0.0.9/24" {
		t.Errorf("合并标签=%q，期望 first,old-10.0.0.9/24", cidr.Tags)
	}
	if cidr.Owner != "张三" {
		t.Errorf("保留行维护信息丢失: %q", cidr.Owner)
	}
	// 幂等：再次迁移无改动。
	changed, err = normalizeExistingTargets(st.db)
	if err != nil || changed != 0 {
		t.Fatalf("二次迁移 changed=%d err=%v，期望 0/nil", changed, err)
	}
}
