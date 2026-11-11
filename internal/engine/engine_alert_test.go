package engine

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"easm-platform/internal/config"
	"easm-platform/internal/store"
)

// 本文件回归核对「扫描结果聚合 → 白名单比对 → 告警生命周期」链路（任务2），
// 并覆盖新增的网络不可达告警（任务3）：独立键空间、realert 间隔、resolved 重开、
// ignored 屏蔽、与端口白名单互不干扰。

func newAlertTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alerts.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, path
}

func seedScanResults(t *testing.T, st *store.Store, results []store.Result) int64 {
	t.Helper()
	scanID, err := st.CreateScan(1, "告警回归", "top")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertResultsBatch(scanID, results); err != nil {
		t.Fatal(err)
	}
	return scanID
}

// backdateAlert 通过独立连接把告警最近发现时间回拨，模拟超过 realert 间隔。
func backdateAlert(t *testing.T, dbPath string, alertID int64, d time.Duration) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	past := time.Now().Add(-d).Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE alerts SET last_seen_at=? WHERE id=?`, past, alertID); err != nil {
		t.Fatal(err)
	}
}

// TestAfterScanWhitelistDimensions 验证白名单三维匹配（IP/CIDR、端口列表/范围、协议），
// 已加白端口绝不生成告警；未加白的 UDP/TCP 分别独立告警。
func TestAfterScanWhitelistDimensions(t *testing.T) {
	st, _ := newAlertTestStore(t)
	e := New(st, &config.Config{RealertDays: 7})
	if _, err := st.ImportTargets([]store.TargetSpec{{Raw: "10.9.0.0/24", Kind: "cidr"}}, "", "test"); err != nil {
		t.Fatal(err)
	}
	for _, wl := range []store.WLEntry{
		{IPSpec: "10.9.0.1", PortSpec: "22", Proto: "tcp"},         // 精确 IP+端口
		{IPSpec: "10.9.0.0/24", PortSpec: "8000-8010", Proto: "*"}, // CIDR+端口范围
		{IPSpec: "10.9.0.3", PortSpec: "*", Proto: "udp"},          // 仅 UDP 放行
	} {
		if _, err := st.AddWhitelist(wl); err != nil {
			t.Fatal(err)
		}
	}
	scanID := seedScanResults(t, st, []store.Result{
		{IP: "10.9.0.1", Port: 22, Proto: "tcp"},   // 加白 → 无告警
		{IP: "10.9.0.2", Port: 8005, Proto: "tcp"}, // CIDR+范围 → 无告警
		{IP: "10.9.0.3", Port: 53, Proto: "udp"},   // UDP 加白 → 无告警
		{IP: "10.9.0.3", Port: 53, Proto: "tcp"},   // TCP 未加白 → 告警
		{IP: "10.9.0.4", Port: 3389, Proto: "tcp"}, // 未加白 → 告警
	})
	alerts := e.AfterScan(scanID)
	if len(alerts) != 2 {
		t.Fatalf("期望 2 条告警（tcp:53 与 3389），实际 %d：%+v", len(alerts), alerts)
	}
	for _, a := range alerts {
		if a.Kind != "port" && a.Kind != "" {
			t.Errorf("端口告警 kind 应为 port，实际 %q", a.Kind)
		}
		if a.IP == "10.9.0.1" || a.IP == "10.9.0.2" || (a.IP == "10.9.0.3" && a.Proto == "udp") {
			t.Errorf("已加白端口生成了告警: %+v", a)
		}
	}
}

// TestAfterScanRealertLifecycle 验证 realert_days 间隔抑制、超期重开、
// resolved 立即重开、ignored 永久屏蔽——全部由扫描收尾驱动。
func TestAfterScanRealertLifecycle(t *testing.T) {
	st, dbPath := newAlertTestStore(t)
	e := New(st, &config.Config{RealertDays: 7})
	if _, err := st.ImportTargets([]store.TargetSpec{{Raw: "10.9.1.0/24", Kind: "cidr"}}, "", "test"); err != nil {
		t.Fatal(err)
	}
	results := []store.Result{{IP: "10.9.1.1", Port: 443, Proto: "tcp"}}
	scanID := seedScanResults(t, st, results)

	if alerts := e.AfterScan(scanID); len(alerts) != 1 {
		t.Fatalf("首次扫描应新建 1 条告警，实际 %d", len(alerts))
	}
	a, _ := st.AlertFind("10.9.1.1", 443, "tcp")
	if a == nil {
		t.Fatal("告警未入库")
	}
	// 间隔内重复扫描：只刷新 last_seen，不重复通知。
	if alerts := e.AfterScan(scanID); len(alerts) != 0 {
		t.Fatalf("realert 间隔内不应重复通知，实际 %d", len(alerts))
	}
	// 超过间隔：重开并通知。
	backdateAlert(t, dbPath, a.ID, 8*24*time.Hour)
	if alerts := e.AfterScan(scanID); len(alerts) != 1 {
		t.Fatalf("超过 realert 间隔应重开通知，实际 %d", len(alerts))
	}
	// 已解决：再次探明立即重开（不受间隔约束）。
	if err := st.UpdateAlertStatus(a.ID, "resolved", "已修复", "tester"); err != nil {
		t.Fatal(err)
	}
	if alerts := e.AfterScan(scanID); len(alerts) != 1 {
		t.Fatalf("resolved 再次探明应立即重开，实际 %d", len(alerts))
	}
	// 已忽略：确认放行，永不自动重开。
	if err := st.UpdateAlertStatus(a.ID, "ignored", "业务放行", "tester"); err != nil {
		t.Fatal(err)
	}
	backdateAlert(t, dbPath, a.ID, 30*24*time.Hour)
	if alerts := e.AfterScan(scanID); len(alerts) != 0 {
		t.Fatalf("ignored 不应被自动重开，实际 %d", len(alerts))
	}
	if cur, _ := st.AlertByID(a.ID); cur.Status != "ignored" {
		t.Fatalf("ignored 状态被篡改: %s", cur.Status)
	}
}

// TestProcessUnreachableLifecycle 验证网络不可达告警：独立 kind、原因记录、
// realert 间隔、resolved 重开、ignored 屏蔽，且不受端口白名单影响。
func TestProcessUnreachableLifecycle(t *testing.T) {
	st, dbPath := newAlertTestStore(t)
	e := New(st, &config.Config{RealertDays: 7})
	if _, err := st.ImportTargets([]store.TargetSpec{{Raw: "bad.example.com", Kind: "domain"}}, "", "test"); err != nil {
		t.Fatal(err)
	}
	// 全端口全协议加白：端口告警被放行，但不可达告警必须独立存在。
	if _, err := st.AddWhitelist(store.WLEntry{IPSpec: "*", PortSpec: "*", Proto: "*"}); err != nil {
		t.Fatal(err)
	}
	scanID, err := st.CreateScan(1, "不可达回归", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordUnreachable(scanID, "bad.example.com", store.ReasonDNSFailure); err != nil {
		t.Fatal(err)
	}
	// 幂等：同扫描重复记录不产生第二条明细。
	_ = st.RecordUnreachable(scanID, "bad.example.com", store.ReasonConnTimeout)
	if us, _ := st.Unreachables(scanID); len(us) != 1 || us[0].Reason != store.ReasonDNSFailure {
		t.Fatalf("不可达明细应幂等且保留首次原因: %+v", us)
	}

	e.ProcessUnreachable(scanID)
	a, _ := st.AlertFindUnreachable("bad.example.com")
	if a == nil {
		t.Fatal("不可达告警未生成")
	}
	if a.Kind != "unreachable" || a.Reason != store.ReasonDNSFailure || a.Port != 0 || !a.InScope {
		t.Fatalf("不可达告警字段异常: %+v", a)
	}
	// 间隔内重复：抑制。
	e.ProcessUnreachable(scanID)
	if cur, _ := st.AlertByID(a.ID); cur.Status != "new" {
		t.Fatalf("间隔内状态不应变化: %s", cur.Status)
	}
	all, _ := st.AlertsFilteredKind("", "", "unreachable", 0)
	if len(all) != 1 {
		t.Fatalf("不应重复建告警，实际 %d 条", len(all))
	}
	// 超期重开 + 原因刷新。
	backdateAlert(t, dbPath, a.ID, 8*24*time.Hour)
	_ = st.RecordUnreachable(scanID, "bad.example.com", store.ReasonConnTimeout) // OR IGNORE 保留首次原因
	e.ProcessUnreachable(scanID)
	// resolved 立即重开。
	if err := st.UpdateAlertStatus(a.ID, "resolved", "链路恢复", "tester"); err != nil {
		t.Fatal(err)
	}
	e.ProcessUnreachable(scanID)
	if cur, _ := st.AlertByID(a.ID); cur.Status != "new" {
		t.Fatalf("resolved 再次失败应重开，实际 %s", cur.Status)
	}
	// ignored 屏蔽。
	if err := st.UpdateAlertStatus(a.ID, "ignored", "确认放行", "tester"); err != nil {
		t.Fatal(err)
	}
	backdateAlert(t, dbPath, a.ID, 30*24*time.Hour)
	e.ProcessUnreachable(scanID)
	if cur, _ := st.AlertByID(a.ID); cur.Status != "ignored" {
		t.Fatalf("ignored 不应被自动重开，实际 %s", cur.Status)
	}
	// 类型筛选隔离：端口告警查询不含不可达记录。
	ports, _ := st.AlertsFilteredKind("", "", "port", 0)
	if len(ports) != 0 {
		t.Fatalf("端口告警筛选混入不可达记录: %+v", ports)
	}
}

// fakeTimeoutErr 实现 net.Error 且 Timeout()=true，模拟拨号超时。
type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "i/o timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return true }

// TestProbeHostClassification 验证连通性探测的错误分类：
// 超时→连接超时；网络不可达→网络不可达；连接拒绝/成功→可达不记录。
func TestProbeHostClassification(t *testing.T) {
	orig := probeDial
	defer func() { probeDial = orig }()

	probeDial = func(addr string, timeout time.Duration) (net.Conn, error) {
		return nil, fakeTimeoutErr{}
	}
	if reason := probeHost(context.Background(), "192.0.2.1"); reason != store.ReasonConnTimeout {
		t.Fatalf("超时应记连接超时，实际 %q", reason)
	}
	probeDial = func(addr string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("connect: network is unreachable")
	}
	if reason := probeHost(context.Background(), "192.0.2.2"); reason != store.ReasonNetUnreachable {
		t.Fatalf("网络层不可达分类错误: %q", reason)
	}
	probeDial = func(addr string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("connect: connection refused")
	}
	if reason := probeHost(context.Background(), "192.0.2.3"); reason != "" {
		t.Fatalf("连接拒绝说明主机在线，不应记录: %q", reason)
	}
}

// TestUnreachableDigestWithoutAfterScan 验证 partial/failed 场景（未跑 AfterScan）
// 不可达统计仍能独立形成摘要，供飞书汇总引用。
func TestUnreachableDigestWithoutAfterScan(t *testing.T) {
	st, _ := newAlertTestStore(t)
	e := New(st, &config.Config{RealertDays: 7})
	if _, err := st.ImportTargets([]store.TargetSpec{{Raw: "10.9.2.0/24", Kind: "cidr"}}, "", "test"); err != nil {
		t.Fatal(err)
	}
	scanID, _ := st.CreateScan(1, "partial 场景", "top")
	_ = st.RecordUnreachable(scanID, "10.9.2.9", store.ReasonConnTimeout)
	e.ProcessUnreachable(scanID)
	d := e.takeDigest(scanID)
	if d == nil || d.Unreachable != 1 || len(d.UnreachAlerts) != 1 {
		t.Fatalf("partial 场景摘要应含 1 条不可达告警: %+v", d)
	}
	if d.AlertTotal != 0 {
		t.Fatalf("不可达不应计入端口告警总数: %d", d.AlertTotal)
	}
	text := e.appendUnreachableSection("基础汇总", d)
	if !strings.Contains(text, "网络不可达：1 条") || !strings.Contains(text, "10.9.2.9") {
		t.Fatalf("飞书汇总缺少不可达段落: %s", text)
	}
}
