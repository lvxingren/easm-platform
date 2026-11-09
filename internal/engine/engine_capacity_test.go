package engine

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"easm-platform/internal/config"
	"easm-platform/internal/store"
)

// 本文件验证扫描后处理的容量约束：结果必须按游标分页流式处理，
// 内存结构与结果规模无关（一页结果 + 一个违规分块 + 一份有界告警样本）。
// 全部使用临时库或纯内存 fake 分页，绝不打开 data/easm.db，也不联网。

// newEngineCapacityStore 在临时目录建库，供后处理的元数据（白名单/台账/告警）读写。
func newEngineCapacityStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "engine-capacity.db"))
	if err != nil {
		t.Fatalf("打开临时数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// fakeResultPager 按自增 ID 现算结果、不驻留任何结果集，以固定内存模拟 50 万级结果；
// 每次只返回 id ∈ (afterID, afterID+limit] 的连续行，因此引擎读到或重复读行都会
// 直接体现在计数上。
type fakeResultPager struct {
	total    int64
	calls    int
	maxLimit int
}

func (f *fakeResultPager) ResultsPage(scanID, afterID int64, limit int) (store.ResultPage, error) {
	if scanID <= 0 {
		return store.ResultPage{}, store.ErrScanIDRequired
	}
	if limit <= 0 {
		limit = store.ResultPageDefaultLimit
	}
	if limit > store.ResultPageMaxLimit {
		limit = store.ResultPageMaxLimit
	}
	if limit > f.maxLimit {
		f.maxLimit = limit
	}
	f.calls++
	page := store.ResultPage{NextCursor: afterID}
	if afterID >= f.total {
		return page, nil
	}
	first := afterID + 1
	last := first + int64(limit) - 1
	if last > f.total {
		last = f.total
	}
	page.Results = make([]store.Result, 0, last-first+1)
	for id := first; id <= last; id++ {
		page.Results = append(page.Results, fakeResultByID(id))
	}
	page.NextCursor = last
	page.HasMore = last < f.total
	return page, nil
}

// fakeResultByID 由 ID 派生互不重复的结果：ID 空间与结果空间一一对应，
// 因此「读到的行数」是否等于 total 即可判定遍历有无遗漏/重复。
func fakeResultByID(id int64) store.Result {
	return store.Result{
		ID:     id,
		IP:     fmt.Sprintf("10.%d.%d.%d", (id>>16)&0xff, (id>>8)&0xff, id&0xff),
		Port:   1000 + int(id%40000),
		Proto:  "tcp",
		Status: 1,
	}
}

func lastDigest(t *testing.T, e *Engine) *postScanDigest {
	t.Helper()
	e.digestMu.Lock()
	defer e.digestMu.Unlock()
	if e.lastDigest == nil {
		t.Fatal("AfterScan 未记录后处理摘要")
	}
	return e.lastDigest
}

// TestAfterScanHalfMillionResultsBounded 用 50 万条等价 fake 结果证明：
// 页面遍历无遗漏无重复、页大小与违规分块都有硬上限、告警明细不随规模增长。
func TestAfterScanHalfMillionResultsBounded(t *testing.T) {
	const total = 500000
	st := newEngineCapacityStore(t)
	e := New(st, &config.Config{RealertDays: 7})

	// 无白名单 + 无台账 + 未开启范围外告警：全部违规但都在范围内判定处跳过，
	// 因此只做流式遍历与计数，不产生任何告警写入。
	fake := &fakeResultPager{total: total}
	e.pager = fake
	if alerts := e.AfterScan(1); len(alerts) != 0 {
		t.Fatalf("范围外跳过的结果不应产生告警，实际 %d 条", len(alerts))
	}
	d := lastDigest(t, e)
	if d.TotalResults != total || d.Violations != total || d.Whitelisted != 0 {
		t.Fatalf("遍历计数错误: total=%d violation=%d whitelisted=%d", d.TotalResults, d.Violations, d.Whitelisted)
	}
	if d.OutOfScope != total || d.AlertTotal != 0 || len(d.Alerts) != 0 {
		t.Fatalf("范围外/告警计数错误: outOfScope=%d alertTotal=%d sample=%d", d.OutOfScope, d.AlertTotal, len(d.Alerts))
	}
	if want := int((total + int64(postScanPageSize) - 1) / int64(postScanPageSize)); fake.calls != want {
		t.Fatalf("分页次数=%d，期望 %d（每页 %d）", fake.calls, want, postScanPageSize)
	}
	if fake.maxLimit > store.ResultPageMaxLimit {
		t.Fatalf("请求页大小 %d 超过 store 硬上限 %d", fake.maxLimit, store.ResultPageMaxLimit)
	}
	if d.MaxChunk <= 0 || d.MaxChunk > postScanViolationChunk {
		t.Fatalf("单批违规行数=%d，应落在 (0,%d] 内", d.MaxChunk, postScanViolationChunk)
	}

	// 加一条覆盖 ID 1..65535（IP 第二段=0）的白名单网段：白名单判定在流式遍历中按页进行，
	// 命中数必须精确，且仍不构造全量 violations。
	if _, err := st.AddWhitelist(store.WLEntry{IPSpec: "10.0.0.0/16", PortSpec: "*", Proto: "*", Owner: "capacity"}); err != nil {
		t.Fatalf("写入白名单失败: %v", err)
	}
	fake2 := &fakeResultPager{total: total}
	e.pager = fake2
	_ = e.AfterScan(1)
	d2 := lastDigest(t, e)
	// fakeResultByID 的 IP 为 10.(id>>16).(id>>8).(id)，ID 1..65535 落在 10.0.0.0/16 内。
	const covered = 65535
	if d2.Whitelisted != covered || d2.Violations != total-covered || d2.TotalResults != total {
		t.Fatalf("白名单流式判定错误: whitelisted=%d violation=%d total=%d",
			d2.Whitelisted, d2.Violations, d2.TotalResults)
	}
	if fake2.calls != fake.calls {
		t.Fatalf("白名单不应改变分页次数: %d != %d", fake2.calls, fake.calls)
	}
}

// TestAfterScanEmptyResults 验证空结果语义：不产生告警、不做无谓分页，摘要全零。
func TestAfterScanEmptyResults(t *testing.T) {
	st := newEngineCapacityStore(t)
	e := New(st, &config.Config{RealertDays: 7})
	scanID, err := st.CreateScan(1, "空结果", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(scanID, 0, ""); err != nil {
		t.Fatal(err)
	}
	if alerts := e.AfterScan(scanID); len(alerts) != 0 {
		t.Fatalf("空结果不应产生告警，实际 %d 条", len(alerts))
	}
	d := lastDigest(t, e)
	if d.TotalResults != 0 || d.Violations != 0 || d.Whitelisted != 0 || d.AlertTotal != 0 || d.MaxChunk != 0 {
		t.Fatalf("空结果摘要应全零: %+v", d)
	}
	// Baseline 在空结果上同样不写入任何白名单。
	if n, err := e.Baseline(); err != nil || n != 0 {
		t.Fatalf("空结果 Baseline=(%d,%v)，期望 (0,nil)", n, err)
	}
}

// TestAfterScanWhitelistSemanticsMatchReference 对同一批结果分别用
// 「分块流式」与「全量参考实现」判定，计数与告警集合必须完全一致，
// 且被白名单放行的条目绝不出现在告警里。
func TestAfterScanWhitelistSemanticsMatchReference(t *testing.T) {
	st := newEngineCapacityStore(t)
	rules := []store.WLEntry{
		{IPSpec: "10.30.0.0/24", PortSpec: "*", Proto: "*", Owner: "capacity"},
		{IPSpec: "10.30.1.5", PortSpec: "1000-1010", Proto: "tcp", Owner: "capacity"},
		{IPSpec: "10.30.2.0/24", PortSpec: "8080", Proto: "udp", Owner: "capacity"},
	}
	for _, r := range rules {
		if _, err := st.AddWhitelist(r); err != nil {
			t.Fatalf("写入白名单失败: %v", err)
		}
	}
	scanID, err := st.CreateScan(1, "白名单语义", "top")
	if err != nil {
		t.Fatal(err)
	}
	// 1500 条基础结果 (IP:端口 互不重复) + 若干专门构造的端口/协议边界行。
	rows := make([]store.Result, 0, 1506)
	for i := 0; i < 1500; i++ {
		rows = append(rows, store.Result{
			IP:     fmt.Sprintf("10.30.%d.%d", i/250, i%250),
			Port:   1000 + i,
			Proto:  "tcp",
			Status: 1,
		})
	}
	rows = append(rows,
		store.Result{IP: "10.30.1.5", Port: 1005, Proto: "tcp", Status: 1},    // 单 IP + 端口范围命中
		store.Result{IP: "10.30.1.5", Port: 1011, Proto: "tcp", Status: 1},    // 端口越界
		store.Result{IP: "10.30.2.7", Port: 8080, Proto: "udp", Status: 1},    // 网段 + 端口 + 协议命中
		store.Result{IP: "10.30.2.7", Port: 8080, Proto: "tcp", Status: 1},    // 协议不符
		store.Result{IP: "10.30.3.9", Port: 80, Proto: "tcp", Status: 1},      // 完全未命中
		store.Result{IP: "10.30.0.200", Port: 12345, Proto: "udp", Status: 1}, // CIDR 全端口全协议命中
	)
	wantAlert := make(map[string]bool, len(rows))
	// 参考期望：用独立的 netip 判定构造，避免直接复用引擎实现。
	for _, r := range rows {
		if !referenceWhitelisted(r) {
			wantAlert[ResultKey(r.IP, r.Port, r.Proto)] = true
		}
	}
	if _, err := st.InsertResultsBatch(scanID, rows); err != nil {
		t.Fatalf("写入结果失败: %v", err)
	}

	e := New(st, &config.Config{RealertDays: 7, AlertOutOfScope: true})
	alerts := e.AfterScan(scanID)
	d := lastDigest(t, e)
	if d.TotalResults != len(rows) {
		t.Fatalf("读取行数=%d，期望 %d", d.TotalResults, len(rows))
	}
	if got, want := d.Violations, len(wantAlert); got != want {
		t.Fatalf("违规行数=%d，期望 %d", got, want)
	}
	if got, want := d.Whitelisted, len(rows)-len(wantAlert); got != want {
		t.Fatalf("白名单行数=%d，期望 %d", got, want)
	}
	if d.Created != len(wantAlert) {
		t.Fatalf("新建告警=%d，期望 %d", d.Created, len(wantAlert))
	}
	if len(alerts) != minInt(postScanAlertSampleLimit, len(wantAlert)) {
		t.Fatalf("返回告警明细=%d，期望 %d（样本硬上限）", len(alerts), minInt(postScanAlertSampleLimit, len(wantAlert)))
	}
	// 告警表内的每一行都必须是参考实现判定的违规项，不能出现被白名单放行的条目。
	all, err := st.Alerts(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(wantAlert) {
		t.Fatalf("告警表行数=%d，期望 %d", len(all), len(wantAlert))
	}
	for _, a := range all {
		if !wantAlert[ResultKey(a.IP, a.Port, a.Proto)] {
			t.Fatalf("白名单放行的 %s:%d %s 不应产生告警", a.IP, a.Port, a.Proto)
		}
	}
}

// referenceWhitelisted 是测试侧的独立白名单判定：只覆盖本用例手工构造的三条规则。
func referenceWhitelisted(r store.Result) bool {
	proto := strings.ToLower(r.Proto)
	if strings.HasPrefix(r.IP, "10.30.0.") {
		return true // 10.30.0.0/24 全端口全协议
	}
	if r.IP == "10.30.1.5" && r.Port >= 1000 && r.Port <= 1010 && proto == "tcp" {
		return true
	}
	if strings.HasPrefix(r.IP, "10.30.2.") && r.Port == 8080 && proto == "udp" {
		return true
	}
	return false
}

// TestAfterScanAlertSampleBoundedWithExactTotal 验证告警明细有硬上限、
// 总数不失真：超过样本上限的告警只计数，汇总正文仍给出完整总数与剩余条数。
func TestAfterScanAlertSampleBoundedWithExactTotal(t *testing.T) {
	const total = 800
	st := newEngineCapacityStore(t)
	scanID, err := st.CreateScan(1, "告警样本", "top")
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]store.Result, 0, total)
	for i := 0; i < total; i++ {
		rows = append(rows, store.Result{IP: fmt.Sprintf("10.40.%d.%d", i/250, i%250), Port: 2000, Proto: "tcp", Status: 1})
	}
	if _, err := st.InsertResultsBatch(scanID, rows); err != nil {
		t.Fatal(err)
	}
	e := New(st, &config.Config{RealertDays: 7, AlertOutOfScope: true})

	alerts := e.AfterScan(scanID)
	d := lastDigest(t, e)
	if d.AlertTotal != total || d.Created != total {
		t.Fatalf("告警总数=%d created=%d，期望 %d", d.AlertTotal, d.Created, total)
	}
	if len(alerts) != postScanAlertSampleLimit || len(d.Alerts) != postScanAlertSampleLimit {
		t.Fatalf("告警明细=%d/%d，期望硬上限 %d", len(alerts), len(d.Alerts), postScanAlertSampleLimit)
	}
	if cap(d.Alerts) > postScanAlertSampleLimit {
		t.Fatalf("样本容量=%d，超过硬上限 %d", cap(d.Alerts), postScanAlertSampleLimit)
	}
	if n, err := st.CountResultsByScan(scanID); err != nil || n != total {
		t.Fatalf("库内结果行数=%d err=%v，期望 %d", n, err, total)
	}
	stored, err := st.Alerts(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != total {
		t.Fatalf("告警表行数=%d，期望 %d（计数不能丢）", len(stored), total)
	}

	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("读取扫描记录失败: %v", err)
	}
	text := e.buildSummaryText(scan, "done", alerts, d.AlertTotal, 0)
	if !strings.Contains(text, fmt.Sprintf("新增风险告警：%d 条", total)) {
		t.Fatalf("汇总未给出完整总数: %s", text)
	}
	if want := fmt.Sprintf("…其余 %d 条见平台", total-summaryAlertListLimit); !strings.Contains(text, want) {
		t.Fatalf("汇总剩余条数错误，期望包含 %q: %s", want, text)
	}
	if got := strings.Count(text, " - "); got != summaryAlertListLimit {
		t.Fatalf("汇总逐条列出 %d 条，期望 %d", got, summaryAlertListLimit)
	}
	// 摘要只能被通知层消费一次，取出后立即清空，避免跨扫描残留。
	if e.takeDigest(scanID) == nil {
		t.Fatal("摘要应可被通知层取出")
	}
	if e.takeDigest(scanID) != nil {
		t.Fatal("摘要取出后必须清空")
	}

	// 同一次执行再跑后处理：告警已存在且在重复提醒间隔内，不应重复计数。
	if again := e.AfterScan(scanID); len(again) != 0 {
		t.Fatalf("重复后处理不应新增告警，实际 %d 条", len(again))
	}
	d2 := lastDigest(t, e)
	if d2.AlertTotal != 0 || d2.Suppressed != total {
		t.Fatalf("重复后处理统计错误: alertTotal=%d suppressed=%d", d2.AlertTotal, d2.Suppressed)
	}
}

// TestBaselineStreamsPages 验证基线加白改为分页流式：5000 条结果全部写入白名单，
// 且第二次执行（已全部放行）不再写入任何条目。
func TestBaselineStreamsPages(t *testing.T) {
	const total = 5000
	st := newEngineCapacityStore(t)
	scanID, err := st.CreateScan(1, "基线", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(scanID, 0, ""); err != nil {
		t.Fatal(err)
	}
	fake := &fakeResultPager{total: total}
	e := New(st, &config.Config{RealertDays: 7})
	e.pager = fake
	n, err := e.Baseline()
	if err != nil {
		t.Fatalf("Baseline 失败: %v", err)
	}
	if n != total {
		t.Fatalf("写入白名单 %d 条，期望 %d", n, total)
	}
	entries, err := st.Whitelist()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != total {
		t.Fatalf("白名单行数=%d，期望 %d", len(entries), total)
	}
	if want := int((total + int64(postScanPageSize) - 1) / int64(postScanPageSize)); fake.calls != want {
		t.Fatalf("Baseline 分页次数=%d，期望 %d", fake.calls, want)
	}
	if n, err := e.Baseline(); err != nil || n != 0 {
		t.Fatalf("基线重复执行=(%d,%v)，期望 (0,nil)", n, err)
	}
}

// TestWalkPagesGuards 验证游标不前进不会造成死循环，空页与读取错误都能正常收敛。
func TestWalkPagesGuards(t *testing.T) {
	st := newEngineCapacityStore(t)
	e := New(st, &config.Config{RealertDays: 7})

	stuck := &stuckPager{}
	e.pager = stuck
	err := e.walkPages(1, func([]store.Result) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "游标未前进") {
		t.Fatalf("游标不前进应返回错误，实际: %v", err)
	}

	e.pager = &emptyPagePager{}
	if err := e.walkPages(1, func([]store.Result) error { return nil }); err != nil {
		t.Fatalf("空页应立即结束，实际: %v", err)
	}

	e.pager = &errorPager{}
	if err := e.walkPages(1, func([]store.Result) error { return nil }); err == nil {
		t.Fatal("分页读取错误应向上返回")
	}
}

type stuckPager struct{}

func (stuckPager) ResultsPage(scanID, afterID int64, limit int) (store.ResultPage, error) {
	return store.ResultPage{Results: []store.Result{{ID: afterID, IP: "10.0.0.1", Port: 80, Proto: "tcp"}}, NextCursor: afterID, HasMore: true}, nil
}

type emptyPagePager struct{}

func (emptyPagePager) ResultsPage(scanID, afterID int64, limit int) (store.ResultPage, error) {
	return store.ResultPage{NextCursor: afterID, HasMore: true}, nil
}

type errorPager struct{}

func (errorPager) ResultsPage(scanID, afterID int64, limit int) (store.ResultPage, error) {
	return store.ResultPage{}, fmt.Errorf("模拟分页读取失败")
}

// TestWhitelistStatusPagesMatchesSliceAPI 验证暴露面/资产使用的流式白名单判定
// 与一次性判定结果一致，且每页大小受限、总行数无遗漏无重复。
func TestWhitelistStatusPagesMatchesSliceAPI(t *testing.T) {
	st := newEngineCapacityStore(t)
	if _, err := st.AddWhitelist(store.WLEntry{IPSpec: "10.50.0.0/16", PortSpec: "80,443", Proto: "tcp", Owner: "capacity"}); err != nil {
		t.Fatal(err)
	}
	scanID, err := st.CreateScan(1, "流式白名单", "top")
	if err != nil {
		t.Fatal(err)
	}
	const total = 4500
	rows := make([]store.Result, 0, total)
	for i := 0; i < total; i++ {
		rows = append(rows, store.Result{
			IP:     fmt.Sprintf("10.50.%d.%d", i/250, i%250),
			Port:   []int{80, 443, 8080}[i%3],
			Proto:  "tcp",
			Status: 1,
		})
	}
	if _, err := st.InsertResultsBatch(scanID, rows); err != nil {
		t.Fatal(err)
	}
	e := New(st, &config.Config{RealertDays: 7})

	// 参考结果用一次性接口（调用方已持有全部结果时仍走同一套匹配逻辑）。
	want, err := e.WhitelistStatus(rows)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, total)
	pages := 0
	if err := e.WhitelistStatusPages(scanID, func(page []store.Result, status map[string]bool) error {
		pages++
		if len(page) > postScanPageSize {
			t.Fatalf("页大小 %d 超过上限 %d", len(page), postScanPageSize)
		}
		if len(status) != len(page) {
			t.Fatalf("状态 map 大小 %d 与页大小 %d 不一致", len(status), len(page))
		}
		for _, r := range page {
			key := ResultKey(r.IP, r.Port, r.Proto)
			if seen[key] {
				t.Fatalf("结果重复出现: %s", key)
			}
			seen[key] = true
			if status[key] != want[key] {
				t.Fatalf("%s 白名单判定不一致: 流式=%v 一次性=%v", key, status[key], want[key])
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("流式白名单判定失败: %v", err)
	}
	if len(seen) != total {
		t.Fatalf("遍历行数=%d，期望 %d", len(seen), total)
	}
	if wantPages := (total + postScanPageSize - 1) / postScanPageSize; pages != wantPages {
		t.Fatalf("回调页数=%d，期望 %d", pages, wantPages)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
