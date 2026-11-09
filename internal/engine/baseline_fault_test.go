package engine

import (
	"errors"
	"fmt"
	"sort"
	"testing"

	"easm-platform/internal/config"
	"easm-platform/internal/store"
)

// 本文件对 Baseline 的分页流式写入做故障注入：分块中间条目写入失败、
// 分页读取失败、最后一块写入失败。三类故障都必须满足：
//   - 已成功写入的前缀不会被再次提交（白名单行数 = 成功条数，且无重复行）；
//   - 返回值 n 只反映真正写入成功的条数；
//   - 读取错误与写入错误可以被区分。
// 写入入口通过 Engine.addWL 注入，不修改 store。

var (
	errSimWhitelistWrite = errors.New("模拟白名单写入失败")
	errSimPageRead       = errors.New("模拟分页读取失败")
)

// wlFaultInjector 记录每次白名单写入尝试的顺序，并在第 failAt 次（1 基）返回错误。
// delegate 通常指向 st.AddWhitelist，使数据库行数等同于真实成功写入次数。
type wlFaultInjector struct {
	delegate func(store.WLEntry) (int64, error)
	failAt   int
	calls    []store.WLEntry
}

func (f *wlFaultInjector) add(entry store.WLEntry) (int64, error) {
	f.calls = append(f.calls, entry)
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return 0, errSimWhitelistWrite
	}
	if f.delegate != nil {
		return f.delegate(entry)
	}
	return int64(len(f.calls)), nil
}

// fixedPagePager 按固定页长翻页（无视 limit），并可在第 failPage 次读取时报错，
// 用于精确构造「读取到某个中间页后失败」的场景。
type fixedPagePager struct {
	total    int64
	pageLen  int
	failPage int
	calls    int
}

func (p *fixedPagePager) ResultsPage(scanID, afterID int64, limit int) (store.ResultPage, error) {
	if scanID <= 0 {
		return store.ResultPage{}, store.ErrScanIDRequired
	}
	p.calls++
	if p.failPage > 0 && p.calls == p.failPage {
		return store.ResultPage{}, errSimPageRead
	}
	page := store.ResultPage{NextCursor: afterID}
	if afterID >= p.total {
		return page, nil
	}
	first := afterID + 1
	last := first + int64(p.pageLen) - 1
	if last > p.total {
		last = p.total
	}
	page.Results = make([]store.Result, 0, last-first+1)
	for id := first; id <= last; id++ {
		page.Results = append(page.Results, fakeResultByID(id))
	}
	page.NextCursor = last
	page.HasMore = last < p.total
	return page, nil
}

// baselineExpectedEntry 是结果 ID 对应的期望白名单条目，顺序与结果 ID 一致。
func baselineExpectedEntry(id int64) store.WLEntry {
	r := fakeResultByID(id)
	proto := r.Proto
	if proto == "" {
		proto = "tcp"
	}
	return store.WLEntry{
		IPSpec: r.IP, PortSpec: fmt.Sprintf("%d", r.Port), Proto: proto,
		Service: r.Service, Owner: "baseline",
	}
}

// assertBaselineRows 断言白名单恰好写入 want 条：无重复、无缺失，且按结果顺序落库。
func assertBaselineRows(t *testing.T, st *store.Store, want int) {
	t.Helper()
	entries, err := st.Whitelist()
	if err != nil {
		t.Fatalf("读取白名单失败: %v", err)
	}
	if len(entries) != want {
		t.Fatalf("白名单行数=%d，期望 %d（重复写入或丢失）", len(entries), want)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	seen := make(map[string]bool, len(entries))
	for i, en := range entries {
		key := en.IPSpec + "|" + en.PortSpec + "|" + en.Proto
		if seen[key] {
			t.Fatalf("白名单条目重复: %s（已成功前缀被重复提交）", key)
		}
		seen[key] = true
		wantEntry := baselineExpectedEntry(int64(i + 1))
		if en.IPSpec != wantEntry.IPSpec || en.PortSpec != wantEntry.PortSpec ||
			en.Proto != wantEntry.Proto || en.Owner != wantEntry.Owner {
			t.Fatalf("第 %d 条白名单顺序/内容错误: got %+v want %+v", i+1, en, wantEntry)
		}
	}
}

func newBaselineFaultEngine(t *testing.T, pager resultPager, inject *wlFaultInjector) (*Engine, *store.Store) {
	t.Helper()
	st := newEngineCapacityStore(t)
	scanID, err := st.CreateScan(1, "基线故障注入", "top")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(scanID, 0, ""); err != nil {
		t.Fatal(err)
	}
	e := New(st, &config.Config{RealertDays: 7})
	e.pager = pager
	e.addWL = inject.add
	return e, st
}

// TestBaselineMidChunkWriteFailureNoDuplicatePrefix 让第二个 500 条块的中间条目失败：
// 已成功的 749 条必须只落库一次，返回的 n 只计成功条数，且失败后不再继续分页。
func TestBaselineMidChunkWriteFailureNoDuplicatePrefix(t *testing.T) {
	const total = 5000
	const failAt = 750 // 第二个块（501..1000）中间
	pager := &fakeResultPager{total: total}
	inject := &wlFaultInjector{failAt: failAt}
	e, st := newBaselineFaultEngine(t, pager, inject)
	inject.delegate = st.AddWhitelist

	n, err := e.Baseline()
	if err == nil {
		t.Fatal("中间条目写入失败应返回错误")
	}
	var writeErr *baselineWriteError
	if !errors.As(err, &writeErr) {
		t.Fatalf("应返回写入错误，实际 %T: %v", err, err)
	}
	if !errors.Is(err, errSimWhitelistWrite) {
		t.Fatalf("错误链应保留底层失败原因，实际: %v", err)
	}
	if n != failAt-1 {
		t.Fatalf("返回成功条数=%d，期望 %d", n, failAt-1)
	}
	if writeErr.written != n {
		t.Fatalf("错误中的已成功条数=%d，与返回值 %d 不一致", writeErr.written, n)
	}
	// 失败条目只尝试一次：成功前缀绝不能被再次提交。
	if len(inject.calls) != failAt {
		t.Fatalf("白名单写入尝试 %d 次，期望 %d 次（成功后不得重试）", len(inject.calls), failAt)
	}
	assertBaselineRows(t, st, failAt-1)
	if pager.calls != 1 {
		t.Fatalf("写入失败后仍继续分页 %d 次，应在首个失败处停止", pager.calls)
	}
}

// TestBaselinePageReadFailureFlushesReadTail 让第 5 页读取失败：
// 已读到的 1200 条全部落库（含最后一个未满块的 200 条），且返回的是读取错误而非写入错误。
func TestBaselinePageReadFailureFlushesReadTail(t *testing.T) {
	const total = 3000
	const pageLen = 300
	const failPage = 5 // 已读 4 页 = 1200 行，其中 1000 行已在满块时写入
	const read = (failPage - 1) * pageLen
	pager := &fixedPagePager{total: total, pageLen: pageLen, failPage: failPage}
	inject := &wlFaultInjector{}
	e, st := newBaselineFaultEngine(t, pager, inject)
	inject.delegate = st.AddWhitelist

	n, err := e.Baseline()
	if !errors.Is(err, errSimPageRead) {
		t.Fatalf("应返回分页读取错误，实际: %v", err)
	}
	var writeErr *baselineWriteError
	if errors.As(err, &writeErr) {
		t.Fatalf("分页读取错误不应被识别为写入错误: %v", err)
	}
	if n != read {
		t.Fatalf("成功写入 %d 条，期望 %d（已读行应全部落盘）", n, read)
	}
	if len(inject.calls) != read {
		t.Fatalf("白名单写入尝试 %d 次，期望 %d 次", len(inject.calls), read)
	}
	assertBaselineRows(t, st, read)
	if pager.calls != failPage {
		t.Fatalf("分页读取次数=%d，期望 %d", pager.calls, failPage)
	}
}

// TestBaselineLastChunkWriteFailure 让最后一个块的末尾条目失败：
// 之前的 1199 条只落库一次，收尾 flush 不得重放成功前缀。
func TestBaselineLastChunkWriteFailure(t *testing.T) {
	const total = 1200
	pager := &fakeResultPager{total: total}
	inject := &wlFaultInjector{failAt: total}
	e, st := newBaselineFaultEngine(t, pager, inject)
	inject.delegate = st.AddWhitelist

	n, err := e.Baseline()
	if err == nil {
		t.Fatal("最后一块写入失败应返回错误")
	}
	var writeErr *baselineWriteError
	if !errors.As(err, &writeErr) {
		t.Fatalf("应返回写入错误，实际 %T: %v", err, err)
	}
	if n != total-1 {
		t.Fatalf("返回成功条数=%d，期望 %d", n, total-1)
	}
	if len(inject.calls) != total {
		t.Fatalf("白名单写入尝试 %d 次，期望 %d 次（收尾 flush 不得重放前缀）", len(inject.calls), total)
	}
	assertBaselineRows(t, st, total-1)
}

// TestBaselineInjectedWriterSuccessExact 守卫正常路径：接入写入入口后，
// 成功计数与落库顺序与直接写库完全一致。
func TestBaselineInjectedWriterSuccessExact(t *testing.T) {
	const total = 1200
	pager := &fakeResultPager{total: total}
	inject := &wlFaultInjector{}
	e, st := newBaselineFaultEngine(t, pager, inject)
	inject.delegate = st.AddWhitelist

	n, err := e.Baseline()
	if err != nil {
		t.Fatalf("Baseline 失败: %v", err)
	}
	if n != total {
		t.Fatalf("成功条数=%d，期望 %d", n, total)
	}
	if len(inject.calls) != total {
		t.Fatalf("写入尝试 %d 次，期望 %d 次", len(inject.calls), total)
	}
	assertBaselineRows(t, st, total)
}
