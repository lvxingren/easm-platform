package engine

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"easm-platform/internal/config"
	"easm-platform/internal/notify"
	"easm-platform/internal/store"
)

// 扫描后处理的容量约束。一次执行的结果可能达到数十万行，AfterScan / Baseline
// 必须按页流式处理：任一时刻驻留内存的结果行不超过一页，违规缓冲不超过一个分块，
// 告警明细不超过固定条数（其余只累加计数）。
const (
	// postScanPageSize 后处理每页读取的结果行数，取 store 的分页硬上限。
	postScanPageSize = store.ResultPageMaxLimit
	// postScanViolationChunk 单批处理的违规行数上限。
	postScanViolationChunk = 500
	// postScanAlertSampleLimit 通知层保留的告警明细条数硬上限，超出部分仅计数。
	postScanAlertSampleLimit = 100
	// summaryAlertListLimit 飞书汇总正文最多逐条列出的告警条数。
	summaryAlertListLimit = 50
)

// resultPager 抽象后处理所需的键集分页读取能力。生产环境由 *store.Store 实现；
// 容量测试可注入有界 fake，在不落库的前提下模拟 50 万级结果集。
type resultPager interface {
	ResultsPage(scanID, afterID int64, limit int) (store.ResultPage, error)
}

type Engine struct {
	st  *store.Store
	cfg *config.Config
	// pager 结果分页读取入口，为空时回退到 st。
	pager resultPager
	// addWL 白名单写入入口，为空时回退到 st.AddWhitelist。
	// 故障注入测试用它模拟单条写入失败，无需改动 store。
	addWL func(store.WLEntry) (int64, error)

	digestMu sync.Mutex
	// lastDigest 最近一次后处理的聚合统计：只保留一份，不随扫描次数增长。
	// AfterScan 与 NotifyScanSummary 在同一扫描流程内串行调用，用于把
	// 「有界明细 + 完整总数」传递给通知层。
	lastDigest *postScanDigest
}

func New(st *store.Store, cfg *config.Config) *Engine {
	return &Engine{st: st, cfg: cfg, pager: st}
}

// postScanDigest 是一次后处理的聚合结果：全量计数 + 有界告警样本。
// 结果行与告警都只累加计数，不驻留明细，因此内存占用与结果规模无关。
type postScanDigest struct {
	ScanID       int64
	TotalResults int           // 实际读取到的结果行数
	Whitelisted  int           // 命中白名单的行数
	Violations   int           // 未命中白名单的行数
	OutOfScope   int           // 范围外且未开启范围外告警而跳过的行数
	Suppressed   int           // 命中忽略状态或重复提醒间隔而跳过的行数
	Touched      int           // 成功刷新 last_seen_at 的已有告警数
	Created      int           // 新建告警数
	Reopened     int           // 重开告警数
	Failed       int           // 单条告警操作失败次数
	AlertTotal   int           // 需要通知的告警总数（新建 + 重开）
	MaxChunk     int           // 单批处理过的最大违规行数（用于证明分块硬上限）
	Alerts       []store.Alert // 有界样本，最多 postScanAlertSampleLimit 条
}

// addAlert 记录一条待通知告警：总数始终累加，明细到上限即停止追加。
// 样本切片创建时即按上限预分配，容量也不会超过硬上限。
func (d *postScanDigest) addAlert(a store.Alert) {
	d.AlertTotal++
	if d.Alerts == nil {
		d.Alerts = make([]store.Alert, 0, postScanAlertSampleLimit)
	}
	if len(d.Alerts) >= postScanAlertSampleLimit {
		return
	}
	d.Alerts = append(d.Alerts, a)
}

func (e *Engine) rememberDigest(d *postScanDigest) {
	e.digestMu.Lock()
	e.lastDigest = d
	e.digestMu.Unlock()
}

// takeDigest 取出并清空摘要；scanID 不匹配（迟到的旧摘要）时返回 nil。
func (e *Engine) takeDigest(scanID int64) *postScanDigest {
	e.digestMu.Lock()
	d := e.lastDigest
	e.lastDigest = nil
	e.digestMu.Unlock()
	if d == nil || d.ScanID != scanID {
		return nil
	}
	return d
}

// walkPages 用键集游标逐页遍历某次执行的结果。页切片在回调返回后即可回收，
// 因此遍历期间的额外内存上限是一页结果（≤ store.ResultPageMaxLimit 行）。
func (e *Engine) walkPages(scanID int64, fn func([]store.Result) error) error {
	pager := e.pager
	if pager == nil {
		pager = e.st
	}
	var cursor int64
	for {
		page, err := pager.ResultsPage(scanID, cursor, postScanPageSize)
		if err != nil {
			return err
		}
		if len(page.Results) == 0 {
			return nil
		}
		if err := fn(page.Results); err != nil {
			return err
		}
		if !page.HasMore {
			return nil
		}
		if page.NextCursor <= cursor {
			return fmt.Errorf("结果分页游标未前进: scan=%d cursor=%d next=%d", scanID, cursor, page.NextCursor)
		}
		cursor = page.NextCursor
	}
}

type portSet struct {
	all   bool
	ports map[int]bool
}

func parsePortSpec(spec string) (portSet, error) {
	spec = strings.TrimSpace(spec)
	if spec == "*" {
		return portSet{all: true}, nil
	}
	ps := portSet{ports: map[int]bool{}}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			a, err1 := strconv.Atoi(strings.TrimSpace(ab[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(ab[1]))
			if err1 != nil || err2 != nil || a > b {
				return ps, fmt.Errorf("端口范围非法: %s", part)
			}
			for p := a; p <= b; p++ {
				ps.ports[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return ps, fmt.Errorf("端口非法: %s", part)
			}
			ps.ports[p] = true
		}
	}
	return ps, nil
}

type wlRule struct {
	allIP  bool
	prefix netip.Prefix
	ip     netip.Addr
	ports  portSet
	proto  string
}

func parseRule(e store.WLEntry) (wlRule, error) {
	r := wlRule{ports: portSet{all: true}, proto: strings.ToLower(strings.TrimSpace(e.Proto))}
	if r.proto == "" {
		r.proto = "*"
	}
	ipSpec := strings.TrimSpace(e.IPSpec)
	if ipSpec == "*" {
		r.allIP = true
	} else if p, err := netip.ParsePrefix(ipSpec); err == nil {
		r.prefix = p.Masked()
	} else if a, err := netip.ParseAddr(ipSpec); err == nil {
		r.ip = a
	} else {
		return r, fmt.Errorf("IP 规则非法: %s", ipSpec)
	}
	ps, err := parsePortSpec(e.PortSpec)
	if err != nil {
		return r, err
	}
	r.ports = ps
	return r, nil
}

func (r wlRule) match(ip string, port int, proto string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if !r.allIP {
		if r.prefix.IsValid() {
			if !r.prefix.Contains(addr) {
				return false
			}
		} else if r.ip != addr {
			return false
		}
	}
	if !r.ports.all && !r.ports.ports[port] {
		return false
	}
	p := strings.ToLower(proto)
	if p == "" {
		p = "tcp"
	}
	if r.proto != "*" && r.proto != p {
		return false
	}
	return true
}

// ValidateEntry 校验白名单条目格式（ip|port|proto）
func ValidateEntry(e store.WLEntry) error {
	_, err := parseRule(e)
	return err
}

func (e *Engine) matchAny(ip string, port int, proto string, rules []wlRule) bool {
	for _, r := range rules {
		if r.match(ip, port, proto) {
			return true
		}
	}
	return false
}

func ResultKey(ip string, port int, proto string) string {
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%s|%d|%s", ip, port, strings.ToLower(proto))
}

// WhitelistStatus 一次性加载规则并批量判断结果，供聚合视图和导出复用 CIDR/端口范围匹配逻辑。
func (e *Engine) WhitelistStatus(results []store.Result) (map[string]bool, error) {
	rules, err := e.loadRules()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(results))
	for _, result := range results {
		out[ResultKey(result.IP, result.Port, result.Proto)] = e.matchAny(result.IP, result.Port, result.Proto, rules)
	}
	return out, nil
}

func (e *Engine) loadRules() ([]wlRule, error) {
	entries, err := e.st.Whitelist()
	if err != nil {
		return nil, err
	}
	rules := make([]wlRule, 0, len(entries))
	for _, entry := range entries {
		r, err := parseRule(entry)
		if err != nil {
			log.Printf("白名单规则解析失败，跳过: %v", err)
			continue
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (e *Engine) realertDays() int {
	if v := e.st.Setting("realert_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return e.cfg.RealertDays
}

func (e *Engine) outOfScopeAlert() bool {
	if v := e.st.Setting("alert_out_of_scope"); v != "" {
		return v == "1" || v == "true"
	}
	return e.cfg.AlertOutOfScope
}

// targetMatcher 判定一个结果 IP 是否落在台账范围内（支持单 IP / CIDR / 范围）
type targetMatcher struct {
	kind   string // ip | cidr | range
	addr   netip.Addr
	prefix netip.Prefix
	lo, hi netip.Addr
}

func (m targetMatcher) match(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	switch m.kind {
	case "cidr":
		return m.prefix.IsValid() && m.prefix.Contains(a)
	case "range":
		return a.Is4() == m.lo.Is4() && m.lo.Compare(a) <= 0 && a.Compare(m.hi) <= 0
	default:
		return m.addr == a
	}
}

// parseTargetMatcher 解析台账规格为匹配器：依次尝试 范围(a-b) / CIDR / 单 IP
func parseTargetMatcher(raw string) (targetMatcher, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return targetMatcher{}, false
	}
	if idx := strings.Index(raw, "-"); idx > 0 {
		a, err1 := netip.ParseAddr(strings.TrimSpace(raw[:idx]))
		b, err2 := netip.ParseAddr(strings.TrimSpace(raw[idx+1:]))
		if err1 == nil && err2 == nil && a.Is4() == b.Is4() && a.Compare(b) <= 0 {
			return targetMatcher{kind: "range", lo: a.Unmap(), hi: b.Unmap()}, true
		}
		return targetMatcher{}, false
	}
	if p, err := netip.ParsePrefix(raw); err == nil {
		return targetMatcher{kind: "cidr", prefix: p.Masked()}, true
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return targetMatcher{kind: "ip", addr: a.Unmap()}, true
	}
	return targetMatcher{}, false
}

// ClassifyTarget 校验并返回台账规格类型(ip/cidr/range/domain)；非法返回 ok=false。供导入校验复用。
func ClassifyTarget(raw string) (kind string, ok bool) {
	if m, ok := parseTargetMatcher(raw); ok {
		return m.kind, true
	}
	if ValidDomain(raw) {
		return "domain", true
	}
	return "", false
}

// ValidDomain 判断是否为合法域名（主机名）：不含协议/路径/端口/空白，至少两级且 TLD 含字母，
// 允许前导 *. 通配子域。IP/CIDR/范围由 parseTargetMatcher 先行处理，不会走到这里。
func ValidDomain(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 253 {
		return false
	}
	if strings.ContainsAny(s, " \t/\\?#@:;,") {
		return false
	}
	s = strings.TrimPrefix(s, "*.")
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lb := range labels {
		if lb == "" || len(lb) > 63 || strings.HasPrefix(lb, "-") || strings.HasSuffix(lb, "-") {
			return false
		}
		for _, c := range lb {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	for _, c := range tld {
		if c >= 'a' && c <= 'z' {
			return true
		}
	}
	return false
}

// ValidWhitelistIP 判断白名单 IP 规则是否合法（* / 单 IP / CIDR，白名单不支持范围）
func ValidWhitelistIP(s string) bool {
	s = strings.TrimSpace(s)
	if s == "*" {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func buildTargetMatchers(targets []store.Target) []targetMatcher {
	ms := make([]targetMatcher, 0, len(targets))
	for _, t := range targets {
		if m, ok := parseTargetMatcher(t.IP); ok {
			ms = append(ms, m)
		}
	}
	return ms
}

func matchAnyTarget(ms []targetMatcher, ip string) bool {
	for _, m := range ms {
		if m.match(ip) {
			return true
		}
	}
	return false
}

// AfterScan 在扫描入库后执行：白名单比对 → 告警去重，返回本次新增/重开的告警
// （不直接推送飞书，由结束汇总统一发送）。
//
// 结果通过 ResultsPage 键集游标逐页读取，并按 postScanViolationChunk 分块处理：
// 不再全量加载结果，也不会构造覆盖整次扫描的 violations 切片。返回的告警明细
// 以 postScanAlertSampleLimit 为硬上限，完整总数记录在内部摘要中，供
// NotifyScanSummary 生成「有界明细 + 总数」的汇总。
func (e *Engine) AfterScan(scanID int64) []store.Alert {
	d := &postScanDigest{ScanID: scanID}
	rules, err := e.loadRules()
	if err != nil {
		log.Printf("读取白名单失败: %v", err)
		return nil
	}
	tgts, err := e.st.Targets()
	if err != nil {
		log.Printf("读取台账失败: %v", err)
		return nil
	}
	// 台账规模由资产数决定（与结果行数无关）；解析为匹配器后立即释放原始切片。
	tmatchers := buildTargetMatchers(tgts)
	tgts = nil
	realert := time.Duration(e.realertDays()) * 24 * time.Hour
	now := time.Now()
	alertOutOfScope := e.outOfScopeAlert()

	// violations 复用同一个缓冲，长度不超过 postScanViolationChunk。
	violations := make([]store.Result, 0, postScanViolationChunk)
	flush := func() {
		if len(violations) == 0 {
			return
		}
		e.processViolations(violations, d, tmatchers, realert, now, alertOutOfScope)
		violations = violations[:0]
	}
	if err := e.walkPages(scanID, func(page []store.Result) error {
		d.TotalResults += len(page)
		for _, r := range page {
			if e.matchAny(r.IP, r.Port, r.Proto, rules) {
				d.Whitelisted++
				continue
			}
			violations = append(violations, r)
			if len(violations) >= postScanViolationChunk {
				flush()
			}
		}
		return nil
	}); err != nil {
		// 分页读取失败：已处理的批次不回滚，保留已产生的告警继续汇总，
		// 避免把已经落库的告警信息丢掉。
		log.Printf("读取扫描结果分页失败（已读 %d 行，违规 %d 条）: %v", d.TotalResults, d.Violations, err)
	}
	flush()
	e.rememberDigest(d)
	log.Printf("扫描 %d: 结果 %d 条（白名单 %d，违规 %d，范围外跳过 %d），新增告警 %d 条（明细样本 %d 条，单批最大 %d 行）",
		scanID, d.TotalResults, d.Whitelisted, d.Violations, d.OutOfScope, d.AlertTotal, len(d.Alerts), d.MaxChunk)
	if len(d.Alerts) == 0 {
		return nil
	}
	return d.Alerts
}

// processViolations 处理一段违规结果（长度 ≤ postScanViolationChunk）：范围内判定 →
// 告警去重/刷新/重开/新建。单条失败只记录日志并继续，与原全量版本的错误处理一致；
// 告警明细只保留有界样本，计数始终完整。
func (e *Engine) processViolations(chunk []store.Result, d *postScanDigest, tmatchers []targetMatcher, realert time.Duration, now time.Time, alertOutOfScope bool) {
	if len(chunk) > d.MaxChunk {
		d.MaxChunk = len(chunk)
	}
	for _, v := range chunk {
		d.Violations++
		inScope := matchAnyTarget(tmatchers, v.IP)
		if !inScope && !alertOutOfScope {
			d.OutOfScope++
			continue
		}
		existing, err := e.st.AlertFind(v.IP, v.Port, v.Proto)
		if err != nil {
			log.Printf("查询告警失败: %v", err)
			d.Failed++
			continue
		}
		if existing != nil {
			last, _ := time.Parse(time.RFC3339, existing.LastSeenAt)
			if err := e.st.TouchAlert(existing.ID); err != nil {
				log.Printf("更新告警失败: %v", err)
				d.Failed++
			} else {
				d.Touched++
			}
			// 忽略代表确认放行；已解决但再次被探明则立即重开，其余状态按间隔重复提醒。
			if existing.Status == "ignored" || (existing.Status != "resolved" && now.Sub(last) < realert) {
				d.Suppressed++
				continue
			}
			if err := e.st.ReopenAlert(existing.ID); err != nil {
				log.Printf("重开告警失败: %v", err)
				d.Failed++
				continue
			}
			existing.Status = "new"
			existing.SentFeishu = false
			d.Reopened++
			d.addAlert(*existing)
			continue
		}
		id, err := e.st.CreateAlert(v.IP, v.Port, v.Proto, v.Service, inScope)
		if err != nil {
			log.Printf("创建告警失败: %v", err)
			d.Failed++
			continue
		}
		d.Created++
		d.addAlert(store.Alert{ID: id, IP: v.IP, Port: v.Port, Proto: v.Proto, Service: v.Service, InScope: inScope})
	}
}

// WhitelistStatusPages 按页流式判定某次执行结果的白名单状态：每页回调一次，
// 页内 map 在回调返回后即可回收。供暴露面聚合、资产导出等可能遍历大量结果的
// 调用方使用，避免「先全量加载结果 → 再构造全量状态 map」。
func (e *Engine) WhitelistStatusPages(scanID int64, fn func([]store.Result, map[string]bool) error) error {
	rules, err := e.loadRules()
	if err != nil {
		return err
	}
	return e.walkPages(scanID, func(page []store.Result) error {
		status := make(map[string]bool, len(page))
		for _, r := range page {
			status[ResultKey(r.IP, r.Port, r.Proto)] = e.matchAny(r.IP, r.Port, r.Proto, rules)
		}
		return fn(page, status)
	})
}

// NotifyScanSummary 在任务结束时发送唯一一条飞书汇总（执行结果 + 资源峰值 + 新增风险告警）。
// 扫描过程中的资源告警只记录执行事件与日志，不再单独推送飞书。
//
// newAlerts 是 AfterScan 返回的有界明细样本；完整告警总数从 AfterScan 留下的
// 摘要中取，因此即使告警量超过样本上限，汇总里的总数也不会失真。
func (e *Engine) NotifyScanSummary(scanID int64, status string, newAlerts []store.Alert) {
	digest := e.takeDigest(scanID)
	scan, err := e.st.Scan(scanID)
	if err != nil || scan == nil {
		log.Printf("读取扫描记录失败，跳过结束汇总: %v", err)
		return
	}
	resourceAlerts, _ := e.st.CountScanEvents(scanID, "resource")
	nf := &notify.Feishu{Webhook: e.st.Setting("feishu_webhook"), Secret: e.st.Setting("feishu_secret")}
	if nf.Webhook == "" {
		// 未配置飞书：仅保留页面事件与日志，不视为失败，也不标记告警已推送。
		return
	}
	alertTotal := len(newAlerts)
	if digest != nil && digest.AlertTotal > alertTotal {
		alertTotal = digest.AlertTotal
	}
	if err := nf.Send(e.buildSummaryText(scan, status, newAlerts, alertTotal, resourceAlerts)); err != nil {
		log.Printf("飞书发送失败: %v", err)
		return
	}
	// 仅对汇总里实际列出的样本逐条标记已推送：超出样本上限的告警已计入汇总总数，
	// 不逐条回调标记，以免为数十万级告警构造无界 ID 序列。
	for _, a := range newAlerts {
		if err := e.st.MarkAlertSent(a.ID); err != nil {
			log.Printf("标记告警已发送失败: %v", err)
		}
	}
	if alertTotal > len(newAlerts) {
		log.Printf("扫描 %d: 告警 %d 条，汇总逐条标记已推送 %d 条，其余 %d 条仅计入总数",
			scanID, alertTotal, len(newAlerts), alertTotal-len(newAlerts))
	}
}

// NotifyScanResource 已废弃：资源告警不再实时推送飞书，改为统一并入任务结束汇总。

func scanStatusText(status string) string {
	switch status {
	case "done":
		return "完成"
	case "partial":
		return "部分完成"
	case "stopped":
		return "已终止"
	case "failed":
		return "失败"
	case "running":
		return "运行中"
	case "paused":
		return "已暂停"
	default:
		return status
	}
}

// buildSummaryText 生成任务结束时的唯一一条飞书汇总。alertTotal 是本次新增告警的
// 完整总数，newAlerts 只是有界明细样本，正文最多逐条列出 summaryAlertListLimit 条。
func (e *Engine) buildSummaryText(scan *store.Scan, status string, newAlerts []store.Alert, alertTotal, resourceAlerts int) string {
	var b strings.Builder
	b.WriteString("【扫描任务结束】执行 #" + strconv.FormatInt(scan.ID, 10) + " " + scan.Name + "\n")
	b.WriteString("状态：" + scanStatusText(status) + "\n")
	if t0, err := time.Parse(time.RFC3339, scan.StartedAt); err == nil {
		t1 := time.Now()
		if scan.FinishedAt != "" {
			if tf, terr := time.Parse(time.RFC3339, scan.FinishedAt); terr == nil {
				t1 = tf
			}
		}
		if d := t1.Sub(t0).Round(time.Second); d > 0 {
			b.WriteString("耗时：" + d.String() + "\n")
		}
	}
	fmt.Fprintf(&b, "目标：已处理 %d/%d，异常 %d，开放端口 %d\n",
		scan.ProcessedTargets, scan.TargetCount, scan.FailedTargets, scan.OpenPorts)
	fmt.Fprintf(&b, "资源峰值：CPU %.1f%%，RSS %.1f MiB", scan.MaxCPUPercent, float64(scan.MaxMemoryRSS)/(1024*1024))
	if resourceAlerts > 0 {
		fmt.Fprintf(&b, "（触发资源告警 %d 次）", resourceAlerts)
	}
	b.WriteString("\n")
	switch status {
	case "stopped":
		b.WriteString("说明：任务被用户或平台终止，保留终止前已发现结果，不生成端口风险告警。\n")
	case "partial", "failed":
		b.WriteString("说明：结果不完整，未执行白名单比对与端口风险告警，详见执行详情异常。\n")
	}
	if alertTotal < len(newAlerts) {
		alertTotal = len(newAlerts)
	}
	if alertTotal > 0 {
		fmt.Fprintf(&b, "新增风险告警：%d 条\n", alertTotal)
		listed := len(newAlerts)
		if listed > summaryAlertListLimit {
			listed = summaryAlertListLimit
		}
		for _, a := range newAlerts[:listed] {
			mark := "范围内"
			if !a.InScope {
				mark = "范围外"
			}
			fmt.Fprintf(&b, " - %s:%d %s %s [%s]\n", a.IP, a.Port, a.Proto, a.Service, mark)
		}
		if alertTotal > listed {
			fmt.Fprintf(&b, " …其余 %d 条见平台\n", alertTotal-listed)
		}
	} else {
		b.WriteString("新增风险告警：0 条\n")
	}
	b.WriteString("时间: " + time.Now().Format("2006-01-02 15:04:05"))
	return b.String()
}

// baselineWriteError 标记「基线白名单写入失败」，与结果分页读取错误区分开。
// 写入失败时读取流并未耗尽，但其成功前缀已落库并明确消费，因此调用方
// 绝不能再做一次收尾 flush，否则会把成功前缀重复写入。
type baselineWriteError struct {
	written int
	entry   store.WLEntry
	err     error
}

func (w *baselineWriteError) Error() string {
	return fmt.Sprintf("写入基线白名单失败（已成功 %d 条，失败条目 %s 端口 %s 协议 %s）: %v",
		w.written, w.entry.IPSpec, w.entry.PortSpec, w.entry.Proto, w.err)
}

func (w *baselineWriteError) Unwrap() error { return w.err }

// addWhitelistEntry 统一白名单写入入口：存在注入入口时优先使用。
func (e *Engine) addWhitelistEntry(entry store.WLEntry) (int64, error) {
	if e.addWL != nil {
		return e.addWL(entry)
	}
	return e.st.AddWhitelist(entry)
}

// Baseline 把最近一次扫描结果中不在白名单的条目全部加入白名单。
// 结果按页读取、按 postScanViolationChunk 分块写入：既不全量加载结果，
// 也不构造覆盖整次扫描的待写入切片。
//
// 写入进度由 consumed 游标显式跟踪：每成功写入一条就前移，失败条目仍留在
// 游标位置。因此「已成功写入的前缀」只会被提交一次，不会因为收尾 flush
// 而重复；写入错误用 baselineWriteError 标记，与分页读取错误区分处理。
func (e *Engine) Baseline() (int, error) {
	scanID, err := e.st.LatestDoneScan()
	if err != nil {
		return 0, fmt.Errorf("没有已完成的扫描: %v", err)
	}
	rules, err := e.loadRules()
	if err != nil {
		return 0, err
	}
	n := 0
	pending := make([]store.WLEntry, 0, postScanViolationChunk)
	// consumed 是 pending 中已成功写入的前缀长度；写失败时停在失败条目上。
	consumed := 0
	flush := func() error {
		for consumed < len(pending) {
			entry := pending[consumed]
			if _, err := e.addWhitelistEntry(entry); err != nil {
				return &baselineWriteError{written: n, entry: entry, err: err}
			}
			n++
			consumed++
		}
		pending = pending[:0]
		consumed = 0
		return nil
	}
	walkErr := e.walkPages(scanID, func(page []store.Result) error {
		for _, r := range page {
			if e.matchAny(r.IP, r.Port, r.Proto, rules) {
				continue
			}
			proto := r.Proto
			if proto == "" {
				proto = "tcp"
			}
			pending = append(pending, store.WLEntry{
				IPSpec: r.IP, PortSpec: strconv.Itoa(r.Port), Proto: proto,
				Service: r.Service, Owner: "baseline",
			})
			if len(pending) >= postScanViolationChunk {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		return nil
	})
	var writeErr *baselineWriteError
	if errors.As(walkErr, &writeErr) {
		// 写入失败：成功前缀已落库并计入 n，立即返回，绝不再 flush 一次。
		return n, walkErr
	}
	// 读取失败只说明后面还有未读到的结果，已读到的尾部条目仍需落盘一次；
	// flush 从 consumed 处继续，因此不会重复已成功的条目。
	if err := flush(); err != nil {
		return n, err
	}
	return n, walkErr
}
