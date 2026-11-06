package engine

import (
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"easm-platform/internal/config"
	"easm-platform/internal/notify"
	"easm-platform/internal/store"
)

type Engine struct {
	st  *store.Store
	cfg *config.Config
}

func New(st *store.Store, cfg *config.Config) *Engine {
	return &Engine{st: st, cfg: cfg}
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

// AfterScan 在扫描入库后执行：白名单比对 → 告警去重，返回本次新增/重开的告警（不直接推送飞书，由结束汇总统一发送）。
func (e *Engine) AfterScan(scanID int64) []store.Alert {
	results, err := e.st.ResultsByScan(scanID)
	if err != nil {
		log.Printf("读取扫描结果失败: %v", err)
		return nil
	}
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
	tmatchers := buildTargetMatchers(tgts)
	realert := time.Duration(e.realertDays()) * 24 * time.Hour
	now := time.Now()

	violations := []store.Result{}
	for _, r := range results {
		if !e.matchAny(r.IP, r.Port, r.Proto, rules) {
			violations = append(violations, r)
		}
	}

	var newAlerts []store.Alert
	for _, v := range violations {
		inScope := matchAnyTarget(tmatchers, v.IP)
		if !inScope && !e.outOfScopeAlert() {
			continue
		}
		existing, err := e.st.AlertFind(v.IP, v.Port, v.Proto)
		if err != nil {
			log.Printf("查询告警失败: %v", err)
			continue
		}
		if existing != nil {
			last, _ := time.Parse(time.RFC3339, existing.LastSeenAt)
			if err := e.st.TouchAlert(existing.ID); err != nil {
				log.Printf("更新告警失败: %v", err)
			}
			// 忽略代表确认放行；已解决但再次被探明则立即重开，其余状态按间隔重复提醒。
			if existing.Status == "ignored" || (existing.Status != "resolved" && now.Sub(last) < realert) {
				continue
			}
			if err := e.st.ReopenAlert(existing.ID); err != nil {
				log.Printf("重开告警失败: %v", err)
				continue
			}
			existing.Status = "new"
			existing.SentFeishu = false
			newAlerts = append(newAlerts, *existing)
			continue
		}
		id, err := e.st.CreateAlert(v.IP, v.Port, v.Proto, v.Service, inScope)
		if err != nil {
			log.Printf("创建告警失败: %v", err)
			continue
		}
		newAlerts = append(newAlerts, store.Alert{ID: id, IP: v.IP, Port: v.Port, Proto: v.Proto, Service: v.Service, InScope: inScope})
	}

	if len(newAlerts) == 0 {
		log.Printf("扫描 %d: 结果 %d 条，违规 %d 条，新增告警 0 条", scanID, len(results), len(violations))
		return nil
	}
	log.Printf("扫描 %d: 结果 %d 条，违规 %d 条，新增告警 %d 条", scanID, len(results), len(violations), len(newAlerts))
	return newAlerts
}

// NotifyScanSummary 在任务结束时发送唯一一条飞书汇总（执行结果 + 资源峰值 + 新增风险告警）。
// 扫描过程中的资源告警只记录执行事件与日志，不再单独推送飞书。
func (e *Engine) NotifyScanSummary(scanID int64, status string, newAlerts []store.Alert) {
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
	if err := nf.Send(e.buildSummaryText(scan, status, newAlerts, resourceAlerts)); err != nil {
		log.Printf("飞书发送失败: %v", err)
		return
	}
	for _, a := range newAlerts {
		if err := e.st.MarkAlertSent(a.ID); err != nil {
			log.Printf("标记告警已发送失败: %v", err)
		}
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

// buildSummaryText 生成任务结束时的唯一一条飞书汇总。
func (e *Engine) buildSummaryText(scan *store.Scan, status string, newAlerts []store.Alert, resourceAlerts int) string {
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
	if len(newAlerts) > 0 {
		fmt.Fprintf(&b, "新增风险告警：%d 条\n", len(newAlerts))
		list := newAlerts
		if len(list) > 50 {
			list = list[:50]
		}
		for _, a := range list {
			mark := "范围内"
			if !a.InScope {
				mark = "范围外"
			}
			fmt.Fprintf(&b, " - %s:%d %s %s [%s]\n", a.IP, a.Port, a.Proto, a.Service, mark)
		}
		if len(newAlerts) > 50 {
			fmt.Fprintf(&b, " …其余 %d 条见平台\n", len(newAlerts)-50)
		}
	} else {
		b.WriteString("新增风险告警：0 条\n")
	}
	b.WriteString("时间: " + time.Now().Format("2006-01-02 15:04:05"))
	return b.String()
}

// Baseline 把最近一次扫描结果中不在白名单的条目全部加入白名单
func (e *Engine) Baseline() (int, error) {
	scanID, err := e.st.LatestDoneScan()
	if err != nil {
		return 0, fmt.Errorf("没有已完成的扫描: %v", err)
	}
	results, err := e.st.ResultsByScan(scanID)
	if err != nil {
		return 0, err
	}
	rules, err := e.loadRules()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range results {
		if e.matchAny(r.IP, r.Port, r.Proto, rules) {
			continue
		}
		proto := r.Proto
		if proto == "" {
			proto = "tcp"
		}
		if _, err := e.st.AddWhitelist(store.WLEntry{
			IPSpec: r.IP, PortSpec: strconv.Itoa(r.Port), Proto: proto,
			Service: r.Service, Owner: "baseline",
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
