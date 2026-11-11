package engine

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"easm-platform/internal/store"
)

// 本文件实现「网络不可达」告警引擎：独立于端口暴露告警（kind=unreachable vs port）。
// 采集来源：
//  1. naabu 明确报告的域名解析失败（批次解析回调实时落 scan_unreachable）；
//  2. 可选连通性探测（设置 unreachable_probe=1）：对本次扫描声明目标中、台账内为单 IP
//     且零结果的资产做有界 TCP 连接测试（80/443），超时/网络不可达才记录，连接拒绝视为可达不告警。
//
// ProcessUnreachable 在每次执行收尾调用（含 partial/failed——DNS 失败恰恰会把
// 终态拉成 partial，不可达告警不能被该状态门禁挡住），复用 realert_days 间隔、
// resolved 立即重开、ignored 永久屏蔽的既有生命周期语义。

const (
	// unreachSampleLimit 是摘要中保留的不可达告警明细上限（超出仅计数）。
	unreachSampleLimit = 20
	// probeMaxTargets / probeConcurrency / probeDialTimeout / probeBudget 约束
	// 可选探测的规模与耗时，确保不拖垮收尾流程，也不影响扫描本体。
	probeMaxTargets  = 500
	probeConcurrency = 8
	probeDialTimeout = 2 * time.Second
	probeBudget      = 90 * time.Second
)

// probeDial 可注入以便测试（生产用 net.DialTimeout）。
var probeDial = func(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}

// ProcessUnreachable 处理某次扫描的不可达明细：可选探测补充采集 → 范围判定 →
// 告警去重/刷新/重开/新建，并把统计合并进该扫描的后处理摘要（供飞书汇总引用）。
// 与 AfterScan 不同：不受 done/stopped 终态门禁限制，任何收尾状态都应执行。
func (e *Engine) ProcessUnreachable(scanID int64) {
	if e.probeEnabled() {
		e.probeUnreachable(scanID)
	}
	entries, err := e.st.Unreachables(scanID)
	if err != nil {
		log.Printf("读取不可达明细失败: %v", err)
		return
	}
	if len(entries) == 0 {
		return
	}
	tgts, err := e.st.Targets()
	if err != nil {
		log.Printf("读取台账失败（不可达范围判定降级为全部范围内）: %v", err)
	}
	tmatchers := buildTargetMatchers(tgts)
	domains := map[string]bool{}
	for _, t := range tgts {
		if t.Kind == "domain" {
			domains[strings.ToLower(t.IP)] = true
		}
	}
	realert := time.Duration(e.realertDays()) * 24 * time.Hour
	now := time.Now()
	alertOutOfScope := e.outOfScopeAlert()

	created, reopened, suppressed := 0, 0, 0
	samples := make([]store.Alert, 0, unreachSampleLimit)
	addSample := func(a store.Alert) {
		if len(samples) < unreachSampleLimit {
			samples = append(samples, a)
		}
	}
	for _, u := range entries {
		inScope := matchAnyTarget(tmatchers, u.Target) || domains[strings.ToLower(u.Target)]
		if !inScope && !alertOutOfScope {
			suppressed++
			continue
		}
		existing, err := e.st.AlertFindUnreachable(u.Target)
		if err != nil {
			log.Printf("查询不可达告警失败: %v", err)
			continue
		}
		if existing != nil {
			last, _ := time.Parse(time.RFC3339, existing.LastSeenAt)
			if err := e.st.TouchAlert(existing.ID); err != nil {
				log.Printf("更新不可达告警失败: %v", err)
			}
			_ = e.st.UpdateAlertReason(existing.ID, u.Reason)
			// 与端口告警同一生命周期：忽略=确认放行；已解决再次失败立即重开；
			// 其余状态按 realert_days 间隔重复提醒。
			if existing.Status == "ignored" || (existing.Status != "resolved" && now.Sub(last) < realert) {
				suppressed++
				continue
			}
			if err := e.st.ReopenAlert(existing.ID); err != nil {
				log.Printf("重开不可达告警失败: %v", err)
				continue
			}
			existing.Status = "new"
			existing.SentFeishu = false
			existing.Reason = u.Reason
			reopened++
			addSample(*existing)
			continue
		}
		id, err := e.st.CreateUnreachableAlert(u.Target, u.Reason, inScope)
		if err != nil {
			log.Printf("创建不可达告警失败: %v", err)
			continue
		}
		created++
		addSample(store.Alert{ID: id, IP: u.Target, Proto: "", Kind: "unreachable", Reason: u.Reason, InScope: inScope})
	}
	e.mergeUnreachableDigest(scanID, created+reopened, samples)
	log.Printf("扫描 %d: 网络不可达目标 %d 个，新增告警 %d 条，重开 %d 条，抑制 %d 条",
		scanID, len(entries), created, reopened, suppressed)
	if created+reopened > 0 {
		_ = e.st.AddScanEvent(scanID, "warn", "unreachable",
			"网络不可达告警：新增 "+strconv.Itoa(created)+" 条，重开 "+strconv.Itoa(reopened)+" 条（独立于端口暴露告警，可在风险告警页按类型筛选）")
	}
}

func (e *Engine) probeEnabled() bool {
	return e.st.Setting("unreachable_probe") == "1"
}

// probeUnreachable 对台账中本次扫描零结果的单 IP 做有界 TCP 连通性探测：
// 80/443 任一可连接即视为可达；全部超时记「连接超时」，网络层不可达记「网络不可达」，
// 连接拒绝（RST）说明主机在线，不记录。整体受 probeBudget 时间预算约束。
func (e *Engine) probeUnreachable(scanID int64) {
	ips, err := e.st.LedgerIPsWithoutResults(scanID, probeMaxTargets)
	if err != nil || len(ips) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeBudget)
	defer cancel()
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			if reason := probeHost(ctx, ip); reason != "" {
				_ = e.st.RecordUnreachable(scanID, ip, reason)
			}
		}(ip)
	}
	wg.Wait()
}

// probeHost 依次尝试 80/443；返回不可达原因，可达或无法判定时返回空。
func probeHost(ctx context.Context, ip string) string {
	var timeout, unreachable bool
	for _, port := range []string{"80", "443"} {
		if ctx.Err() != nil {
			break
		}
		conn, err := probeDial(net.JoinHostPort(ip, port), probeDialTimeout)
		if err == nil {
			_ = conn.Close()
			return ""
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			timeout = true
			continue
		}
		// 网络层不可达：优先按系统 errno 结构化判定（跨 locale/Go 版本稳健），
		// 无结构化错误信息时回退到大小写无关的文案匹配（兼容包装错误与注入的 plain error）。
		if dialUnreachable(err) || containsUnreachableMsg(err) {
			unreachable = true
			continue
		}
		// 连接拒绝（RST）及其他有响应错误说明主机在线，视为可达。
		return ""
	}
	if unreachable {
		return store.ReasonNetUnreachable
	}
	if timeout {
		return store.ReasonConnTimeout
	}
	return ""
}

// containsUnreachableMsg 是网络不可达的文案兜底判定，供无法提供 syscall errno 的场景
// （非 unix 平台、被二次包装的错误、测试注入的 plain error）使用。
func containsUnreachableMsg(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "no route to host")
}

// mergeUnreachableDigest 把不可达统计并入该扫描的后处理摘要：AfterScan 已留下
// 摘要时追加字段；partial/failed 未跑 AfterScan 时新建一份只含不可达的摘要，
// 保证 NotifyScanSummary 在任何终态都能取到不可达数据。
func (e *Engine) mergeUnreachableDigest(scanID int64, total int, samples []store.Alert) {
	e.digestMu.Lock()
	defer e.digestMu.Unlock()
	if e.digests == nil {
		e.digests = map[int64]*postScanDigest{}
	}
	d := e.digests[scanID]
	if d == nil {
		d = &postScanDigest{ScanID: scanID}
		e.digests[scanID] = d
	}
	d.Unreachable += total
	d.UnreachAlerts = append(d.UnreachAlerts, samples...)
	if len(d.UnreachAlerts) > unreachSampleLimit {
		d.UnreachAlerts = d.UnreachAlerts[:unreachSampleLimit]
	}
}
