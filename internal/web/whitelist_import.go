package web

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"strconv"
	"strings"

	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

// ErrNoPortSpec 表示某行只给了 IP/网段而未给端口——这是自动匹配展开的前置信号。
// 用哨兵错误配合 errors.Is 判定，替代对错误文案的字符串匹配，解析器措辞调整不再
// 静默破坏自动匹配触发。
var ErrNoPortSpec = errors.New("未解析到端口")

// 白名单 Excel/CSV 模板列名候选（与资产导入共用一套表头识别机制，小写精确匹配）。
// 模板列序固定为「IP/网段、端口、服务、备注、原因」；协议/负责人/业务 为可选列，仅在带表头时按列名识别。
var (
	wlIPColCandidates       = []string{"ip/网段", "ip", "公网ip", "公网地址", "ip地址", "网段", "cidr", "目标", "目标ip", "地址", "host", "主机", "主机ip", "资产", "资产地址", "target", "asset"}
	wlPortColCandidates     = []string{"端口", "端口号", "开放端口", "服务端口", "port", "ports"}
	wlProtoColCandidates    = []string{"协议", "传输协议", "proto", "protocol"}
	wlServiceColCandidates  = []string{"服务", "服务名", "应用", "组件", "中间件", "service"}
	wlRemarkColCandidates   = []string{"备注", "备注说明", "说明", "描述", "remark", "note", "comment", "comments"}
	wlReasonColCandidates   = []string{"原因", "加白原因", "放行原因", "reason"}
	wlOwnerColCandidates    = []string{"负责人", "业务负责人", "责任人", "维护人员", "联系人", "owner", "contact"}
	wlBusinessColCandidates = []string{"业务", "业务归属", "业务线", "归属", "business"}
)

// wlColumns 记录表格中各字段命中的列号，-1 表示文件未提供该列。
type wlColumns struct{ ip, port, proto, service, remark, reason, owner, business int }

func newWLColumns() wlColumns {
	return wlColumns{-1, -1, -1, -1, -1, -1, -1, -1}
}

// identifyWhitelistColumns 按首行表头识别白名单列；命中任一候选列名即视为带表头。
// 无表头时按模板列序回落为 IP、端口、服务、备注（协议列需表头才生效）。
func identifyWhitelistColumns(records [][]string) (wlColumns, bool) {
	cols := newWLColumns()
	if len(records) == 0 {
		return cols, false
	}
	pick := func(header string, cands []string, cur, idx int) int {
		if cur < 0 && matchImportCol(header, cands) {
			return idx
		}
		return cur
	}
	for i, h := range records[0] {
		cols.ip = pick(h, wlIPColCandidates, cols.ip, i)
		cols.port = pick(h, wlPortColCandidates, cols.port, i)
		cols.proto = pick(h, wlProtoColCandidates, cols.proto, i)
		cols.service = pick(h, wlServiceColCandidates, cols.service, i)
		cols.remark = pick(h, wlRemarkColCandidates, cols.remark, i)
		cols.reason = pick(h, wlReasonColCandidates, cols.reason, i)
		cols.owner = pick(h, wlOwnerColCandidates, cols.owner, i)
		cols.business = pick(h, wlBusinessColCandidates, cols.business, i)
	}
	if cols.ip >= 0 || cols.port >= 0 || cols.proto >= 0 || cols.service >= 0 || cols.remark >= 0 || cols.reason >= 0 || cols.owner >= 0 || cols.business >= 0 {
		return cols, true
	}
	return wlColumns{ip: 0, port: 1, proto: -1, service: 2, remark: 3, reason: -1, owner: -1, business: -1}, false
}

// readWhitelistTable 按扩展名读取上传的白名单表格：Excel（.xlsx/.xlsm）走 xlsx 解析，其余按 CSV。
func readWhitelistTable(name string, file multipart.File) ([][]string, error) {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".xlsx") || strings.HasSuffix(lower, ".xlsm") {
		return xlsxRows(file)
	}
	return csvRows(file)
}

// wlTableImport 一次表格解析的结果集合。
type wlTableImport struct {
	manual     []store.WLEntry
	autoIPs    []string
	autoRemark map[string]string // 自动匹配 IP 的行内备注（仅表格导入有）
	autoReason map[string]string // 自动匹配 IP 的行内原因（仅表格导入有）
	skipped    []string
}

// parseWhitelistTable 把 Excel/CSV 行转成白名单条目：IP/网段 + 端口（多端口逗号分隔）+ 协议（可选）
// 复用文本导入的同一套行解析规则，服务/备注/负责人/业务 从对应列直接取值。
// 逐行容错：非法 IP/端口/协议、端口为空且未勾选自动匹配、批内重复规则都进入 skipped 并给出原因，
// 不阻断整批导入（与资产导入的透明化策略一致）；仅当完全缺少 IP 列时才整体报错。
func parseWhitelistTable(records [][]string, autoMatch bool) (*wlTableImport, error) {
	cols, hasHeader := identifyWhitelistColumns(records)
	if cols.ip < 0 {
		return nil, fmt.Errorf("未识别到「IP/网段」列：模板首行请为「IP/网段、端口、服务、备注」（或按此列序填写数据）")
	}
	// 解析阶段即拒绝超限表格，避免先全量展开再拒绝（自动匹配会把一行放大为多端口条目）。
	if dataRows := len(records); dataRows > wlImportMaxRows+1 {
		return nil, fmt.Errorf("表格行数过多（%d 行），超过单次导入上限 %d，请分批导入", dataRows, wlImportMaxRows)
	}
	out := &wlTableImport{autoRemark: map[string]string{}, autoReason: map[string]string{}}
	start := 0
	if hasHeader {
		start = 1
	}
	for i := start; i < len(records); i++ {
		rec := records[i]
		at := func(idx int) string {
			if idx < 0 || idx >= len(rec) {
				return ""
			}
			return strings.TrimSpace(strings.ReplaceAll(rec[idx], "\ufeff", ""))
		}
		line := fmt.Sprintf("第 %d 行", i+1)
		ipCell := at(cols.ip)
		if ipCell == "" {
			continue // 空行忽略
		}
		if proto := strings.ToLower(at(cols.proto)); proto != "" && proto != "tcp" && proto != "udp" && proto != "*" {
			out.skipped = append(out.skipped, fmt.Sprintf("%s 协议非法「%s」（仅支持 tcp/udp/*）", line, at(cols.proto)))
			continue
		}
		// 单元格留空与多写法（"1.2.3.4:3306"、"22,80"、"22-80"、行尾 udp）都交给行解析统一处理
		parts := []string{ipCell}
		for _, cell := range []string{at(cols.port), at(cols.proto)} {
			if cell != "" {
				parts = append(parts, cell)
			}
		}
		remark := at(cols.remark)
		reason := at(cols.reason)
		entries, perr := parseWhitelistLines(strings.Join(parts, " "))
		if perr != nil {
			if autoMatch && errors.Is(perr, ErrNoPortSpec) {
				ip := strings.Fields(ipCell)[0]
				if net.ParseIP(ip) != nil {
					out.autoIPs = append(out.autoIPs, ip)
					if remark != "" {
						out.autoRemark[ip] = remark
					}
					if reason != "" {
						out.autoReason[ip] = reason
					}
				} else {
					out.skipped = append(out.skipped, fmt.Sprintf("%s %s（仅单 IP 可自动匹配）", line, ip))
				}
				continue
			}
			out.skipped = append(out.skipped, fmt.Sprintf("%s %v", line, perr))
			continue
		}
		service, owner, business := at(cols.service), at(cols.owner), at(cols.business)
		for _, e := range entries {
			if e.Service == "" {
				e.Service = service
			}
			if owner != "" {
				e.Owner = owner
			}
			e.Remark, e.Business, e.Reason = remark, business, reason
			out.manual = append(out.manual, e)
		}
	}
	return out, nil
}

// dedupeWLEntries 去掉本批中匹配规则完全相同（IP+端口+协议）的重复条目，返回保留项与重复说明。
func dedupeWLEntries(entries []store.WLEntry) ([]store.WLEntry, []string) {
	out := make([]store.WLEntry, 0, len(entries))
	seen := map[string]bool{}
	var dups []string
	for _, e := range entries {
		key := store.WhitelistRuleKey(e.IPSpec, e.PortSpec, e.Proto)
		if seen[key] {
			dups = append(dups, fmt.Sprintf("%s %s/%s（批内规则重复）", e.IPSpec, e.PortSpec, e.Proto))
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out, dups
}

// dedupeAgainstRules 跳过与 rules 中已有规则完全相同的条目（库内已存在或同批已保留），
// 并把保留项的键写回 rules，使后续集合不会与前面重复。返回待入库项与跳过说明。
func dedupeAgainstRules(entries []store.WLEntry, rules map[string]bool) ([]store.WLEntry, []string) {
	out := make([]store.WLEntry, 0, len(entries))
	var dups []string
	for _, e := range entries {
		key := store.WhitelistRuleKey(e.IPSpec, e.PortSpec, e.Proto)
		if rules[key] {
			dups = append(dups, fmt.Sprintf("%s %s/%s（已在白名单）", e.IPSpec, e.PortSpec, e.Proto))
			continue
		}
		rules[key] = true
		out = append(out, e)
	}
	return out, dups
}

// dedupeWLIPs 去掉本批自动匹配 IP 的重复项，返回保留项与重复说明。
func dedupeWLIPs(ips []string) ([]string, []string) {
	out := make([]string, 0, len(ips))
	seen := map[string]bool{}
	var dups []string
	for _, ip := range ips {
		if seen[ip] {
			dups = append(dups, ip+"（批内重复）")
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out, dups
}

// ---------- 导入计划（预览 / 确认导入 / 一步式导入共用）----------

const (
	wlRemarkMaxBytes = 2000     // 单条备注上限，与行内编辑备注一致
	wlImportMaxRows  = 5000     // 单次导入解析/写入上限（预览、确认、一步式共用）
	wlImportMaxBytes = 16 << 20 // 上传请求体上限（16 MiB），防御超大文件与压缩炸弹
	// wlPreviewMaxRows 与写入上限一致：预览必须呈现全部可导入条目，否则未渲染行无法勾选，
	// 超出预览上限的部分将无法提交（避免与 apply 的 wlImportMaxRows 形成矛盾的次序）。
	wlPreviewMaxRows = wlImportMaxRows
)

// wlImportError 带 HTTP 状态语义的导入错误（存储失败 500，解析失败 400）。
type wlImportError struct {
	status int
	msg    string
}

func (e *wlImportError) Error() string { return e.msg }

// wlImportPlan 解析完成、尚未写入的导入计划：自动匹配已展开为具体端口，
// 批内已去重，并标记出哪些规则已在白名单中（预览默认不勾选）。
type wlImportPlan struct {
	Entries []store.WLEntry
	Exists  []bool
	Skipped []string
	Parsed  int
}

// pending 返回计划中尚未存在于白名单的条目，已存在的规则给出跳过说明。
func (p *wlImportPlan) pending() ([]store.WLEntry, []string) {
	var fresh []store.WLEntry
	var dups []string
	for i, e := range p.Entries {
		if p.Exists[i] {
			dups = append(dups, fmt.Sprintf("%s %s/%s（已在白名单）", e.IPSpec, e.PortSpec, e.Proto))
			continue
		}
		fresh = append(fresh, e)
	}
	return fresh, dups
}

// buildWhitelistImportPlan 解析文本框与上传文件（两者可同时提交），完成批内去重、
// 自动匹配端口展开与库内规则标记。预览与一步式导入走同一入口，保证两侧语义一致。
func (s *Server) buildWhitelistImportPlan(w http.ResponseWriter, r *http.Request) (*wlImportPlan, error) {
	// 上传体积护栏：先限制请求体大小，超大文件/压缩炸弹在 multipart 解析阶段即被截断。
	r.Body = http.MaxBytesReader(w, r.Body, wlImportMaxBytes)
	autoMatch := r.FormValue("auto_match") == "on"
	// 批量备注：作为兜底应用到本批未单独填写备注的条目（含自动匹配），逐行备注优先。
	batchRemark := strings.TrimSpace(r.FormValue("remark"))
	var manual []store.WLEntry
	var autoIPs, skipped []string
	autoRemark := map[string]string{}
	autoReason := map[string]string{}
	// 1) 文本框逐行（保持既有严格语义：非法行直接报错）。
	if text := strings.TrimSpace(r.FormValue("entries")); text != "" {
		m, a, sk, err := parseWhitelistImport(text, autoMatch)
		if err != nil {
			return nil, &wlImportError{http.StatusBadRequest, err.Error()}
		}
		manual, autoIPs, skipped = m, a, sk
	}
	// 2) Excel / CSV 模板文件（列名自动识别，非法行逐行跳过并回显原因）。
	if file, hdr, err := r.FormFile("file"); err == nil {
		defer file.Close()
		if name := strings.TrimSpace(hdr.Filename); name != "" {
			if strings.HasSuffix(strings.ToLower(name), ".txt") {
				data, rerr := io.ReadAll(io.LimitReader(file, wlImportMaxBytes+1))
				if rerr != nil {
					return nil, &wlImportError{http.StatusBadRequest, "读取文件失败: " + rerr.Error()}
				}
				if len(data) > wlImportMaxBytes {
					return nil, &wlImportError{http.StatusBadRequest, fmt.Sprintf("文本文件过大（超过 %d MiB），请分批导入", wlImportMaxBytes>>20)}
				}
				m, a, sk, perr := parseWhitelistImport(string(data), autoMatch)
				if perr != nil {
					return nil, &wlImportError{http.StatusBadRequest, perr.Error()}
				}
				manual, autoIPs, skipped = append(manual, m...), append(autoIPs, a...), append(skipped, sk...)
			} else {
				rows, rerr := readWhitelistTable(name, file)
				if rerr != nil {
					return nil, &wlImportError{http.StatusBadRequest, rerr.Error()}
				}
				tab, perr := parseWhitelistTable(rows, autoMatch)
				if perr != nil {
					return nil, &wlImportError{http.StatusBadRequest, perr.Error()}
				}
				manual, autoIPs, skipped = append(manual, tab.manual...), append(autoIPs, tab.autoIPs...), append(skipped, tab.skipped...)
				for ip, remark := range tab.autoRemark {
					if autoRemark[ip] == "" {
						autoRemark[ip] = remark
					}
				}
				for ip, reason := range tab.autoReason {
					if autoReason[ip] == "" {
						autoReason[ip] = reason
					}
				}
			}
		}
	}
	// 3) 批内去重：同一 IP+端口+协议 只算一条，重复项回显而非静默入库。
	uniqEntries, dupEntries := dedupeWLEntries(manual)
	manual, skipped = uniqEntries, append(skipped, dupEntries...)
	uniqIPs, dupIPs := dedupeWLIPs(autoIPs)
	autoIPs, skipped = uniqIPs, append(skipped, dupIPs...)
	if len(manual) == 0 && len(autoIPs) == 0 {
		msg := "未解析到有效白名单条目"
		if len(skipped) > 0 {
			msg += "：本批全部行都被跳过（" + strings.Join(skipped[:min(len(skipped), 3)], "；") + "）"
		}
		return nil, &wlImportError{http.StatusBadRequest, msg}
	}
	parsed := len(manual) + len(autoIPs)
	for i := range manual {
		manual[i].Source = "manual"
		if manual[i].Remark == "" {
			manual[i].Remark = batchRemark
		}
	}
	// 4) 自动匹配仅对台账内存在的单 IP 生效，展开为其历史开放端口。
	ledger, err := s.st.TargetIPSet()
	if err != nil {
		return nil, &wlImportError{http.StatusInternalServerError, "读取资产台账失败: " + err.Error()}
	}
	var kept []string
	for _, ip := range autoIPs {
		if ledger[ip] {
			kept = append(kept, ip)
		} else {
			skipped = append(skipped, ip+"（不在台账）")
		}
	}
	autoEntries := []store.WLEntry{}
	if len(kept) > 0 {
		open, err := s.st.OpenPortsByIPs(kept)
		if err != nil {
			return nil, &wlImportError{http.StatusInternalServerError, "查询已识别端口失败: " + err.Error()}
		}
		for _, op := range open {
			remark := "自动匹配已识别端口"
			if batchRemark != "" {
				remark = batchRemark
			}
			if rowRemark := autoRemark[op.IP]; rowRemark != "" {
				remark = rowRemark
			}
			autoEntries = append(autoEntries, store.WLEntry{
				IPSpec: op.IP, PortSpec: strconv.Itoa(op.Port), Proto: op.Proto, Service: op.Service,
				Owner: "import", Source: "auto_match", Remark: remark, Reason: autoReason[op.IP],
			})
		}
	}
	// 5) 库内规则 + 本批跨组（手动/自动）统一去重：手动行与自动匹配展开出的相同
	//    IP+端口+协议只保留先出现的一条，其余记入 skipped，避免一步式导入重复写入。
	rules, err := s.st.WhitelistRuleSet()
	if err != nil {
		return nil, &wlImportError{http.StatusInternalServerError, "读取现有白名单失败: " + err.Error()}
	}
	batch := map[string]bool{}
	plan := &wlImportPlan{Skipped: skipped, Parsed: parsed}
	for _, group := range [][]store.WLEntry{manual, autoEntries} {
		for _, e := range group {
			key := store.WhitelistRuleKey(e.IPSpec, e.PortSpec, e.Proto)
			if batch[key] {
				plan.Skipped = append(plan.Skipped, fmt.Sprintf("%s %s/%s（本批手动与自动匹配规则重复，保留先出现的一条）", e.IPSpec, e.PortSpec, e.Proto))
				continue
			}
			batch[key] = true
			plan.Entries = append(plan.Entries, e)
			plan.Exists = append(plan.Exists, rules[key])
		}
	}
	// 6) 与确认导入路径一致的强约束（客户端/文件数据均不可信）：总条数上限 + 逐条校验 + 备注限长，
	//    使一步式导入与两步式共享同一套护栏。
	if len(plan.Entries) > wlImportMaxRows {
		return nil, &wlImportError{http.StatusBadRequest, fmt.Sprintf("本次可导入条目 %d 条，超过单次上限 %d，请分批导入", len(plan.Entries), wlImportMaxRows)}
	}
	for i, e := range plan.Entries {
		if len(e.Remark) > wlRemarkMaxBytes {
			return nil, &wlImportError{http.StatusBadRequest, fmt.Sprintf("第 %d 条备注过长（%d 字节），请控制在 %d 字节以内", i+1, len(e.Remark), wlRemarkMaxBytes)}
		}
		if err := engine.ValidateEntry(e); err != nil {
			return nil, &wlImportError{http.StatusBadRequest, fmt.Sprintf("第 %d 条条目非法: %v", i+1, err)}
		}
	}
	return plan, nil
}

// apiImportWhitelist 一步式导入（解析后立即写入）：供脚本/curl 等无需预览的场景使用，
// 页面导入已改用「解析预览 → 确认导入」两个接口。写入前同样跳过库内已有的相同规则。
func (s *Server) apiImportWhitelist(w http.ResponseWriter, r *http.Request) {
	plan, err := s.buildWhitelistImportPlan(w, r)
	if err != nil {
		s.audit(r, "导入白名单", "", "失败: "+err.Error())
		writeWlImportError(w, err)
		return
	}
	fresh, existDups := plan.pending()
	skipped := append(append([]string{}, plan.Skipped...), existDups...)
	manualAdded, autoAdded := 0, 0
	for _, e := range fresh {
		if _, err := s.st.AddWhitelist(e); err != nil {
			s.audit(r, "导入白名单", "", fmt.Sprintf("写入失败（已写入 %d 条）: %v", manualAdded+autoAdded, err))
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if e.Source == "auto_match" {
			autoAdded++
		} else {
			manualAdded++
		}
	}
	s.audit(r, "导入白名单", "", fmt.Sprintf("手动 %d 条，自动匹配 %d 条，跳过 %d 项", manualAdded, autoAdded, len(skipped)))
	writeJSON(w, 200, map[string]interface{}{
		"parsed": plan.Parsed, "added": manualAdded + autoAdded,
		"manual_added": manualAdded, "auto_added": autoAdded, "skipped": skipped,
	})
}

// writeWlImportError 统一回显导入错误：存储失败 500，其余 400。
func writeWlImportError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if e, ok := err.(*wlImportError); ok {
		status = e.status
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// apiWhitelistImportPreview 解析上传的白名单文本/表格但不写入，返回可逐条勾选的预览清单。
func (s *Server) apiWhitelistImportPreview(w http.ResponseWriter, r *http.Request) {
	plan, err := s.buildWhitelistImportPlan(w, r)
	if err != nil {
		writeWlImportError(w, err)
		return
	}
	type row struct {
		IPSpec   string `json:"ip_spec"`
		PortSpec string `json:"port_spec"`
		Proto    string `json:"proto"`
		Service  string `json:"service"`
		Owner    string `json:"owner"`
		Business string `json:"business"`
		Remark   string `json:"remark"`
		Reason   string `json:"reason"`
		Source   string `json:"source"`
		Exists   bool   `json:"exists"`
	}
	list := make([]row, 0, min(len(plan.Entries), wlPreviewMaxRows))
	existing, truncated := 0, 0
	for i, e := range plan.Entries {
		if plan.Exists[i] {
			existing++
		}
		if len(list) < wlPreviewMaxRows {
			list = append(list, row{IPSpec: e.IPSpec, PortSpec: e.PortSpec, Proto: e.Proto, Service: e.Service,
				Owner: e.Owner, Business: e.Business, Remark: e.Remark, Reason: e.Reason, Source: e.Source, Exists: plan.Exists[i]})
			continue
		}
		truncated++
	}
	writeJSON(w, 200, map[string]interface{}{
		"entries": list, "skipped": plan.Skipped, "total": len(plan.Entries),
		"existing": existing, "parsed": plan.Parsed, "truncated": truncated,
	})
}

// apiWhitelistImportApply 按预览勾选结果写入白名单：客户端数据不可信，逐条重新校验与限长，
// 再跳过库内已有的相同规则，因此重复提交或两人同时导入也不会产生重复规则。
func (s *Server) apiWhitelistImportApply(w http.ResponseWriter, r *http.Request) {
	if err := parseAnyForm(r); err != nil {
		writeJSON(w, 400, map[string]string{"error": "表单解析失败"})
		return
	}
	ips := r.Form["ip"]
	if len(ips) == 0 {
		writeJSON(w, 400, map[string]string{"error": "未选择任何要导入的条目"})
		return
	}
	if len(ips) > wlImportMaxRows {
		writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("单次导入条目过多（%d 超过 %d），请分批提交", len(ips), wlImportMaxRows)})
		return
	}
	cell := func(vals []string, i int, def string) string {
		if i < len(vals) {
			if v := strings.TrimSpace(vals[i]); v != "" {
				return v
			}
		}
		return def
	}
	entries := make([]store.WLEntry, 0, len(ips))
	for i := range ips {
		source := cell(r.Form["source"], i, "manual")
		if source != "auto_match" {
			source = "manual"
		}
		e := store.WLEntry{
			IPSpec:   cell(r.Form["ip"], i, ""),
			PortSpec: cell(r.Form["port"], i, ""),
			Proto:    cell(r.Form["proto"], i, "tcp"),
			Service:  cell(r.Form["service"], i, ""),
			Owner:    cell(r.Form["owner"], i, "import"),
			Business: cell(r.Form["business"], i, ""),
			Remark:   cell(r.Form["remark"], i, ""),
			Reason:   cell(r.Form["reason"], i, ""),
			Source:   source,
		}
		if len(e.Remark) > wlRemarkMaxBytes {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("第 %d 行备注过长，请控制在 %d 字节以内", i+1, wlRemarkMaxBytes)})
			return
		}
		if err := engine.ValidateEntry(e); err != nil {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("第 %d 行条目非法: %v", i+1, err)})
			return
		}
		entries = append(entries, e)
	}
	rules, err := s.st.WhitelistRuleSet()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "读取现有白名单失败: " + err.Error()})
		return
	}
	fresh, existDups := dedupeAgainstRules(entries, rules)
	manualAdded, autoAdded := 0, 0
	for _, e := range fresh {
		if _, err := s.st.AddWhitelist(e); err != nil {
			s.audit(r, "导入白名单", "", fmt.Sprintf("确认导入失败（已写入 %d 条）: %v", manualAdded+autoAdded, err))
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if e.Source == "auto_match" {
			autoAdded++
		} else {
			manualAdded++
		}
	}
	s.audit(r, "导入白名单", "", fmt.Sprintf("确认导入：手动 %d 条，自动匹配 %d 条，跳过 %d 项", manualAdded, autoAdded, len(existDups)))
	writeJSON(w, 200, map[string]interface{}{
		"added": manualAdded + autoAdded, "manual_added": manualAdded, "auto_added": autoAdded, "skipped": existDups,
	})
}
