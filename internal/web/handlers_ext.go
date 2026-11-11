package web

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"

	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

// ---------- 资产标签 / 删除 ----------

func (s *Server) apiSetTargetTags(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tags := strings.TrimSpace(r.FormValue("tags"))
	if err := s.st.SetTargetTags(id, tags); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "修改资产标签", "#"+r.PathValue("id"), tags)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.st.DeleteTarget(id); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "删除资产", "#"+r.PathValue("id"), "")
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// apiBatchTargetTags 批量设置/追加资产标签：支持按资产 ID（资产台账页）或按 IP（告警页改关联资产）。
// mode=set 覆盖（tags 为空即清除），mode=append 追加合并。仅 operator/admin。
func (s *Server) apiBatchTargetTags(w http.ResponseWriter, r *http.Request) {
	if err := parseAnyForm(r); err != nil {
		writeJSON(w, 400, map[string]string{"error": "表单解析失败"})
		return
	}
	tags := strings.TrimSpace(r.FormValue("tags"))
	appendMode := r.FormValue("mode") == "append"
	if appendMode && tags == "" {
		writeJSON(w, 400, map[string]string{"error": "追加模式下标签不能为空"})
		return
	}
	idSet := map[int64]struct{}{}
	ids := make([]int64, 0)
	addID := func(id int64) {
		if id <= 0 {
			return
		}
		if _, ok := idSet[id]; ok {
			return
		}
		idSet[id] = struct{}{}
		ids = append(ids, id)
	}
	for _, raw := range r.Form["target_ids"] {
		for _, part := range strings.Split(raw, ",") {
			id, _ := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
			addID(id)
		}
	}
	var ips []string
	for _, raw := range r.Form["ips"] {
		for _, part := range strings.Split(raw, ",") {
			if p := strings.TrimSpace(part); p != "" {
				ips = append(ips, p)
			}
		}
	}
	matchedByIP := 0
	if len(ips) > 0 {
		ipIDs, err := s.st.TargetIDsByIPs(ips)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "按 IP 匹配资产失败: " + err.Error()})
			return
		}
		matchedByIP = len(ipIDs)
		for _, id := range ipIDs {
			addID(id)
		}
	}
	if len(ids) == 0 {
		writeJSON(w, 400, map[string]string{"error": "未选择任何资产，或所选告警的 IP 不在资产台账中"})
		return
	}
	updated, err := s.st.SetTargetTagsBatch(ids, tags, appendMode)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "批量修改标签失败: " + err.Error()})
		return
	}
	action := "批量覆盖资产标签"
	if appendMode {
		action = "批量追加资产标签"
	}
	s.audit(r, action, fmt.Sprintf("%d 个资产", updated), "tags="+tags)
	resp := map[string]interface{}{"ok": "1", "updated": updated}
	if len(ips) > 0 {
		resp["matched_by_ip"] = matchedByIP
		resp["ip_count"] = len(ips)
	}
	writeJSON(w, 200, resp)
}

// apiBatchDeleteTargets 批量删除勾选的资产（IP/CIDR/范围/域名均可）。仅 operator/admin。
func (s *Server) apiBatchDeleteTargets(w http.ResponseWriter, r *http.Request) {
	if err := parseAnyForm(r); err != nil {
		writeJSON(w, 400, map[string]string{"error": "表单解析失败"})
		return
	}
	seen := map[int64]struct{}{}
	ids := make([]int64, 0)
	for _, raw := range r.Form["ids"] {
		for _, part := range strings.Split(raw, ",") {
			id, _ := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
			if id <= 0 {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		writeJSON(w, 400, map[string]string{"error": "未选择任何资产"})
		return
	}
	deleted := 0
	for _, id := range ids {
		if err := s.st.DeleteTarget(id); err == nil {
			deleted++
		}
	}
	s.audit(r, "批量删除资产", fmt.Sprintf("%d 个", deleted), "")
	writeJSON(w, 200, map[string]interface{}{"ok": "1", "deleted": deleted})
}

// apiExposureWhitelist 把暴露面勾选项（ip[]/port[]/proto[]/service[] 对齐数组）批量加入白名单。仅 operator/admin。
// reason 必填：支持单值（应用到全部）或与 ip[] 对齐的 reason 数组（逐行）；
// 若某行原因为空则拒绝整批并回报具体行号，不部分写入。remark 为可选备注。
func (s *Server) apiExposureWhitelist(w http.ResponseWriter, r *http.Request) {
	if err := parseAnyForm(r); err != nil {
		writeJSON(w, 400, map[string]string{"error": "表单解析失败"})
		return
	}
	ips := r.Form["ip"]
	ports := r.Form["port"]
	protos := r.Form["proto"]
	services := r.Form["service"]
	if len(ips) == 0 {
		writeJSON(w, 400, map[string]string{"error": "未选择任何暴露面条目"})
		return
	}
	reasons := r.Form["reason"]
	// getReason 兼容两种提交：单值 reason（len==1，应用到全部）或与 ip[] 对齐的逐行数组。
	getReason := func(i int) string {
		if i < len(reasons) {
			return strings.TrimSpace(reasons[i])
		}
		if len(reasons) == 1 {
			return strings.TrimSpace(reasons[0])
		}
		return ""
	}
	remark := strings.TrimSpace(r.FormValue("remark"))
	operator := currentUser(r).username

	rows := make([]store.WLEntry, 0, len(ips))
	emptyRows := 0
	// 先逐行校验（含必填原因），任一行不合格则拒绝整批，不部分写入。
	for i, ip := range ips {
		ip = strings.TrimSpace(ip)
		port := ""
		if i < len(ports) {
			port = strings.TrimSpace(ports[i])
		}
		if ip == "" || port == "" {
			emptyRows++ // 缺 ip/port 的行计入跳过（与旧行为一致）
			continue
		}
		reason := getReason(i)
		if reason == "" {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("第 %d 行缺少加白原因（必填）：%s:%s", i+1, ip, port)})
			return
		}
		proto := "tcp"
		if i < len(protos) && strings.TrimSpace(protos[i]) != "" {
			proto = strings.TrimSpace(protos[i])
		}
		entry := store.WLEntry{IPSpec: ip, PortSpec: port, Proto: proto, Owner: operator, Reason: reason, Remark: remark, Source: "exposure"}
		if i < len(services) {
			entry.Service = strings.TrimSpace(services[i])
		}
		if err := engine.ValidateEntry(entry); err != nil {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("第 %d 行条目非法: %v", i+1, err)})
			return
		}
		rows = append(rows, entry)
	}
	added, skipped := 0, emptyRows
	for _, entry := range rows {
		if _, err := s.st.AddWhitelist(entry); err != nil {
			skipped++
			continue
		}
		added++
	}
	s.audit(r, "暴露面批量加白", fmt.Sprintf("%d 条", added), fmt.Sprintf("跳过 %d 条", skipped))
	writeJSON(w, 200, map[string]interface{}{"ok": "1", "added": added, "skipped": skipped})
}

// filterTargets 按关键词/标签/是否打标签过滤资产（列表页与导出共用）；关键词覆盖 IP/域名/标签/来源/维护人员/安全设备。
func filterTargets(targets []store.Target, query, curTag, filter string) []store.Target {
	if curTag == "" && query == "" && filter == "" {
		return targets
	}
	q := strings.ToLower(strings.TrimSpace(query))
	out := make([]store.Target, 0, len(targets))
	for _, t := range targets {
		hasTag := strings.TrimSpace(t.Tags) != ""
		if filter == "tagged" && !hasTag {
			continue
		}
		if filter == "untagged" && hasTag {
			continue
		}
		if curTag != "" {
			matched := false
			for _, tg := range strings.Split(t.Tags, ",") {
				if strings.TrimSpace(tg) == curTag {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if q != "" {
			haystack := strings.ToLower(t.IP + " " + t.Domain + " " + t.Tags + " " + t.Source + " " + t.Owner + " " + t.SecurityDevice)
			if !strings.Contains(haystack, q) {
				continue
			}
		}
		out = append(out, t)
	}
	return out
}

func targetKindName(kind string) string {
	switch kind {
	case "cidr":
		return "网段"
	case "range":
		return "范围"
	case "domain":
		return "域名"
	default:
		return "单 IP"
	}
}

// apiCreateTarget 手动新增单条资产（IP/CIDR/范围/域名 + 维护人员 + 安全设备 + 标签）。
func (s *Server) apiCreateTarget(w http.ResponseWriter, r *http.Request) {
	spec := strings.TrimSpace(r.FormValue("spec"))
	if spec == "" {
		writeJSON(w, 400, map[string]string{"error": "请填写 IP / 网段 / 范围 / 域名"})
		return
	}
	// 归一化后再校验与入库：等价形态（未掩码 CIDR/大写或尾点域名）命中已有资产时提示不重复添加。
	if norm, _ := store.NormalizeTargetSpec(spec); norm != "" {
		spec = norm
	}
	kind, ok := engine.ClassifyTarget(spec)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "目标格式非法：" + spec + "（支持单 IP、CIDR 网段、IP 范围、域名）"})
		return
	}
	row := store.ImportAsset{Raw: spec, Kind: kind, Owner: strings.TrimSpace(r.FormValue("owner")), SecurityDevice: strings.TrimSpace(r.FormValue("security_device"))}
	tags := strings.TrimSpace(r.FormValue("tags"))
	added, err := s.st.ImportAssets([]store.ImportAsset{row}, tags, "手动添加")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "新增资产", spec, "owner="+row.Owner+" device="+row.SecurityDevice+" tags="+tags)
	if added == 0 {
		writeJSON(w, 200, map[string]interface{}{"ok": "1", "added": 0, "message": "该资产已存在，未重复添加（如需修改维护信息请用行内「编辑」）"})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": "1", "added": 1})
}

// apiUpdateTargetMeta 编辑单条资产的维护人员、安全设备与标签（不改动 IP/域名主标识）。
func (s *Server) apiUpdateTargetMeta(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 {
		writeJSON(w, 400, map[string]string{"error": "资产 ID 非法"})
		return
	}
	owner := strings.TrimSpace(r.FormValue("owner"))
	device := strings.TrimSpace(r.FormValue("security_device"))
	tags := strings.TrimSpace(r.FormValue("tags"))
	if err := s.st.UpdateTargetMeta(id, owner, device, tags); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "编辑资产", "#"+r.PathValue("id"), "owner="+owner+" device="+device+" tags="+tags)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// exportAssets 导出当前筛选下的资产 CSV（含域名、维护人员、安全设备）。
func (s *Server) exportAssets(w http.ResponseWriter, r *http.Request) {
	targets, _ := s.st.Targets()
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	curTag := r.URL.Query().Get("tag")
	filter := r.URL.Query().Get("filter")
	if filter != "tagged" && filter != "untagged" {
		filter = ""
	}
	targets = filterTargets(targets, query, curTag, filter)
	records := [][]string{{"目标", "类型", "域名", "标签", "维护人员", "安全设备", "来源", "创建时间"}}
	for _, t := range targets {
		records = append(records, []string{t.IP, targetKindName(t.Kind), t.Domain, t.Tags, t.Owner, t.SecurityDevice, t.Source, t.CreatedAt})
	}
	s.audit(r, "导出资产", "", fmt.Sprintf("%d 条", len(targets)))
	writeCSVDownload(w, "assets.csv", records)
}

// ---------- 导入样例文件下载 ----------

// whitelistTemplateHeaders / whitelistTemplateRows 白名单 Excel/CSV 模板的表头与示例行。
// 列序与无表头文件的回落列序一致：IP/网段、端口、服务、备注（原因列靠表头名识别；协议/负责人/业务 同理可自行加列）。
var (
	whitelistTemplateHeaders = []string{"IP/网段", "端口", "服务", "备注", "原因"}
	whitelistTemplateRows    = [][5]string{
		{"1.2.3.4", "22,80,443", "SSH,HTTP,HTTPS", "运维跳板机，工单 #1024", "运维官方服务"},
		{"10.0.0.5", "3306", "MySQL", "仅内网访问", "业务数据库"},
		{"10.0.0.0/24", "1000-2000", "业务端口段", "整段放行", "已确认合规"},
		{"*", "443", "HTTPS", "全局通用端口", "通用 HTTPS"},
		{"10.0.0.9", "", "", "端口留空 + 勾选「自动匹配已识别端口」，自动放行该 IP 已识别端口", "自动匹配放行"},
	}
)

func (s *Server) apiSample(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("kind") {
	case "assets.csv":
		body := "\ufeff" + "目标,维护人员,安全设备\n1.2.3.4,张三,WAF\n10.0.0.0/24,,\n1.2.3.1-1.2.3.50,李四,云盾\nexample.com,王五,防火墙\n"
		download(w, "assets-sample.csv", "text/csv; charset=utf-8", []byte(body))
	case "assets.xlsx":
		f := excelize.NewFile()
		sheet := f.GetSheetName(0)
		_ = f.SetCellValue(sheet, "A1", "目标")
		_ = f.SetCellValue(sheet, "B1", "维护人员")
		_ = f.SetCellValue(sheet, "C1", "安全设备")
		sampleRows := [][3]string{{"1.2.3.4", "张三", "WAF"}, {"10.0.0.0/24", "", ""}, {"1.2.3.1-1.2.3.50", "李四", "云盾"}, {"example.com", "王五", "防火墙"}}
		for i, row := range sampleRows {
			_ = f.SetCellValue(sheet, fmt.Sprintf("A%d", i+2), row[0])
			_ = f.SetCellValue(sheet, fmt.Sprintf("B%d", i+2), row[1])
			_ = f.SetCellValue(sheet, fmt.Sprintf("C%d", i+2), row[2])
		}
		var buf bytes.Buffer
		_ = f.Write(&buf)
		_ = f.Close()
		download(w, "assets-sample.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", buf.Bytes())
	case "whitelist.txt":
		body := "# 每行一条：IP + 端口（多端口用逗号分隔，支持范围与 tcp/udp）\n" +
			"1.2.3.4 22,80,443\n" +
			"10.0.0.5 3306\n" +
			"10.0.0.0/24 1000-2000 udp\n"
		download(w, "whitelist-sample.txt", "text/plain; charset=utf-8", []byte(body))
	case "whitelist.xlsx":
		f := excelize.NewFile()
		sheet := f.GetSheetName(0)
		cols := []string{"A", "B", "C", "D", "E"}
		for i, h := range whitelistTemplateHeaders {
			_ = f.SetCellValue(sheet, cols[i]+"1", h)
		}
		for i, row := range whitelistTemplateRows {
			for j, v := range row {
				_ = f.SetCellValue(sheet, fmt.Sprintf("%s%d", cols[j], i+2), v)
			}
		}
		_ = f.SetColWidth(sheet, "A", "E", 26)
		var buf bytes.Buffer
		_ = f.Write(&buf)
		_ = f.Close()
		download(w, "whitelist-template.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", buf.Bytes())
	case "whitelist.csv":
		var b bytes.Buffer
		b.WriteString("\ufeff")
		// 端口列常含逗号（如 22,80,443），必须走 CSV 引号转义，否则会被拆成多列
		cw := csv.NewWriter(&b)
		_ = cw.Write(whitelistTemplateHeaders)
		for _, row := range whitelistTemplateRows {
			_ = cw.Write(row[:])
		}
		cw.Flush()
		download(w, "whitelist-template.csv", "text/csv; charset=utf-8", b.Bytes())
	default:
		http.Error(w, "未知样例类型", http.StatusNotFound)
	}
}

func download(w http.ResponseWriter, filename, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

// ---------- 白名单说明页 ----------

func (s *Server) pageWhitelistHelp(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "白名单说明", "whitelist")
	s.render(w, "whitelist_help.html", bd)
}

// ---------- 任务表单页（新建 / 编辑）----------

func (s *Server) pageTaskForm(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	bd, _ := s.baseData(r, "扫描任务", "tasks")
	var task store.ScanTask
	editing := false
	if id > 0 {
		t, err := s.st.ScanTask(id)
		if err != nil || t == nil {
			http.Error(w, "扫描任务不存在", http.StatusNotFound)
			return
		}
		task = *t
		editing = true
		bd.Title = "编辑任务"
	} else {
		bd.Title = "新建任务"
		task.TargetType = "all"
		task.Hour = 2
		// 新建任务协议默认取全局 scan_udp：开启→TCP+UDP，关闭→纯 TCP；用户可在任务表单单独覆盖。
		if s.st.Setting("scan_udp") == "1" {
			task.Protocol = "both"
		} else {
			task.Protocol = "tcp"
		}
	}
	tags, _ := s.st.AllTags()
	s.render(w, "task_form.html", struct {
		pageData
		Task    store.ScanTask
		Editing bool
		Tags    []string
	}{bd, task, editing, tags})
}

// pageDomainDetail 域名资产详情：关联端口（domain_map 衍生 IP 的开放端口）+ 服务指纹 + 安全设备。
func (s *Server) pageDomainDetail(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if domain == "" {
		http.Error(w, "域名不能为空", http.StatusBadRequest)
		return
	}
	bd, _ := s.baseData(r, "域名资产 · "+domain, "assets")
	ips, _ := s.st.IPsForDomain(domain)
	ports, _ := s.st.OpenPortsByIPs(ips)
	services, _ := s.st.DomainServices(domain)
	device := ""
	targets, _ := s.st.Targets()
	for _, t := range targets {
		if t.Kind == "domain" && strings.EqualFold(t.IP, domain) {
			device = t.SecurityDevice
			break
		}
	}
	s.render(w, "domain_detail.html", struct {
		pageData
		Domain   string
		IPs      []string
		Ports    []store.Result
		Services []string
		Device   string
	}{bd, domain, ips, ports, services, device})
}

// apiDomainWhitelist 一键将域名下所有衍生 IP 的开放端口加入白名单。
// 查询错误显式返回 500（区分“确实无端口”与“查询失败”）；靠 AddWhitelist 的
// INSERT OR IGNORE 幂等保证重复点击不产生重复规则（id==0 计为已存在）；并对衍生规模设上限。
func (s *Server) apiDomainWhitelist(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	if domain == "" {
		writeJSON(w, 400, map[string]string{"error": "域名不能为空"})
		return
	}
	ips, err := s.st.IPsForDomain(domain)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "查询域名衍生 IP 失败: " + err.Error()})
		return
	}
	open, err := s.st.OpenPortsByIPs(ips)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "查询已识别端口失败: " + err.Error()})
		return
	}
	if len(open) > wlImportMaxRows {
		writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("该域名衍生端口 %d 条，超过单次加白上限 %d，请按需精确添加", len(open), wlImportMaxRows)})
		return
	}
	operator := currentUser(r).username
	added, existed := 0, 0
	for _, p := range open {
		e := store.WLEntry{IPSpec: p.IP, PortSpec: strconv.Itoa(p.Port), Proto: p.Proto, Service: p.Service, Owner: operator, Source: "domain", Remark: "域名衍生 IP 一键加白: " + domain}
		id, err := s.st.AddWhitelist(e)
		if err != nil {
			s.audit(r, "域名一键加白", domain, fmt.Sprintf("写入失败（已加白 %d 条）: %v", added, err))
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if id > 0 {
			added++
		} else {
			existed++ // 相同规则已在白名单，幂等跳过
		}
	}
	s.audit(r, "域名一键加白", domain, fmt.Sprintf("新增 %d 条，已存在 %d 条", added, existed))
	writeJSON(w, 200, map[string]interface{}{"added": added, "existed": existed})
}

// ---------- 聚合暴露面 ----------

func exposureFilters(r *http.Request) (string, string, int) {
	port, _ := strconv.Atoi(r.URL.Query().Get("port"))
	if port < 1 || port > 65535 {
		port = 0
	}
	proto := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("proto")))
	if proto != "tcp" && proto != "udp" {
		proto = ""
	}
	return strings.TrimSpace(r.URL.Query().Get("q")), proto, port
}

func (s *Server) loadExposures(r *http.Request, limit int) ([]store.Exposure, error) {
	query, proto, port := exposureFilters(r)
	items, err := s.st.Exposures(query, proto, port, limit)
	if err != nil {
		return nil, err
	}
	results := make([]store.Result, 0, len(items))
	for _, item := range items {
		results = append(results, store.Result{IP: item.IP, Port: item.Port, Proto: item.Proto})
	}
	status, err := s.eng.WhitelistStatus(results)
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i].Whitelisted = status[engine.ResultKey(items[i].IP, items[i].Port, items[i].Proto)]
	}
	return items, nil
}

func (s *Server) pageExposure(w http.ResponseWriter, r *http.Request) {
	bd, _ := s.baseData(r, "暴露面资产", "exposure")
	items, err := s.loadExposures(r, 1000)
	if err != nil {
		http.Error(w, "读取暴露面失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	query, proto, port := exposureFilters(r)

	// 域名反向检索：domain 参数→解析 IP 集合→过滤暴露面。
	domainFilter := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domainFilter != "" {
		ips, _ := s.st.IPsForDomain(domainFilter)
		ipSet := map[string]bool{}
		for _, ip := range ips {
			ipSet[ip] = true
		}
		filtered := items[:0]
		for _, it := range items {
			if ipSet[it.IP] {
				filtered = append(filtered, it)
			}
		}
		items = filtered
	}

	// 域名列：每个 IP 反查关联域名（有界，最多展示前 3 个）。
	domains := make([][]string, len(items))
	for i, it := range items {
		ds, _ := s.st.DomainsForIP(it.IP)
		if len(ds) > 3 {
			ds = ds[:3]
		}
		domains[i] = ds
	}

	s.render(w, "exposure.html", struct {
		pageData
		Items   []store.Exposure
		Domains [][]string
		Query   string
		Proto   string
		Port    int
		Domain  string
	}{bd, items, domains, query, proto, port, domainFilter})
}

func writeCSVDownload(w http.ResponseWriter, filename string, records [][]string) {
	// 防止服务识别结果或处理备注在表格软件中被解释为公式。
	for i := range records {
		for j, cell := range records[i] {
			trimmed := strings.TrimLeft(cell, " \t")
			if strings.HasPrefix(trimmed, "=") || strings.HasPrefix(trimmed, "+") || strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "@") {
				records[i][j] = "'" + cell
			}
		}
	}
	var buf bytes.Buffer
	buf.WriteString("\ufeff")
	cw := csv.NewWriter(&buf)
	_ = cw.WriteAll(records)
	download(w, filename, "text/csv; charset=utf-8", buf.Bytes())
}

func (s *Server) exportExposure(w http.ResponseWriter, r *http.Request) {
	items, err := s.loadExposures(r, 0)
	if err != nil {
		http.Error(w, "导出失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	records := [][]string{{"IP", "端口", "协议", "服务", "首次发现", "最近发现", "出现扫描次数", "最近扫描ID", "白名单", "告警状态"}}
	for _, item := range items {
		whitelisted := "否"
		if item.Whitelisted {
			whitelisted = "是"
		}
		records = append(records, []string{item.IP, strconv.Itoa(item.Port), item.Proto, item.Service, item.FirstSeenAt, item.LastSeenAt,
			strconv.Itoa(item.SeenCount), strconv.FormatInt(item.LastScanID, 10), whitelisted, alertStatusName(item.AlertStatus)})
	}
	s.audit(r, "导出暴露面", "", fmt.Sprintf("%d 条", len(items)))
	writeCSVDownload(w, "exposure.csv", records)
}

// exportResults 导出当前筛选下的扫描结果 CSV。
func (s *Server) exportResults(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode != "full" && mode != "top" {
		mode = ""
	}
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	scanID, _ := strconv.ParseInt(r.URL.Query().Get("scan_id"), 10, 64)
	port, _ := strconv.Atoi(r.URL.Query().Get("port"))
	if port < 1 || port > 65535 {
		port = 0
	}
	items, err := s.st.ResultsFiltered(strings.TrimSpace(r.URL.Query().Get("q")), mode, taskID, scanID, port, 0)
	if err != nil {
		http.Error(w, "导出失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	records := [][]string{{"IP", "端口", "协议", "服务", "扫描模式", "执行名称", "任务ID", "执行ID", "扫描时间"}}
	for _, item := range items {
		mode := "常用端口 top-1000"
		if item.ScanMode == "full" {
			mode = "全端口 1-65535"
		} else if item.ScanMode == "custom" {
			mode = "自定义端口"
		}
		records = append(records, []string{item.IP, strconv.Itoa(item.Port), item.Proto, item.Service, mode,
			item.ScanName, strconv.FormatInt(item.TaskID, 10), strconv.FormatInt(item.ScanID, 10), item.StartedAt})
	}
	s.audit(r, "导出扫描结果", "", fmt.Sprintf("%d 条", len(items)))
	writeCSVDownload(w, "results.csv", records)
}

// exportWhitelist 导出全部白名单条目 CSV。
func (s *Server) exportWhitelist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.st.Whitelist()
	if err != nil {
		http.Error(w, "导出失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	records := [][]string{{"IP/网段", "端口", "协议", "服务", "负责人", "业务", "原因", "备注", "创建时间"}}
	for _, e := range entries {
		records = append(records, []string{e.IPSpec, e.PortSpec, e.Proto, e.Service, e.Owner, e.Business, e.Reason, e.Remark, e.CreatedAt})
	}
	s.audit(r, "导出白名单", "", fmt.Sprintf("%d 条", len(entries)))
	writeCSVDownload(w, "whitelist.csv", records)
}

// apiBaselinePreview 返回最近一次完成扫描中「尚未在白名单」的开放端口，供生成基线前预览勾选（最多 2000 条）。
func (s *Server) apiBaselinePreview(w http.ResponseWriter, r *http.Request) {
	scanID, err := s.st.LatestDoneScan()
	if err != nil || scanID == 0 {
		writeJSON(w, 400, map[string]string{"error": "没有已完成的扫描，无法生成基线"})
		return
	}
	results, err := s.st.ResultsByScan(scanID)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "读取扫描结果失败: " + err.Error()})
		return
	}
	status, err := s.eng.WhitelistStatus(results)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "读取白名单状态失败: " + err.Error()})
		return
	}
	type entry struct {
		IP      string `json:"ip"`
		Port    int    `json:"port"`
		Proto   string `json:"proto"`
		Service string `json:"service"`
	}
	entries := make([]entry, 0, len(results))
	for _, res := range results {
		if status[engine.ResultKey(res.IP, res.Port, res.Proto)] {
			continue
		}
		proto := res.Proto
		if proto == "" {
			proto = "tcp"
		}
		entries = append(entries, entry{IP: res.IP, Port: res.Port, Proto: proto, Service: res.Service})
		if len(entries) >= 2000 {
			break
		}
	}
	scanName, scanTime := "", ""
	if scan, _ := s.st.Scan(scanID); scan != nil {
		scanName, scanTime = scan.Name, scan.StartedAt
	}
	writeJSON(w, 200, map[string]interface{}{
		"scan_id": scanID, "scan_name": scanName, "scan_time": scanTime,
		"entries": entries, "total": len(entries),
	})
}

// apiBaselineApply 把预览中勾选的条目（ip[]/port[]/proto[]/service[] 对齐数组）批量加入白名单，
// owner=baseline，可带统一业务归属。仅 operator/admin。
func (s *Server) apiBaselineApply(w http.ResponseWriter, r *http.Request) {
	if err := parseAnyForm(r); err != nil {
		writeJSON(w, 400, map[string]string{"error": "表单解析失败"})
		return
	}
	ips := r.Form["ip"]
	ports := r.Form["port"]
	protos := r.Form["proto"]
	services := r.Form["service"]
	if len(ips) == 0 {
		writeJSON(w, 400, map[string]string{"error": "未选择任何基线条目"})
		return
	}
	business := strings.TrimSpace(r.FormValue("business"))
	added, skipped := 0, 0
	for i, ip := range ips {
		ip = strings.TrimSpace(ip)
		port := ""
		if i < len(ports) {
			port = strings.TrimSpace(ports[i])
		}
		proto := "tcp"
		if i < len(protos) && strings.TrimSpace(protos[i]) != "" {
			proto = strings.TrimSpace(protos[i])
		}
		service := ""
		if i < len(services) {
			service = strings.TrimSpace(services[i])
		}
		if ip == "" || port == "" {
			skipped++
			continue
		}
		entry := store.WLEntry{IPSpec: ip, PortSpec: port, Proto: proto, Service: service, Owner: "baseline", Business: business, Remark: "基线生成"}
		if err := engine.ValidateEntry(entry); err != nil {
			skipped++
			continue
		}
		if _, err := s.st.AddWhitelist(entry); err != nil {
			skipped++
			continue
		}
		added++
	}
	s.audit(r, "生成白名单基线", fmt.Sprintf("%d 条", added), fmt.Sprintf("业务=%s 跳过 %d 条", business, skipped))
	writeJSON(w, 200, map[string]interface{}{"ok": "1", "added": added, "skipped": skipped})
}

// exportAudit 导出当前筛选下的操作审计 CSV。仅 admin。
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	logs, err := s.st.AuditLogsAdvanced(strings.TrimSpace(r.URL.Query().Get("q")), strings.TrimSpace(r.URL.Query().Get("user")),
		strings.TrimSpace(r.URL.Query().Get("type")), strings.TrimSpace(r.URL.Query().Get("from")), strings.TrimSpace(r.URL.Query().Get("to")), 20000)
	if err != nil {
		http.Error(w, "导出失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	records := [][]string{{"时间", "用户", "角色", "操作", "对象", "详情", "来源IP"}}
	for _, l := range logs {
		records = append(records, []string{l.Ts, l.Username, roleName(l.Role), l.Action, l.Target, l.Detail, l.IP})
	}
	s.audit(r, "导出操作审计", "", fmt.Sprintf("%d 条", len(logs)))
	writeCSVDownload(w, "audit.csv", records)
}

// ---------- 告警处置闭环 ----------

func validAlertStatus(status string) bool {
	return status == "" || status == "new" || status == "acked" || status == "resolved" || status == "ignored"
}

func alertStatusName(status string) string {
	switch status {
	case "new":
		return "待处理"
	case "acked":
		return "跟进中"
	case "resolved":
		return "已解决"
	case "ignored":
		return "已忽略"
	default:
		return "无告警"
	}
}

type alertFormData struct {
	pageData
	Alert  store.Alert
	Status string
	Note   string
	Return string
}

func alertListPath(r *http.Request) string {
	values := url.Values{}
	status := r.URL.Query().Get("status")
	if status != "" && validAlertStatus(status) {
		values.Set("status", status)
	}
	if query := strings.TrimSpace(r.URL.Query().Get("q")); query != "" {
		values.Set("q", query)
	}
	path := "/alerts"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return path
}

func safeAlertReturn(value string) string {
	if value == "/alerts" || strings.HasPrefix(value, "/alerts?") {
		return value
	}
	return "/alerts"
}

func validateAlertUpdate(status, note string) string {
	if status == "" || !validAlertStatus(status) {
		return "告警状态非法"
	}
	if (status == "resolved" || status == "ignored") && note == "" {
		return "解决或忽略告警时，请填写处理说明"
	}
	if len(note) > 4000 {
		return "处理说明过长，请控制在 4000 字节以内"
	}
	return ""
}

func (s *Server) renderAlertForm(w http.ResponseWriter, r *http.Request, alert *store.Alert, status, note, returnTo, errorMessage string, code int) {
	bd, err := s.baseData(r, "处置告警", "alerts")
	if err != nil {
		http.Error(w, "读取告警统计失败", http.StatusInternalServerError)
		return
	}
	bd.Error = errorMessage
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	s.render(w, "alert_form.html", alertFormData{
		pageData: bd,
		Alert:    *alert,
		Status:   status,
		Note:     note,
		Return:   safeAlertReturn(returnTo),
	})
}

func (s *Server) pageAlertForm(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	alert, err := s.st.AlertByID(id)
	if err != nil {
		http.Error(w, "读取告警失败", http.StatusInternalServerError)
		return
	}
	if alert == nil {
		http.Error(w, "告警不存在", http.StatusNotFound)
		return
	}
	status := alert.Status
	if status == "new" {
		status = "acked"
	}
	s.renderAlertForm(w, r, alert, status, alert.HandleNote, alertListPath(r), "", http.StatusOK)
}

func (s *Server) submitAlertForm(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	alert, err := s.st.AlertByID(id)
	if err != nil {
		http.Error(w, "读取告警失败", http.StatusInternalServerError)
		return
	}
	if alert == nil {
		http.Error(w, "告警不存在", http.StatusNotFound)
		return
	}
	returnTo := safeAlertReturn(r.FormValue("return"))
	status := r.FormValue("status")
	note := strings.TrimSpace(r.FormValue("note"))
	if message := validateAlertUpdate(status, note); message != "" {
		s.renderAlertForm(w, r, alert, status, note, returnTo, message, http.StatusBadRequest)
		return
	}
	if err := s.st.UpdateAlertStatus(id, status, note, currentUser(r).username); err != nil {
		s.renderAlertForm(w, r, alert, status, note, returnTo, "保存处置失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "处置告警", "#"+r.PathValue("id"), "status="+status+" note="+note)
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func (s *Server) submitAlertWhitelist(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	alert, err := s.st.AlertByID(id)
	if err != nil {
		http.Error(w, "读取告警失败", http.StatusInternalServerError)
		return
	}
	if alert == nil {
		http.Error(w, "告警不存在", http.StatusNotFound)
		return
	}
	returnTo := safeAlertReturn(r.FormValue("return"))
	if alert.Kind == "unreachable" {
		http.Error(w, "网络不可达告警不适用端口加白，请按排查建议处置连通性问题", http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(r.FormValue("note"))
	status := alert.Status
	if status == "new" {
		status = "acked"
	}
	if len(note) > 4000 {
		s.renderAlertForm(w, r, alert, status, note, returnTo, "处理说明过长，请控制在 4000 字节以内", http.StatusBadRequest)
		return
	}
	proto := alert.Proto
	if proto == "" {
		proto = "tcp"
	}
	entry := store.WLEntry{IPSpec: alert.IP, PortSpec: strconv.Itoa(alert.Port), Proto: proto, Service: alert.Service,
		Owner: currentUser(r).username, Remark: "由告警 #" + r.PathValue("id") + " 确认放行"}
	if _, err := s.st.AddWhitelist(entry); err != nil {
		s.renderAlertForm(w, r, alert, status, note, returnTo, "加入白名单失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if note == "" {
		note = "已确认风险并加入白名单"
	}
	if err := s.st.UpdateAlertStatus(id, "ignored", note, currentUser(r).username); err != nil {
		s.renderAlertForm(w, r, alert, status, note, returnTo, "白名单已添加，但告警状态更新失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "告警加入白名单", "#"+r.PathValue("id"), alert.IP+":"+strconv.Itoa(alert.Port))
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func (s *Server) apiUpdateAlert(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	status := r.FormValue("status")
	note := strings.TrimSpace(r.FormValue("note"))
	if message := validateAlertUpdate(status, note); message != "" {
		writeJSON(w, 400, map[string]string{"error": message})
		return
	}
	alert, err := s.st.AlertByID(id)
	if err != nil || alert == nil {
		writeJSON(w, 404, map[string]string{"error": "告警不存在"})
		return
	}
	if err := s.st.UpdateAlertStatus(id, status, note, currentUser(r).username); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "处置告警", "#"+r.PathValue("id"), "status="+status+" note="+note)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiAlertWhitelist(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	alert, err := s.st.AlertByID(id)
	if err != nil || alert == nil {
		writeJSON(w, 404, map[string]string{"error": "告警不存在"})
		return
	}
	if alert.Kind == "unreachable" {
		writeJSON(w, 400, map[string]string{"error": "网络不可达告警不适用端口加白，请按排查建议处置连通性问题"})
		return
	}
	proto := alert.Proto
	if proto == "" {
		proto = "tcp"
	}
	entry := store.WLEntry{IPSpec: alert.IP, PortSpec: strconv.Itoa(alert.Port), Proto: proto, Service: alert.Service,
		Owner: currentUser(r).username, Remark: "由告警 #" + r.PathValue("id") + " 确认放行"}
	if _, err := s.st.AddWhitelist(entry); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	note := strings.TrimSpace(r.FormValue("note"))
	if note == "" {
		note = "已确认风险并加入白名单"
	}
	if err := s.st.UpdateAlertStatus(id, "ignored", note, currentUser(r).username); err != nil {
		writeJSON(w, 500, map[string]string{"error": "白名单已添加，但告警状态更新失败: " + err.Error()})
		return
	}
	s.audit(r, "告警加入白名单", "#"+r.PathValue("id"), alert.IP+":"+strconv.Itoa(alert.Port))
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// apiBatchAlerts 批量处置告警：按状态批量变更，或批量加白并忽略。仅 operator/admin。
func (s *Server) apiBatchAlerts(w http.ResponseWriter, r *http.Request) {
	if err := parseAnyForm(r); err != nil {
		writeJSON(w, 400, map[string]string{"error": "表单解析失败"})
		return
	}
	seen := map[int64]struct{}{}
	ids := make([]int64, 0)
	for _, field := range []string{"ids", "id"} {
		for _, raw := range r.Form[field] {
			for _, part := range strings.Split(raw, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				id, err := strconv.ParseInt(part, 10, 64)
				if err != nil || id <= 0 {
					continue
				}
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		writeJSON(w, 400, map[string]string{"error": "未选择任何告警"})
		return
	}
	action := r.FormValue("action")
	note := strings.TrimSpace(r.FormValue("note"))
	operator := currentUser(r).username

	if action == "whitelist" {
		wlNote := note
		if wlNote == "" {
			wlNote = "批量确认放行并加入白名单"
		}
		added, ignored := 0, 0
		for _, id := range ids {
			alert, err := s.st.AlertByID(id)
			if err != nil || alert == nil {
				continue
			}
			// 网络不可达告警没有端口维度，加白无意义，跳过并保留原状态供单独处置。
			if alert.Kind == "unreachable" {
				continue
			}
			proto := alert.Proto
			if proto == "" {
				proto = "tcp"
			}
			entry := store.WLEntry{IPSpec: alert.IP, PortSpec: strconv.Itoa(alert.Port), Proto: proto,
				Service: alert.Service, Owner: operator, Remark: "批量告警加白"}
			if _, err := s.st.AddWhitelist(entry); err != nil {
				continue
			}
			added++
			if err := s.st.UpdateAlertStatus(id, "ignored", wlNote, operator); err == nil {
				ignored++
			}
		}
		s.audit(r, "批量告警加白", fmt.Sprintf("%d 条", len(ids)), fmt.Sprintf("加白 %d，忽略 %d", added, ignored))
		writeJSON(w, 200, map[string]interface{}{"ok": "1", "whitelisted": added, "ignored": ignored})
		return
	}

	switch action {
	case "acked", "resolved", "ignored", "new":
	default:
		writeJSON(w, 400, map[string]string{"error": "不支持的批量处置操作"})
		return
	}
	if (action == "resolved" || action == "ignored") && note == "" {
		writeJSON(w, 400, map[string]string{"error": "批量解决或忽略时，请填写统一处理说明"})
		return
	}
	if len(note) > 4000 {
		writeJSON(w, 400, map[string]string{"error": "处理说明过长，请控制在 4000 字节以内"})
		return
	}
	updated, err := s.st.UpdateAlertStatusBatch(ids, action, note, operator)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "批量处置失败: " + err.Error()})
		return
	}
	s.audit(r, "批量处置告警", fmt.Sprintf("%d 条", updated), "status="+action+" note="+note)
	writeJSON(w, 200, map[string]interface{}{"ok": "1", "updated": updated})
}

func (s *Server) exportAlerts(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if !validAlertStatus(status) {
		status = ""
	}
	kind := r.URL.Query().Get("kind")
	if kind != "port" && kind != "unreachable" {
		kind = ""
	}
	alerts, err := s.st.AlertsFilteredKind(status, strings.TrimSpace(r.URL.Query().Get("q")), kind, 0)
	if err != nil {
		http.Error(w, "导出失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	records := [][]string{{"ID", "类型", "IP", "端口", "协议", "服务", "范围", "状态", "失败原因", "排查建议", "首次发现", "最近发现", "处理人", "处理说明", "处理时间"}}
	for _, a := range alerts {
		scope := "范围外"
		if a.InScope {
			scope = "范围内"
		}
		kindName, reason, suggestion := "端口风险", "", ""
		if a.Kind == "unreachable" {
			kindName, reason, suggestion = "网络不可达", a.Reason, store.UnreachableSuggestion(a.Reason)
		}
		records = append(records, []string{strconv.FormatInt(a.ID, 10), kindName, a.IP, strconv.Itoa(a.Port), a.Proto, a.Service, scope,
			alertStatusName(a.Status), reason, suggestion, a.FirstSeenAt, a.LastSeenAt, a.Handler, a.HandleNote, a.HandledAt})
	}
	writeCSVDownload(w, "alerts.csv", records)
}
