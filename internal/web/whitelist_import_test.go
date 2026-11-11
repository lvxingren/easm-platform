package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"easm-platform/internal/store"
)

// wlXlsxBytes 按行写入单个工作表，返回 xlsx 字节流（构造白名单导入用例的上传文件）。
func wlXlsxBytes(t *testing.T, rows [][]string) []byte {
	t.Helper()
	letters := []string{"A", "B", "C", "D", "E", "F", "G", "H"}
	f := excelize.NewFile()
	sheet := f.GetSheetName(0)
	for i, row := range rows {
		for j, v := range row {
			if j >= len(letters) {
				t.Fatalf("列数超出测试支持范围")
			}
			if err := f.SetCellValue(sheet, fmt.Sprintf("%s%d", letters[j], i+1), v); err != nil {
				t.Fatal(err)
			}
		}
	}
	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return buf.Bytes()
}

// wlFileRequest 以 multipart 形式提交白名单导入（文本字段 + 可选上传文件）。
func wlFileRequest(t *testing.T, server *Server, username string, fields map[string]string, fileName string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	return wlImportRequest(t, server, username, "/api/whitelist/import", fields, fileName, content)
}

// wlImportRequest 与 wlFileRequest 相同，但可指定提交路径（一步式导入 / 解析预览）。
func wlImportRequest(t *testing.T, server *Server, username, path string, fields map[string]string, fileName string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if fileName != "" {
		fw, err := mw.CreateFormFile("file", fileName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "easm_sid", Value: "test-" + username})
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	return rec
}

// wlPreviewRow 解析预览接口返回的单行候选规则。
type wlPreviewRow struct {
	IPSpec   string `json:"ip_spec"`
	PortSpec string `json:"port_spec"`
	Proto    string `json:"proto"`
	Service  string `json:"service"`
	Remark   string `json:"remark"`
	Source   string `json:"source"`
	Exists   bool   `json:"exists"`
}

func wlFindPreview(rows []wlPreviewRow, ipSpec, portSpec string) (wlPreviewRow, bool) {
	for _, r := range rows {
		if r.IPSpec == ipSpec && r.PortSpec == portSpec {
			return r, true
		}
	}
	return wlPreviewRow{}, false
}

func wlFindEntry(t *testing.T, entries []store.WLEntry, ipSpec string) store.WLEntry {
	t.Helper()
	for _, e := range entries {
		if e.IPSpec == ipSpec {
			return e
		}
	}
	t.Fatalf("未找到 %s 的白名单条目（共 %d 条）", ipSpec, len(entries))
	return store.WLEntry{}
}

// TestWhitelistImportReasonColumn 验证 Excel/CSV 导入时「原因」列按表头名识别并映射到 Reason 字段（与备注分开）。
func TestWhitelistImportReasonColumn(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	rows := [][]string{
		{"IP/网段", "端口", "服务", "原因", "备注"},
		{"10.5.0.1", "22", "SSH", "运维跳板机", "工单 #1"},
		{"10.5.0.2", "3306", "MySQL", "业务数据库", ""},
	}
	rec := wlFileRequest(t, server, "operator", nil, "wl-reason.xlsx", wlXlsxBytes(t, rows))
	if rec.Code != http.StatusOK {
		t.Fatalf("导入应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	entries, _ := st.Whitelist()
	if len(entries) != 2 {
		t.Fatalf("应导入 2 条，实际 %d", len(entries))
	}
	byIP := map[string]store.WLEntry{}
	for _, e := range entries {
		byIP[e.IPSpec] = e
	}
	if e := byIP["10.5.0.1"]; e.Reason != "运维跳板机" || e.Remark != "工单 #1" {
		t.Fatalf("原因/备注列映射错误: %+v", e)
	}
	if e := byIP["10.5.0.2"]; e.Reason != "业务数据库" || e.Remark != "" {
		t.Fatalf("第二行原因/备注映射错误: %+v", e)
	}
}

// TestWhitelistImportExcelTemplate 验证白名单 Excel 模板导入：
// IP+端口+服务+备注 四列按表头识别、逐行备注优先于批量备注、非法行逐行跳过并回显原因、
// 批内重复与库内已存在规则都不重复入库。
func TestWhitelistImportExcelTemplate(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	rows := [][]string{
		{"IP/网段", "端口", "服务", "备注"},
		{"1.2.3.4", "22,80,443", "SSH,HTTP,HTTPS", "工单 #1024 放行"},
		{"10.0.0.5", "3306", "MySQL", ""},
		{"10.0.0.0/24", "1000-2000", "业务端口段", "整段放行"},
		{"1.2.3.4", "abc", "非法端口行", ""},
		{"10.0.0.9", "", "", "端口留空且未勾选自动匹配"},
		{"1.2.3.4", "22,80,443", "重复规则", ""},
	}
	rec := wlFileRequest(t, server, "operator", map[string]string{"remark": "批量兜底备注"}, "wl.xlsx", wlXlsxBytes(t, rows))
	if rec.Code != http.StatusOK {
		t.Fatalf("导入应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"manual_added":3`, `"auto_added":0`, "端口非法", "未解析到端口", "批内规则重复"} {
		if !strings.Contains(body, want) {
			t.Fatalf("导入回显缺少 %s: %s", want, body)
		}
	}
	entries, _ := st.Whitelist()
	if len(entries) != 3 {
		t.Fatalf("应入库 3 条（非法/空端口/重复均被跳过），实际 %d", len(entries))
	}
	e := wlFindEntry(t, entries, "1.2.3.4")
	if e.PortSpec != "22,80,443" || e.Proto != "tcp" {
		t.Fatalf("端口/协议解析错误: %+v", e)
	}
	if e.Service != "SSH,HTTP,HTTPS" {
		t.Fatalf("服务列未写入: %+v", e)
	}
	if e.Remark != "工单 #1024 放行" {
		t.Fatalf("逐行备注应优先于批量备注: %q", e.Remark)
	}
	if e.Owner != "import" || e.Source != "manual" {
		t.Fatalf("导入条目来源标记错误: %+v", e)
	}
	if got := wlFindEntry(t, entries, "10.0.0.5"); got.Remark != "批量兜底备注" {
		t.Fatalf("未填备注的行应使用批量备注兜底: %+v", got)
	}
	if got := wlFindEntry(t, entries, "10.0.0.0/24"); got.PortSpec != "1000-2000" || got.Remark != "整段放行" {
		t.Fatalf("CIDR/端口范围解析错误: %+v", got)
	}

	// 页面渲染：上传控件与模板下载入口存在。
	page := newAuthedGet(server, "/whitelist", "operator")
	if pb := page.Body.String(); !strings.Contains(pb, `name="file"`) || !strings.Contains(pb, "/api/sample/whitelist.xlsx") {
		t.Fatalf("白名单页缺少 Excel 模板上传/下载入口")
	}
	// viewer 无导入权限。
	if rec := wlFileRequest(t, server, "viewer", nil, "wl.xlsx", wlXlsxBytes(t, rows)); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 导入应 403，实际 %d", rec.Code)
	}

	// 同一份表再导一次：规则完全相同的条目被库内去重，不产生重复规则。
	rec = wlFileRequest(t, server, "operator", map[string]string{"remark": "批量兜底备注"}, "wl.xlsx", wlXlsxBytes(t, rows))
	if rec.Code != http.StatusOK {
		t.Fatalf("重复导入应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if rb := rec.Body.String(); !strings.Contains(rb, `"manual_added":0`) || !strings.Contains(rb, "已在白名单") {
		t.Fatalf("重复导入应全部库内去重: %s", rb)
	}
	if entries, _ := st.Whitelist(); len(entries) != 3 {
		t.Fatalf("重复导入不应新增条目，实际 %d 条", len(entries))
	}
}

// TestWhitelistImportExcelProtoAndAutoMatch 验证可选「协议」列与端口留空行自动匹配已识别端口。
func TestWhitelistImportExcelProtoAndAutoMatch(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	if _, err := st.ImportTargets([]store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}}, "", "test"); err != nil {
		t.Fatal(err)
	}
	scanID, _ := st.CreateScan(0, "s", "top")
	if err := st.InsertResults(scanID, []store.Result{
		{IP: "192.0.2.1", Port: 53, Proto: "udp", Status: 1},
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Status: 1},
	}); err != nil {
		t.Fatal(err)
	}
	rows := [][]string{
		{"IP/网段", "端口", "协议", "服务", "备注"},
		{"10.0.0.1", "53", "udp", "DNS", "内网 DNS"},
		{"192.0.2.1", "", "", "", "端口留空走自动匹配"},
		{"10.0.0.2", "161", "SNMP", "协议列填了服务名", "非法协议应跳过"},
	}
	rec := wlFileRequest(t, server, "operator", map[string]string{"auto_match": "on"}, "wl.xlsx", wlXlsxBytes(t, rows))
	if rec.Code != http.StatusOK {
		t.Fatalf("导入应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// 自动匹配按历史开放端口逐条生成（tcp/443 + udp/53），手动 udp/53 一条，非法协议行跳过。
	if !strings.Contains(body, `"manual_added":1`) || !strings.Contains(body, `"auto_added":2`) {
		t.Fatalf("手动/自动数量错误: %s", body)
	}
	if !strings.Contains(body, "协议非法") {
		t.Fatalf("缺少协议非法跳过原因: %s", body)
	}
	entries, _ := st.Whitelist()
	udp := wlFindEntry(t, entries, "10.0.0.1")
	if udp.Proto != "udp" || udp.PortSpec != "53" || udp.Service != "DNS" || udp.Remark != "内网 DNS" {
		t.Fatalf("协议/服务/备注列解析错误: %+v", udp)
	}
	auto := 0
	for _, e := range entries {
		if e.Source == "auto_match" {
			auto++
			if e.Remark != "端口留空走自动匹配" {
				t.Fatalf("自动匹配条目应使用逐行备注: %+v", e)
			}
		}
	}
	if auto != 2 {
		t.Fatalf("自动匹配条目应 2 条，实际 %d", auto)
	}
}

// TestWhitelistImportCSVNoHeaderAndTemplateRoundTrip 验证无表头 CSV 按模板列序解析，
// 以及官方 Excel 模板下载后可直接回灌导入（模板与解析器列定义一致）。
func TestWhitelistImportCSVNoHeaderAndTemplateRoundTrip(t *testing.T) {
	server, st := newScanLiveTestServer(t)

	rec := wlFileRequest(t, server, "operator", nil, "wl.csv", []byte("1.2.3.9,8080,Nginx,临时站点\n10.9.9.9,443,HTTPS,门户\n"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"manual_added":2`) {
		t.Fatalf("无表头 CSV 导入失败: %d %s", rec.Code, rec.Body.String())
	}
	got := wlFindEntry(t, mustWhitelist(t, st), "1.2.3.9")
	if got.PortSpec != "8080" || got.Service != "Nginx" || got.Remark != "临时站点" {
		t.Fatalf("无表头列序解析错误: %+v", got)
	}

	// 下载 Excel 模板 → 原样上传：4 条合法规则入库，端口留空的示例行被跳过并提示。
	tpl := newAuthedGet(server, "/api/sample/whitelist.xlsx", "operator")
	if tpl.Code != http.StatusOK || !strings.Contains(tpl.Header().Get("Content-Type"), "spreadsheetml") {
		t.Fatalf("Excel 模板下载失败: %d %s", tpl.Code, tpl.Header().Get("Content-Type"))
	}
	rec = wlFileRequest(t, server, "operator", nil, "whitelist-template.xlsx", tpl.Body.Bytes())
	if rec.Code != http.StatusOK {
		t.Fatalf("模板回灌导入失败: %d %s", rec.Code, rec.Body.String())
	}
	if rb := rec.Body.String(); !strings.Contains(rb, `"manual_added":4`) || !strings.Contains(rb, "未解析到端口") {
		t.Fatalf("模板回灌结果错误: %s", rb)
	}

	// CSV 模板：含逗号的端口列必须被引号包裹，否则会被拆成多列。
	ctpl := newAuthedGet(server, "/api/sample/whitelist.csv", "operator")
	if cbody := ctpl.Body.String(); !strings.Contains(cbody, `"22,80,443"`) || !strings.Contains(cbody, "IP/网段,端口,服务,备注") {
		t.Fatalf("CSV 模板列或转义错误: %s", cbody)
	}
}

func mustWhitelist(t *testing.T, st *store.Store) []store.WLEntry {
	t.Helper()
	entries, err := st.Whitelist()
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// wlApplyRow 按确认导入接口的并列数组表单格式追加一行候选规则。
func wlApplyRow(form url.Values, ip, port, proto, service, remark, source string) {
	form.Add("ip", ip)
	form.Add("port", port)
	form.Add("proto", proto)
	form.Add("service", service)
	form.Add("remark", remark)
	form.Add("source", source)
}

// TestWhitelistImportPreviewThenApply 验证页面两步式导入：预览只解析不写库，
// 自动匹配在预览阶段就展开为具体端口供勾选，确认导入只写入提交行，
// 重复提交被库内去重、非法条目被逐条校验拦住。
func TestWhitelistImportPreviewThenApply(t *testing.T) {
	server, st := newScanLiveTestServer(t)
	if _, err := st.ImportTargets([]store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}}, "", "test"); err != nil {
		t.Fatal(err)
	}
	scanID, _ := st.CreateScan(0, "s", "top")
	if err := st.InsertResults(scanID, []store.Result{
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Status: 1, Service: "HTTPS"},
		{IP: "192.0.2.1", Port: 8080, Proto: "tcp", Status: 1},
	}); err != nil {
		t.Fatal(err)
	}
	rows := [][]string{
		{"IP/网段", "端口", "服务", "备注"},
		{"1.2.3.4", "22,80", "SSH,HTTP", "工单 #9"},
		{"10.0.0.5", "3306", "MySQL", ""},
		{"bad-ip", "443", "", "非法 IP 行"},
		{"192.0.2.1", "", "", "自动匹配展开"},
	}
	fields := map[string]string{"auto_match": "on", "remark": "批量备注"}
	var out struct {
		Entries  []wlPreviewRow `json:"entries"`
		Skipped  []string       `json:"skipped"`
		Total    int            `json:"total"`
		Existing int            `json:"existing"`
	}
	rec := wlImportRequest(t, server, "operator", "/api/whitelist/import/preview", fields, "wl.xlsx", wlXlsxBytes(t, rows))
	if rec.Code != http.StatusOK {
		t.Fatalf("预览应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("预览回显解析失败: %v body=%s", err, rec.Body.String())
	}
	// 2 条手动 + 自动匹配展开的 2 个端口；非法 IP 行单独跳过并回显原因。
	if out.Total != 4 || out.Existing != 0 || len(out.Entries) != 4 {
		t.Fatalf("预览条数错误: %+v", out)
	}
	if len(out.Skipped) != 1 || !strings.Contains(out.Skipped[0], "IP/网段非法") {
		t.Fatalf("预览缺少非法行跳过原因: %v", out.Skipped)
	}
	if entries := mustWhitelist(t, st); len(entries) != 0 {
		t.Fatalf("预览不得写入白名单，实际 %d 条", len(entries))
	}
	if auto, ok := wlFindPreview(out.Entries, "192.0.2.1", "443"); !ok || auto.Source != "auto_match" || auto.Service != "HTTPS" || auto.Remark != "自动匹配展开" {
		t.Fatalf("自动匹配未在预览展开: %+v", out.Entries)
	}
	if row, ok := wlFindPreview(out.Entries, "10.0.0.5", "3306"); !ok || row.Remark != "批量备注" {
		t.Fatalf("未填备注的行应在预览中就体现批量备注兜底: %+v", out.Entries)
	}
	if row, ok := wlFindPreview(out.Entries, "1.2.3.4", "22,80"); !ok || row.Remark != "工单 #9" || row.Exists {
		t.Fatalf("逐行备注优先失效: %+v", row)
	}

	// 页面渲染：两步式导入入口与预览容器存在。
	if pb := newAuthedGet(server, "/whitelist", "operator").Body.String(); !strings.Contains(pb, "/api/whitelist/import/preview") || !strings.Contains(pb, "确认导入") {
		t.Fatal("白名单页缺少两步式导入入口")
	}
	// viewer 无预览/确认权限。
	if r := wlImportRequest(t, server, "viewer", "/api/whitelist/import/preview", fields, "wl.xlsx", wlXlsxBytes(t, rows)); r.Code != http.StatusForbidden {
		t.Fatalf("viewer 预览应 403，实际 %d", r.Code)
	}
	if r := scanFormRequest(server, "/api/whitelist/import/apply", "viewer", url.Values{"ip": {"1.2.3.4"}}); r.Code != http.StatusForbidden {
		t.Fatalf("viewer 确认导入应 403，实际 %d", r.Code)
	}

	// 只确认导入其中两条（1 手动 + 1 自动匹配）。
	form := url.Values{}
	wlApplyRow(form, "1.2.3.4", "22,80", "tcp", "SSH,HTTP", "工单 #9", "manual")
	wlApplyRow(form, "192.0.2.1", "443", "tcp", "HTTPS", "自动匹配展开", "auto_match")
	if rec := scanFormRequest(server, "/api/whitelist/import/apply", "operator", form); rec.Code != http.StatusOK {
		t.Fatalf("确认导入应 200，实际 %d: %s", rec.Code, rec.Body.String())
	} else if body := rec.Body.String(); !strings.Contains(body, `"added":2`) || !strings.Contains(body, `"manual_added":1`) || !strings.Contains(body, `"auto_added":1`) {
		t.Fatalf("确认导入回显错误: %s", body)
	}
	entries := mustWhitelist(t, st)
	if len(entries) != 2 {
		t.Fatalf("应仅写入勾选的 2 条，实际 %d 条", len(entries))
	}
	if got := wlFindEntry(t, entries, "192.0.2.1"); got.PortSpec != "443" || got.Source != "auto_match" || got.Owner != "import" {
		t.Fatalf("自动匹配条目写入错误: %+v", got)
	}
	if got := wlFindEntry(t, entries, "1.2.3.4"); got.Remark != "工单 #9" || got.Business != "" {
		t.Fatalf("手动条目备注写入错误: %+v", got)
	}

	// 再次预览：已入库的两条标记为已在白名单（前端默认不勾选）。
	if rec := wlImportRequest(t, server, "operator", "/api/whitelist/import/preview", fields, "wl.xlsx", wlXlsxBytes(t, rows)); rec.Code != http.StatusOK {
		t.Fatalf("二次预览应 200，实际 %d: %s", rec.Code, rec.Body.String())
	} else if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Existing != 2 {
		t.Fatalf("二次预览应标记 2 条已存在: %+v", out)
	}
	if row, ok := wlFindPreview(out.Entries, "1.2.3.4", "22,80"); !ok || !row.Exists {
		t.Fatalf("已入库规则应标记 exists: %+v", out.Entries)
	}

	// 整表确认导入：已存在的 2 条被跳过，仅补充未入库的 2 条。
	form = url.Values{}
	for _, e := range out.Entries {
		wlApplyRow(form, e.IPSpec, e.PortSpec, e.Proto, e.Service, e.Remark, e.Source)
	}
	rec = scanFormRequest(server, "/api/whitelist/import/apply", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("补量导入应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"added":2`) || !strings.Contains(body, "已在白名单") {
		t.Fatalf("整表确认导入应去重已存在规则: %s", body)
	}
	if entries := mustWhitelist(t, st); len(entries) != 4 {
		t.Fatalf("最终应 4 条不重复规则，实际 %d", len(entries))
	}

	// 确认导入阶段重新校验客户端数据：空勾选与非法条目都拒收。
	if rec := scanFormRequest(server, "/api/whitelist/import/apply", "operator", url.Values{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("未勾选应 400，实际 %d", rec.Code)
	}
	form = url.Values{}
	wlApplyRow(form, "not-an-ip", "443", "tcp", "", "", "manual")
	if rec := scanFormRequest(server, "/api/whitelist/import/apply", "operator", form); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "条目非法") {
		t.Fatalf("非法条目应 400: %d %s", rec.Code, rec.Body.String())
	}
	form = url.Values{}
	wlApplyRow(form, "1.2.3.55", "443", "tcp", "", strings.Repeat("长", 800), "manual")
	if rec := scanFormRequest(server, "/api/whitelist/import/apply", "operator", form); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "备注过长") {
		t.Fatalf("超长备注应 400: %d %s", rec.Code, rec.Body.String())
	}
	if entries := mustWhitelist(t, st); len(entries) != 4 {
		t.Fatalf("拒收的提交不得写入，实际 %d 条", len(entries))
	}
}

// TestWhitelistTextImportSkipsInvalidLines 验证文本框粘贴导入逐行容错：
// 非法行只跳过并回显行号与原因，合法行照常进入预览（与 README 承诺、表格导入一致）。
func TestWhitelistTextImportSkipsInvalidLines(t *testing.T) {
	server, _ := newScanLiveTestServer(t)
	form := url.Values{}
	form.Set("entries", "1.2.3.4 22,80\nbad_ip 443\n1.2.3.5 3389")
	rec := scanFormRequest(server, "/api/whitelist/import/preview", "operator", form)
	if rec.Code != http.StatusOK {
		t.Fatalf("非法行不应阻断整批导入，实际 %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Total   int            `json:"total"`
		Skipped []string       `json:"skipped"`
		Entries []wlPreviewRow `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("预览回显解析失败: %v", err)
	}
	if out.Total != 2 || len(out.Entries) != 2 {
		t.Fatalf("应保留 2 条合法规则（多端口合为一条），实际 total=%d entries=%d", out.Total, len(out.Entries))
	}
	if len(out.Skipped) != 1 || !strings.Contains(out.Skipped[0], "第 2 行") {
		t.Fatalf("应回显带行号的非法行原因: %v", out.Skipped)
	}
}
