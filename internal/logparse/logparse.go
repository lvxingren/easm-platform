// Package logparse 解析 CFW 防火墙 / ECS 云主机等网络交互日志（CSV/JSON/TXT/XLSX），
// 自动识别列头并归一化为通信记录，再聚合为资产间通信关系（供 AI 分析与拓扑展示）。
package logparse

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
)

// Flow 是一条归一化的网络交互记录。
type Flow struct {
	SrcIP     string
	DstIP     string
	DstPort   int
	Proto     string
	Action    string
	Timestamp string
}

// Edge 是聚合后的资产间通信关系（src → dst:port/proto）。
type Edge struct {
	SrcIP     string
	DstIP     string
	DstPort   int
	Proto     string
	Action    string
	Count     int
	FirstSeen string
	LastSeen  string
}

// Result 是一次解析的产出与统计。
type Result struct {
	Flows   []Flow
	Format  string // csv | json | txt | xlsx
	Rows    int
	Skipped int
}

// 规范字段 → 常见列头别名（全部小写比较，忽略空格）。
var fieldAliases = map[string][]string{
	"src_ip":    srcIPAliases,
	"dst_ip":    dstIPAliases,
	"dst_port":  dstPortAliases,
	"protocol":  protoAliases,
	"action":    actionAliases,
	"timestamp": timeAliases,
}

var aliasToField = buildAliasIndex()

func buildAliasIndex() map[string]string {
	idx := map[string]string{}
	for field, aliases := range fieldAliases {
		for _, a := range aliases {
			idx[normalizeKey(a)] = field
		}
	}
	return idx
}

func normalizeKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "\ufeff", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

// ParseBytes 按文件扩展名选择解析器，返回归一化通信记录。
func ParseBytes(data []byte, filename string) (*Result, error) {
	name := strings.ToLower(strings.TrimSpace(filename))
	switch {
	case strings.HasSuffix(name, ".json"):
		return parseJSON(data)
	case strings.HasSuffix(name, ".xlsx") || strings.HasSuffix(name, ".xlsm"):
		return parseXLSX(data)
	case strings.HasSuffix(name, ".csv"):
		return parseDelimited(data, ',', "csv")
	case strings.HasSuffix(name, ".tsv"):
		return parseDelimited(data, '\t', "txt")
	default:
		// TXT / 未知扩展名（含 .txt / .log）
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{') {
			if r, err := parseJSON(data); err == nil && len(r.Flows) > 0 {
				return r, nil
			}
		}
		sep := ','
		if bytes.Count(data, []byte{'\t'}) > bytes.Count(data, []byte{','}) {
			sep = '\t'
		}
		return parseDelimited(data, sep, "txt")
	}
}

func parseJSON(data []byte) (*Result, error) {
	res := &Result{Format: "json"}
	records, err := jsonToRecords(data)
	if err != nil {
		return nil, err
	}
	flowsFromRecords(res, records)
	return res, nil
}

// jsonToRecords 兼容 JSON 数组、顶层对象（含 data/logs/records 数组）与 NDJSON（每行一个对象）。
func jsonToRecords(data []byte) ([]map[string]string, error) {
	trimmed := bytes.TrimSpace(data)
	var out []map[string]string
	// 1) 标准 JSON 数组或对象
	var generic interface{}
	if err := json.Unmarshal(trimmed, &generic); err == nil {
		for _, m := range extractArray(generic) {
			out = append(out, flattenMap(m))
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	// 2) NDJSON
	for _, line := range bytes.Split(trimmed, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(line, &m); err == nil {
			out = append(out, flattenMap(m))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("JSON 中未解析到对象记录")
	}
	return out, nil
}

func extractArray(v interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	switch t := v.(type) {
	case []interface{}:
		for _, item := range t {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
	case map[string]interface{}:
		// 顶层对象：优先取常见数组字段，否则视为单条记录
		for _, k := range []string{"data", "logs", "records", "items", "results", "rows", "list", "entries"} {
			if arr, ok := t[k].([]interface{}); ok {
				for _, item := range arr {
					if m, ok := item.(map[string]interface{}); ok {
						out = append(out, m)
					}
				}
				if len(out) > 0 {
					return out
				}
			}
		}
		out = append(out, t)
	}
	return out
}

func flattenMap(m map[string]interface{}) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = scalarToString(v)
	}
	return out
}

func scalarToString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		// JSON 数字统一为 float64，端口等整数去掉小数
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func parseDelimited(data []byte, sep rune, format string) (*Result, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.Comma = sep
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s 解析失败: %v", format, err)
	}
	res := &Result{Format: format}
	flowsFromRows(res, rows)
	return res, nil
}

func parseXLSX(data []byte) (*Result, error) {
	f, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("xlsx 解析失败: %v", err)
	}
	defer f.Close()
	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, fmt.Errorf("xlsx 无工作表")
	}
	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, err
	}
	res := &Result{Format: "xlsx"}
	flowsFromRows(res, rows)
	return res, nil
}

// flowsFromRows 处理带表头的二维表（CSV/TSV/XLSX）
func flowsFromRows(res *Result, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	colIndex := mapColumns(rows[0])
	if colIndex == nil {
		// 首行不是表头，尝试把所有行当数据（用无表头启发式）
		colIndex = guessColumns(rows)
		if colIndex == nil {
			res.Skipped += len(rows)
			return
		}
		for _, row := range rows {
			res.Rows++
			if f, ok := rowToFlow(row, colIndex); ok {
				res.Flows = append(res.Flows, f)
			} else {
				res.Skipped++
			}
		}
		return
	}
	for _, row := range rows[1:] {
		res.Rows++
		if f, ok := rowToFlow(row, colIndex); ok {
			res.Flows = append(res.Flows, f)
		} else {
			res.Skipped++
		}
	}
}

func flowsFromRecords(res *Result, records []map[string]string) {
	for _, rec := range records {
		res.Rows++
		mapped := map[string]string{}
		for k, v := range rec {
			if field, ok := aliasToField[normalizeKey(k)]; ok {
				mapped[field] = v
			}
		}
		src := strings.TrimSpace(mapped["src_ip"])
		dst := strings.TrimSpace(mapped["dst_ip"])
		if src == "" && dst == "" {
			res.Skipped++
			continue
		}
		if (src != "" && !validEndpoint(src)) || (dst != "" && !validEndpoint(dst)) {
			res.Skipped++
			continue
		}
		res.Flows = append(res.Flows, Flow{
			SrcIP:     src,
			DstIP:     dst,
			DstPort:   parsePort(mapped["dst_port"]),
			Proto:     normalizeProto(mapped["protocol"]),
			Action:    strings.ToLower(strings.TrimSpace(mapped["action"])),
			Timestamp: strings.TrimSpace(mapped["timestamp"]),
		})
	}
}

// mapColumns 依据表头返回 规范字段→列索引；无法识别返回 nil。
func mapColumns(header []string) map[string]int {
	idx := map[string]int{}
	for i, h := range header {
		if field, ok := aliasToField[normalizeKey(h)]; ok {
			if _, exists := idx[field]; !exists {
				idx[field] = i
			}
		}
	}
	if _, ok := idx["src_ip"]; !ok {
		if _, ok2 := idx["dst_ip"]; !ok2 {
			return nil
		}
	}
	return idx
}

// guessColumns 无表头时启发式识别 IP 列（至少两列像 IP）。
func guessColumns(rows [][]string) map[string]int {
	if len(rows) == 0 {
		return nil
	}
	maxCols := 0
	for _, r := range rows {
		if len(r) > maxCols {
			maxCols = len(r)
		}
	}
	ipCols := []int{}
	for c := 0; c < maxCols; c++ {
		total, ipLike := 0, 0
		for _, r := range rows {
			if c >= len(r) {
				continue
			}
			cell := strings.TrimSpace(r[c])
			if cell == "" {
				continue
			}
			total++
			if net.ParseIP(cell) != nil {
				ipLike++
			}
		}
		if total > 0 && float64(ipLike)/float64(total) >= 0.7 {
			ipCols = append(ipCols, c)
		}
	}
	if len(ipCols) < 2 {
		return nil
	}
	return map[string]int{"src_ip": ipCols[0], "dst_ip": ipCols[1]}
}

func rowToFlow(row []string, idx map[string]int) (Flow, bool) {
	get := func(field string) string {
		if c, ok := idx[field]; ok && c < len(row) {
			return strings.TrimSpace(row[c])
		}
		return ""
	}
	src := get("src_ip")
	dst := get("dst_ip")
	if src == "" && dst == "" {
		return Flow{}, false
	}
	if (src != "" && !validEndpoint(src)) || (dst != "" && !validEndpoint(dst)) {
		return Flow{}, false
	}
	return Flow{
		SrcIP:     src,
		DstIP:     dst,
		DstPort:   parsePort(get("dst_port")),
		Proto:     normalizeProto(get("protocol")),
		Action:    strings.ToLower(get("action")),
		Timestamp: get("timestamp"),
	}, true
}

// validEndpoint 判断 src/dst 是否为合法 IP 或域名，过滤脏数据列。
func validEndpoint(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	return strings.Contains(s, ".") && !strings.ContainsAny(s, " \t/\\")
}

func parsePort(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if i := strings.IndexAny(s, "-/ "); i > 0 {
		s = s[:i]
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 {
		return 0
	}
	return p
}

func normalizeProto(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	case "1", "icmp":
		return "icmp"
	case "":
		return ""
	default:
		return s
	}
}

// Aggregate 把通信记录按 src→dst:port/proto/action 聚合为关系，按次数降序。
func Aggregate(flows []Flow) []Edge {
	type key struct {
		src, dst, proto, action string
		port                    int
	}
	buckets := map[key]*Edge{}
	for _, f := range flows {
		k := key{f.SrcIP, f.DstIP, f.Proto, f.Action, f.DstPort}
		e, ok := buckets[k]
		if !ok {
			e = &Edge{SrcIP: f.SrcIP, DstIP: f.DstIP, DstPort: f.DstPort, Proto: f.Proto, Action: f.Action, FirstSeen: f.Timestamp, LastSeen: f.Timestamp}
			buckets[k] = e
		}
		e.Count++
		if f.Timestamp != "" {
			if e.FirstSeen == "" || f.Timestamp < e.FirstSeen {
				e.FirstSeen = f.Timestamp
			}
			if e.LastSeen == "" || f.Timestamp > e.LastSeen {
				e.LastSeen = f.Timestamp
			}
		}
	}
	out := make([]Edge, 0, len(buckets))
	for _, e := range buckets {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].SrcIP < out[j].SrcIP
	})
	return out
}

// 常见列头别名（覆盖 CFW / 云安全组 / V PC 流日志等命名习惯）。
var (
	srcIPAliases   = []string{"src_ip", "srcip", "source_ip", "sourceip", "src", "source", "src_addr", "source_address", "saddr", "client_ip", "clientip", "initiator", "源ip", "源地址", "发起方", "攻击源", "内网ip", "private_ip"}
	dstIPAliases   = []string{"dst_ip", "dstip", "dst", "destination", "destination_ip", "dst_addr", "destination_address", "daddr", "remote_ip", "remoteip", "responder", "目的ip", "目的地址", "目标ip", "目标地址", "外网ip", "public_ip"}
	dstPortAliases = []string{"dst_port", "dstport", "destination_port", "dstport", "dport", "server_port", "remote_port", "目的端口", "目标端口", "端口"}
	protoAliases   = []string{"protocol", "proto", "l4_protocol", "ip_protocol", "transport", "transport_protocol", "协议"}
	actionAliases  = []string{"action", "act", "operation", "result", "decision", "policy_action", "rule_action", "event_action", "status", "动作", "行为", "结果", "策略"}
	timeAliases    = []string{"timestamp", "time", "@timestamp", "datetime", "date", "event_time", "create_time", "created_at", "时间", "发生时间", "起始时间"}
)
