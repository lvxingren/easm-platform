// Package ai 通过 OpenAI 兼容接口（POST {endpoint}/chat/completions，Bearer Token）
// 对清洗聚合后的网络交互数据做安全分析：还原拓扑、识别异常通信、给出溯源路径。
// 未配置端点时使用内置规则降级分析（离线可用），配置后端点则调用真实模型。
// 所有请求走 HTTPS，Token 与请求/响应不落盘、不写日志。
package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"easm-platform/internal/logparse"
)

// Config 是 AI 调用配置（来自系统设置）。
type Config struct {
	Endpoint    string
	APIKey      string
	Model       string
	TimeoutSec  int
	Temperature float64
}

// Report 是 AI（或降级规则）输出的结构化分析结果。
type Report struct {
	TopologySummary string      `json:"topology_summary"`
	Nodes           []Node      `json:"nodes"`
	Edges           []EdgeView  `json:"edges"`
	Anomalies       []Anomaly   `json:"anomalies"`
	TracePaths      []TracePath `json:"trace_paths"`
	Readable        string      `json:"readable"`
}

type Node struct {
	IP   string `json:"ip"`
	Role string `json:"role"`
	Note string `json:"note"`
}

type EdgeView struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Risk  string `json:"risk"`
	Note  string `json:"note"`
}

type Anomaly struct {
	Type      string `json:"type"`
	Detail    string `json:"detail"`
	Severity  string `json:"severity"`
	RelatedIP string `json:"related_ip"`
}

type TracePath struct {
	Title      string   `json:"title"`
	EntryPoint string   `json:"entry_point"`
	Target     string   `json:"target"`
	Steps      []string `json:"steps"`
}

const systemPrompt = `你是一名资深网络安全分析师，擅长从防火墙(CFW)与云主机(ECS)流量/安全组日志中还原网络拓扑、识别异常通信与横向移动迹象，并给出可追溯的攻击溯源路径。
你必须只输出一个 JSON 对象，不要输出任何解释性文字或 markdown 代码块。JSON 结构固定为：
{
  "topology_summary": "资产间连接关系与关键跳板/中转节点的文字摘要",
  "nodes": [{"ip":"", "role":"跳板|中转|服务器|终端|外部", "note":""}],
  "edges": [{"src":"", "dst":"", "port":0, "proto":"", "risk":"low|mid|high", "note":""}],
  "anomalies": [{"type":"非常规端口|可疑外联|横向移动|其他", "detail":"", "severity":"info|warn|high", "related_ip":""}],
  "trace_paths": [{"title":"", "entry_point":"潜在入侵起点IP", "target":"受害/告警资产IP", "steps":["从X到Y的第1跳说明","第2跳说明"]}],
  "readable": "面向运营人员的完整可读分析报告(纯文本)"
}`

// Analyze 对聚合通信关系做分析。未配置 Endpoint 时用内置规则降级(返回 usedMock=true)；
// 配置了端点则调用真实模型，失败返回 error（由上层置为 failed，不静默降级）。
func Analyze(cfg Config, edges []logparse.Edge, flowCount int, sourceType string) (*Report, bool, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return ruleBasedReport(edges, flowCount, sourceType), true, nil
	}
	rep, err := callOpenAI(cfg, edges, flowCount, sourceType)
	if err != nil {
		return nil, false, err
	}
	return rep, false, nil
}

// TestConnection 用一次最小请求校验端点连通性与鉴权。
func TestConnection(cfg Config) error {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return fmt.Errorf("未配置 AI 端点 URL")
	}
	body := map[string]interface{}{
		"model":      firstNonEmpty(cfg.Model, "gpt-4o-mini"),
		"messages":   []map[string]string{{"role": "user", "content": "连通性测试，请回复 ok"}},
		"max_tokens": 5,
	}
	resp, err := doChat(cfg, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("鉴权失败(%d)：请检查 Token 是否正确、是否过期", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("端点返回 %d：%s", resp.StatusCode, truncate(string(raw), 300))
	}
	return nil
}

func callOpenAI(cfg Config, edges []logparse.Edge, flowCount int, sourceType string) (*Report, error) {
	body := map[string]interface{}{
		"model":           firstNonEmpty(cfg.Model, "gpt-4o-mini"),
		"messages":        []map[string]string{{"role": "system", "content": systemPrompt}, {"role": "user", "content": buildPrompt(edges, flowCount, sourceType)}},
		"temperature":     cfg.Temperature,
		"response_format": map[string]string{"type": "json_object"},
	}
	resp, err := doChat(cfg, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AI 接口返回 %d：%s", resp.StatusCode, truncate(string(raw), 400))
	}
	var chat struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &chat); err != nil {
		return nil, fmt.Errorf("解析 AI 响应失败: %v", err)
	}
	if len(chat.Choices) == 0 {
		return nil, fmt.Errorf("AI 响应缺少 choices")
	}
	content := chat.Choices[0].Message.Content
	var rep Report
	if err := json.Unmarshal([]byte(extractJSON(content)), &rep); err != nil {
		return nil, fmt.Errorf("AI 输出不是合法 JSON: %v；原文前 300 字：%s", err, truncate(content, 300))
	}
	if rep.Readable == "" {
		rep.Readable = rep.TopologySummary
	}
	return &rep, nil
}

func doChat(cfg Config, body map[string]interface{}) (*http.Response, error) {
	if err := ValidateEndpoint(cfg.Endpoint); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	url := strings.TrimSuffix(strings.TrimSpace(cfg.Endpoint), "/")
	if !strings.HasSuffix(url, "/chat/completions") {
		url += "/chat/completions"
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(cfg.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.APIKey))
	}
	timeout := cfg.TimeoutSec
	if timeout <= 0 {
		timeout = 60
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	return client.Do(req)
}

// buildPrompt 把聚合通信关系（限制条数避免超出上下文）组织为用户提示。
func buildPrompt(edges []logparse.Edge, flowCount int, sourceType string) string {
	const maxEdges = 120
	list := edges
	if len(list) > maxEdges {
		list = list[:maxEdges]
	}
	type slimEdge struct {
		Src    string `json:"src"`
		Dst    string `json:"dst"`
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Action string `json:"action"`
		Count  int    `json:"count"`
	}
	slim := make([]slimEdge, 0, len(list))
	for _, e := range list {
		slim = append(slim, slimEdge{e.SrcIP, e.DstIP, e.DstPort, e.Proto, e.Action, e.Count})
	}
	data, _ := json.Marshal(slim)
	var b strings.Builder
	b.WriteString("以下是从" + sourceLabel(sourceType) + "日志中聚合出的资产间通信关系（按次数降序，最多 " + fmt.Sprint(maxEdges) + " 条）。\n")
	fmt.Fprintf(&b, "原始交互记录总数：%d；聚合通信关系数：%d。\n", flowCount, len(edges))
	b.WriteString("通信关系(JSON)：\n")
	b.Write(data)
	b.WriteString("\n\n请据此还原网络拓扑、标出关键跳板/中转节点，识别异常通信（非常规端口、可疑外联、横向移动迹象），并给出从告警/受害资产回溯到潜在入侵起点的溯源路径。严格按系统要求的 JSON 结构输出。")
	return b.String()
}

func sourceLabel(t string) string {
	switch t {
	case "cfw":
		return "CFW 防火墙"
	case "ecs":
		return "ECS 云主机"
	default:
		return "网络交互"
	}
}

// extractJSON 从可能含 markdown 或前后缀文字的模型输出中截取第一个完整 JSON 对象。
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

// ---------- 无 AI 端点时的内置规则降级分析 ----------

var highRiskPorts = map[int]string{
	22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 135: "RPC", 139: "NetBIOS",
	1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
}

func ruleBasedReport(edges []logparse.Edge, flowCount int, sourceType string) *Report {
	rep := &Report{}
	inDegree := map[string]int{}
	outDegree := map[string]int{}
	for _, e := range edges {
		if e.SrcIP != "" {
			outDegree[e.SrcIP]++
		}
		if e.DstIP != "" {
			inDegree[e.DstIP]++
		}
	}
	// 节点角色
	seen := map[string]bool{}
	for _, e := range edges {
		for _, ip := range []string{e.SrcIP, e.DstIP} {
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			role := "终端"
			note := ""
			if !isPrivate(ip) {
				role = "外部"
				note = "公网地址"
			} else if outDegree[ip] > 0 && inDegree[ip] > 0 {
				role = "中转"
				note = "既发起又接收连接，可能是跳板/中转节点"
			} else if inDegree[ip] >= 2 {
				role = "服务器"
				note = fmt.Sprintf("被 %d 个来源访问", inDegree[ip])
			}
			rep.Nodes = append(rep.Nodes, Node{IP: ip, Role: role, Note: note})
		}
	}
	sort.Slice(rep.Nodes, func(i, j int) bool { return rep.Nodes[i].IP < rep.Nodes[j].IP })

	// 边与风险
	fanout := map[int]map[string]bool{} // port -> set(dst) 用于横向移动判定
	for _, e := range edges {
		risk := "low"
		note := ""
		if svc, ok := highRiskPorts[e.DstPort]; ok {
			risk = "high"
			note = "高危管理/数据库端口 " + svc
		} else if e.DstPort > 0 && (e.DstPort >= 40000 || isUncommon(e.DstPort)) {
			risk = "mid"
			note = "非常规端口"
		}
		if e.DstIP != "" && !isPrivate(e.DstIP) {
			if risk == "low" {
				risk = "mid"
			}
			note = strings.TrimSpace(note + "；外联公网地址")
		}
		rep.Edges = append(rep.Edges, EdgeView{Src: e.SrcIP, Dst: e.DstIP, Port: e.DstPort, Proto: e.Proto, Risk: risk, Note: note})
		if e.DstPort > 0 {
			if fanout[e.DstPort] == nil {
				fanout[e.DstPort] = map[string]bool{}
			}
			fanout[e.DstPort][e.DstIP] = true
		}
	}

	// 异常
	for _, ev := range rep.Edges {
		if ev.Risk == "high" {
			rep.Anomalies = append(rep.Anomalies, Anomaly{Type: "非常规端口", Detail: fmt.Sprintf("%s → %s:%d 命中高危端口(%s)", ev.Src, ev.Dst, ev.Port, ev.Note), Severity: "high", RelatedIP: ev.Dst})
		} else if strings.Contains(ev.Note, "外联公网") {
			rep.Anomalies = append(rep.Anomalies, Anomaly{Type: "可疑外联", Detail: fmt.Sprintf("%s → %s:%d 外联公网", ev.Src, ev.Dst, ev.Port), Severity: "warn", RelatedIP: ev.Src})
		}
	}
	for port, dsts := range fanout {
		if len(dsts) >= 3 {
			if svc, ok := highRiskPorts[port]; ok {
				rep.Anomalies = append(rep.Anomalies, Anomaly{Type: "横向移动", Detail: fmt.Sprintf("端口 %d(%s) 被访问的目标达 %d 个，疑似横向扫描/移动", port, svc, len(dsts)), Severity: "high", RelatedIP: ""})
			}
		}
	}
	if len(rep.Anomalies) > 30 {
		rep.Anomalies = rep.Anomalies[:30]
	}

	// 溯源路径（规则近似）：以高危边的目标为受害资产，源为潜在起点
	for _, ev := range rep.Edges {
		if ev.Risk == "high" && len(rep.TracePaths) < 5 {
			rep.TracePaths = append(rep.TracePaths, TracePath{
				Title:      fmt.Sprintf("到 %s:%d 的高危访问链", ev.Dst, ev.Port),
				EntryPoint: ev.Src,
				Target:     ev.Dst,
				Steps: []string{
					fmt.Sprintf("起点 %s 向 %s:%d(%s) 发起连接，命中高危端口", ev.Src, ev.Dst, ev.Port, ev.Note),
					fmt.Sprintf("建议核查 %s 的登录/爆破记录与 %s 上该服务的访问审计", ev.Src, ev.Dst),
				},
			})
		}
	}

	rep.TopologySummary = fmt.Sprintf("共 %d 个节点、%d 条聚合通信关系（原始记录 %d 条，来源：%s）。其中中转/跳板节点与被多源访问的服务器为主要关注对象。",
		len(rep.Nodes), len(rep.Edges), flowCount, sourceLabel(sourceType))
	rep.Readable = rep.TopologySummary + "\n\n[内置规则分析] 当前未配置 AI 模型端点，以上为基于规则的降级分析（高危端口、外联公网、横向扇出）。在「系统设置 → AI 分析」配置模型端点与 Token 后重新分析，可获得更准确的拓扑还原、异常研判与自然语言溯源建议。"
	return rep
}

func isPrivate(ip string) bool {
	a := net.ParseIP(strings.TrimSpace(ip))
	if a == nil {
		return false
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

func isUncommon(port int) bool {
	common := map[int]bool{80: true, 443: true, 53: true, 8080: true, 8443: true, 21: true, 25: true, 110: true, 143: true, 993: true, 995: true, 587: true}
	return !common[port]
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ValidateEndpoint 校验 AI 端点：必须为合法 URL 且使用 HTTPS（仅本地 localhost/127.0.0.1/::1 允许 HTTP，便于自建网关测试）。
func ValidateEndpoint(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return fmt.Errorf("AI 端点为空")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return fmt.Errorf("AI 端点不是合法 URL：%s", endpoint)
	}
	host := u.Hostname()
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return fmt.Errorf("AI 端点必须使用 HTTPS（仅本地 localhost/127.0.0.1 允许 HTTP 测试），当前：%s", endpoint)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
