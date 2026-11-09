package scanner

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"easm-platform/internal/store"
)

// parseKind 描述一行 naabu 输出的解析结论。
type parseKind int

const (
	// parseSkip 表示该行与端口结果无关（空白、普通日志等），按兼容策略忽略。
	parseSkip parseKind = iota
	// parseResult 表示成功识别一条开放端口结果。
	parseResult
	// parseResolutionFailure 表示 naabu 明确报告某个目标域名解析失败。
	parseResolutionFailure
	// parseMalformed 表示本应是结构化输出（以 { 开头）却无法解析，输出完整性不可证明。
	parseMalformed
)

// parsedOutput 是一行输出统一解析后的结论。
type parsedOutput struct {
	kind   parseKind
	result store.Result
	target string
}

// outputScanBuffer 是 stdout / 输出文件单行上限；与流式扫描共用，避免超长行耗尽内存。
const outputScanBuffer = 1024 * 1024

// jsonResultPayload 是 naabu -json 输出的字段子集。
// 真实 naabu 会输出 host（原始目标，可能是域名）、ip（解析后的 IPv4/IPv6）、
// port、protocol 等字段；不同版本还可能带 tls/timestamp，这里只取需要的字段。
type jsonResultPayload struct {
	Host     string          `json:"host"`
	IP       string          `json:"ip"`
	Port     json.RawMessage `json:"port"`
	Protocol string          `json:"protocol"`
	Error    string          `json:"error"`
	Message  string          `json:"message"`
	Err      string          `json:"err"`
}

// parseOutputLine 统一解析一行 naabu 输出：
//   - 优先按 JSONL 解析（-json），正确识别 hostname / IPv4 / IPv6 / port / protocol；
//   - 保留普通文本 "host:port" / "[IPv6]:port" 兼容；
//   - 明确识别域名解析失败，交由上层记录并阻止虚报 done。
func parseOutputLine(line string) parsedOutput {
	line = strings.TrimSpace(line)
	if line == "" {
		return parsedOutput{kind: parseSkip}
	}
	if strings.HasPrefix(line, "{") {
		return parseJSONLine(line)
	}
	if looksLikeResolutionFailure(line) {
		return parsedOutput{kind: parseResolutionFailure, target: extractResolutionTarget(line)}
	}
	host, port, ok := splitTextHostPort(line)
	if !ok {
		return parsedOutput{kind: parseSkip}
	}
	address := normalizeAddress(host)
	if address == "" || port < 1 || port > 65535 {
		return parsedOutput{kind: parseSkip}
	}
	return parsedOutput{kind: parseResult, result: store.Result{IP: address, Port: port, Proto: "tcp", Status: 1}}
}

func parseJSONLine(line string) parsedOutput {
	var payload jsonResultPayload
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return parsedOutput{kind: parseMalformed}
	}
	port, _ := parseJSONPort(payload.Port)
	note := strings.TrimSpace(strings.Join([]string{payload.Error, payload.Message, payload.Err}, " "))
	host := normalizeHostname(payload.Host)
	ip, ipOK := normalizeIP(payload.IP)
	if note != "" && (looksLikeResolutionFailure(note) || port == 0) {
		target := host
		if target == "" {
			target = ip
		}
		if target == "" {
			target = truncateText(note, 120)
		}
		return parsedOutput{kind: parseResolutionFailure, target: target}
	}
	if port < 1 || port > 65535 {
		return parsedOutput{kind: parseMalformed}
	}
	address := ""
	if ipOK {
		// naabu 的默认域名策略是“首个 IPv4 与首个 IPv6”，JSON 中的 ip 就是实际扫描地址，
		// 优先使用规范化后的 IP，保证 IPv4/IPv6 表示统一。
		address = ip
	} else {
		address = host
	}
	if address == "" {
		return parsedOutput{kind: parseMalformed}
	}
	return parsedOutput{kind: parseResult, result: store.Result{IP: address, Port: port, Proto: normalizeProtocol(payload.Protocol), Status: 1}}
}

func parseJSONPort(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	text := strings.TrimSpace(string(raw))
	text = strings.Trim(text, `"`)
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// splitTextHostPort 解析普通文本 "host:port" 或 "[IPv6]:port"；
// 对不带方括号的 IPv6 使用最后一个冒号切分。
func splitTextHostPort(line string) (string, int, bool) {
	if strings.HasPrefix(line, "[") {
		end := strings.Index(line, "]")
		if end < 0 || end+1 >= len(line) || line[end+1] != ':' {
			return "", 0, false
		}
		host := line[1:end]
		port, err := strconv.Atoi(strings.TrimSpace(line[end+2:]))
		if err != nil || port < 1 || port > 65535 {
			return "", 0, false
		}
		return host, port, true
	}
	index := strings.LastIndex(line, ":")
	if index <= 0 || index == len(line)-1 {
		return "", 0, false
	}
	host := line[:index]
	port, err := strconv.Atoi(strings.TrimSpace(line[index+1:]))
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// normalizeAddress 统一地址表示：合法 IP 走 net.ParseIP 的规范形式，其余按域名规则规范化。
func normalizeAddress(value string) string {
	if ip, ok := normalizeIP(value); ok {
		return ip
	}
	return normalizeHostname(value)
}

// normalizeIP 统一 IPv4/IPv6 表示：去掉方括号与 zone，IPv4 输出点分十进制，IPv6 输出压缩小写形式。
func normalizeIP(value string) (string, bool) {
	text := strings.TrimSpace(value)
	text = strings.Trim(text, "[]")
	if index := strings.IndexByte(text, '%'); index >= 0 {
		text = text[:index]
	}
	ip := net.ParseIP(text)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	return ip.String(), true
}

// normalizeHostname 统一域名大小写并去掉结尾点，拒绝包含空白/路径/端口的非法主机名。
func normalizeHostname(value string) string {
	text := strings.ToLower(strings.TrimSpace(value))
	text = strings.Trim(text, "[]")
	text = strings.TrimSuffix(text, ".")
	if text == "" || len(text) > 253 {
		return ""
	}
	if strings.ContainsAny(text, " \t\r\n/\\?#@:;,") {
		return ""
	}
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return ""
	}
	if strings.Contains(text, "..") || strings.HasPrefix(text, ".") || strings.HasSuffix(text, ".") {
		return ""
	}
	return text
}

func normalizeProtocol(value string) string {
	proto := strings.ToLower(strings.TrimSpace(value))
	if proto == "" {
		return "tcp"
	}
	if len(proto) > 16 {
		return "tcp"
	}
	return proto
}

// resolutionFailureMarkers 是 naabu / 底层 DNS 解析失败的常见提示。
var resolutionFailureMarkers = []string{
	"could not resolve",
	"failed to resolve",
	"unable to resolve",
	"no such host",
	"dns lookup failed",
	"no address associated with hostname",
	"lookup failed",
	"could not lookup",
}

func looksLikeResolutionFailure(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range resolutionFailureMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// extractResolutionTarget 尽力从解析失败提示中提取目标；提取不到时保留截断后的整行，便于人工定位。
// 只接受看起来像 IP 或含点域名（naabu 的目标至少两级域名）的候选，避免把 "host"、"dns" 等
// 提示词误当成目标。
func extractResolutionTarget(line string) string {
	text := strings.TrimSpace(line)
	if index := strings.LastIndex(text, ":"); index >= 0 && index < len(text)-1 {
		candidate := strings.TrimSpace(text[index+1:])
		if plausibleTarget(candidate) {
			if normalized := normalizeAddress(candidate); normalized != "" {
				return normalized
			}
		}
	}
	for _, field := range strings.Fields(text) {
		candidate := strings.Trim(field, `"'():,;`)
		if !plausibleTarget(candidate) {
			continue
		}
		if normalized := normalizeAddress(candidate); normalized != "" {
			return normalized
		}
	}
	return truncateText(text, 160)
}

// plausibleTarget 判断候选片段是否可能是真实目标（合法 IP 或含点的合法域名）。
func plausibleTarget(candidate string) bool {
	if candidate == "" || strings.ContainsAny(candidate, " \t") {
		return false
	}
	if _, ok := normalizeIP(candidate); ok {
		return true
	}
	return strings.Contains(candidate, ".") && normalizeHostname(candidate) != ""
}

func truncateText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…"
}

// streamResultFile 以流式方式补读 naabu 的 -o 输出文件：逐行解析并回调，
// 不构造全量切片，因此大输出也保持有界内存。
// emit 返回 false 表示调用方要求停止（例如入库失败），此时函数正常返回。
func streamResultFile(path string, emit func(store.Result) bool, onResolution func(string), onMalformed func(string)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return streamOutput(file, emit, onResolution, onMalformed)
}

func streamOutput(reader io.Reader, emit func(store.Result) bool, onResolution func(string), onMalformed func(string)) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), outputScanBuffer)
	for scanner.Scan() {
		parsed := parseOutputLine(scanner.Text())
		switch parsed.kind {
		case parseResult:
			if emit != nil && !emit(parsed.result) {
				return nil
			}
		case parseResolutionFailure:
			if onResolution != nil {
				onResolution(parsed.target)
			}
		case parseMalformed:
			if onMalformed != nil {
				onMalformed(scanner.Text())
			}
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			// 文件里存在超过单行上限的行：Scanner 会停止读取，后面的结果全部丢失，
			// 必须按“读取不完整”上报（而不是静默截断）。
			return fmt.Errorf("输出文件存在超过单行上限 %d 字节的行，无法完整解析: %w", outputScanBuffer, err)
		}
		return err
	}
	return nil
}

// recentKeyCache 是有界近期结果缓存：仅用于减少重复提交，最终去重完全依赖
// scan_results 的 UNIQUE(scan_id, ip, port, proto) 与 INSERT OR IGNORE。
// 使用环形队列淘汰最旧键，内存上限固定为 limit 条，不会随全端口扫描无限增长。
type recentKeyCache struct {
	limit int
	set   map[string]struct{}
	ring  []string
	next  int
}

func newRecentKeyCache(limit int) *recentKeyCache {
	if limit < 1 {
		limit = 1
	}
	return &recentKeyCache{limit: limit, set: make(map[string]struct{}, limit), ring: make([]string, 0, limit)}
}

func (c *recentKeyCache) has(key string) bool {
	if c == nil {
		return false
	}
	_, ok := c.set[key]
	return ok
}

func (c *recentKeyCache) add(key string) {
	if c == nil || key == "" {
		return
	}
	if _, ok := c.set[key]; ok {
		return
	}
	if len(c.ring) < c.limit {
		c.ring = append(c.ring, key)
		c.set[key] = struct{}{}
		return
	}
	old := c.ring[c.next]
	delete(c.set, old)
	c.ring[c.next] = key
	c.set[key] = struct{}{}
	c.next = (c.next + 1) % c.limit
}

func (c *recentKeyCache) len() int {
	if c == nil {
		return 0
	}
	return len(c.set)
}

// describeParseFailure 生成便于写入执行事件的解析失败描述。
func describeParseFailure(lines int) string {
	if lines <= 0 {
		return ""
	}
	return fmt.Sprintf("输出中有 %d 行结构化数据无法解析，无法证明实时输出完整", lines)
}
