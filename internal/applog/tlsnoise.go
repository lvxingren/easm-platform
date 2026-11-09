package applog

import (
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// 本文件实现「客户端 TLS 握手噪音」的来源提取、IP 掩码与当日/本周统计，
// 供运行日志页的「TLS 握手噪音统计」面板展示，帮助管理员判断是否为持续扫描攻击。
// 统计为内存态（有界），进程重启后清空，与环形缓冲生命周期一致。

// tlsNoiseMaxEvents 限制保留的噪音事件数，超出丢弃最旧，避免内存无界增长。
const tlsNoiseMaxEvents = 10000

// clientIPRe 匹配 http.Server 握手错误中的「from <host>:<port>」，兼容 IPv4 与 [IPv6]。
var clientIPRe = regexp.MustCompile(`from\s+(\[[^\]]+\]|[^:\s]+):\d+`)

// tlsEvent 是一条被降级的客户端 TLS 噪音事件（只保留时间与来源段，不存完整 IP）。
type tlsEvent struct {
	at  time.Time
	seg string
}

type tlsNoiseTracker struct {
	mu     sync.Mutex
	events []tlsEvent
}

var noiseTracker = &tlsNoiseTracker{}

// ExtractClientIP 从握手错误日志中提取来源 IP（不含端口）；提取失败返回空串。
func ExtractClientIP(msg string) string {
	m := clientIPRe.FindStringSubmatch(msg)
	if len(m) < 2 {
		return ""
	}
	host := m[1]
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

// MaskIP 把 IP 的最后一段掩码（保留前 3 段），用于日志展示以降低隐私暴露：
// IPv4 "203.0.113.5" → "203.0.113.*"；IPv6 保留前 3 组。非法输入原样返回。
func MaskIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return strings.Join(parts[:3], ".") + ".*"
		}
		return parsed.String()
	}
	groups := strings.Split(parsed.String(), ":")
	if len(groups) >= 3 {
		return strings.Join(groups[:3], ":") + ":*"
	}
	return parsed.String()
}

// IPSegment 返回用于聚合的来源段（IPv4 前 3 段即 /24；IPv6 前 3 组）。非法输入返回空串。
func IPSegment(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		parts := strings.Split(parsed.String(), ".")
		if len(parts) == 4 {
			return strings.Join(parts[:3], ".")
		}
		return ""
	}
	groups := strings.Split(parsed.String(), ":")
	if len(groups) >= 3 {
		return strings.Join(groups[:3], ":")
	}
	return ""
}

// recordTLSNoise 记录一条噪音事件（来源段 + 时间），有界保留。
func recordTLSNoise(ip string, now time.Time) {
	seg := IPSegment(ip)
	if seg == "" {
		seg = "unknown"
	}
	noiseTracker.mu.Lock()
	defer noiseTracker.mu.Unlock()
	noiseTracker.events = append(noiseTracker.events, tlsEvent{at: now, seg: seg})
	if len(noiseTracker.events) > tlsNoiseMaxEvents {
		noiseTracker.events = noiseTracker.events[len(noiseTracker.events)-tlsNoiseMaxEvents:]
	}
}

// SegmentCount 是一个来源段的噪音计数。
type SegmentCount struct {
	Segment string `json:"segment"`
	Count   int    `json:"count"`
}

// TLSNoiseStats 返回当日 / 近 7 天被降级的 TLS 噪音次数，以及按次数降序的来源段 Top 列表。
func TLSNoiseStats() (today, week int, top []SegmentCount) {
	return tlsNoiseStatsAt(time.Now())
}

func tlsNoiseStatsAt(now time.Time) (today, week int, top []SegmentCount) {
	noiseTracker.mu.Lock()
	defer noiseTracker.mu.Unlock()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	weekStart := now.Add(-7 * 24 * time.Hour)
	segCount := map[string]int{}
	for _, e := range noiseTracker.events {
		if e.at.Before(weekStart) {
			continue
		}
		week++
		if !e.at.Before(dayStart) {
			today++
		}
		segCount[e.seg]++
	}
	top = make([]SegmentCount, 0, len(segCount))
	for seg, n := range segCount {
		top = append(top, SegmentCount{Segment: seg, Count: n})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].Segment < top[j].Segment
	})
	if len(top) > 10 {
		top = top[:10]
	}
	return today, week, top
}
