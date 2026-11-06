// Package applog 提供进程内分级日志与环形缓冲，供后台「运行日志」页面检索。
// 日志仍照常输出到 stderr（保留标准 log 行为），同时把最近若干条缓存到内存，
// 按 info/warn/error 分级并支持关键词检索。缓冲为内存态，进程重启后清空。
package applog

import (
	"log"
	"os"
	"strings"
	"sync"
)

// 日志级别，用于「报错单独展示」和级别筛选。
const (
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// 级别标记：applog.Errorf/Warnf/Infof 通过标准 log 输出这些前缀，
// 由环形缓冲写入器解析出级别并从消息中剥离，未迁移的 log.Printf 走启发式分类。
const (
	prefixInfo  = "[INFO] "
	prefixWarn  = "[WARN] "
	prefixError = "[ERROR] "
)

// maxEntries 限制内存中保留的日志条数，超出后丢弃最旧的。
const maxEntries = 3000

// Entry 是一条可在页面展示的日志记录。
type Entry struct {
	ID    int64  `json:"id"`
	Ts    string `json:"ts"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

type ring struct {
	mu      sync.Mutex
	entries []Entry
	nextID  int64
}

var global = &ring{nextID: 1}

// Init 把标准 log 的输出接管为「stderr + 内存环形缓冲」，应在 main 最早调用。
func Init() {
	log.SetFlags(log.LstdFlags)
	log.SetOutput(&teeWriter{stderr: os.Stderr})
}

// Infof/Warnf/Errorf 是分级日志入口，既写 stderr 也进入环形缓冲。
func Infof(format string, args ...interface{})  { log.Printf(prefixInfo+format, args...) }
func Warnf(format string, args ...interface{})  { log.Printf(prefixWarn+format, args...) }
func Errorf(format string, args ...interface{}) { log.Printf(prefixError+format, args...) }

// teeWriter 在写 stderr 的同时把整行解析入环形缓冲。
type teeWriter struct {
	stderr *os.File
}

func (w *teeWriter) Write(p []byte) (int, error) {
	global.appendLine(string(p))
	if w.stderr != nil {
		return w.stderr.Write(p)
	}
	return len(p), nil
}

// appendLine 解析标准 log 行（形如「2006/01/02 15:04:05 [LEVEL] msg」）并入库。
func (r *ring) appendLine(line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	ts, rest := splitTimestamp(line)
	level, msg := classify(rest)
	r.append(Entry{Ts: ts, Level: level, Msg: msg})
}

// splitTimestamp 剥离标准 log 的「YYYY/MM/DD HH:MM:SS 」时间前缀。
func splitTimestamp(line string) (ts, rest string) {
	if len(line) >= 20 && line[4] == '/' && line[7] == '/' && line[10] == ' ' &&
		line[13] == ':' && line[16] == ':' && line[19] == ' ' {
		return line[:19], line[20:]
	}
	return "", line
}

// classify 先按显式级别标记分类，未标记时按关键词启发式判断，保证旧调用点也能正确归入报错。
func classify(msg string) (level, text string) {
	switch {
	case strings.HasPrefix(msg, prefixError):
		return LevelError, msg[len(prefixError):]
	case strings.HasPrefix(msg, prefixWarn):
		return LevelWarn, msg[len(prefixWarn):]
	case strings.HasPrefix(msg, prefixInfo):
		return LevelInfo, msg[len(prefixInfo):]
	}
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "失败"), strings.Contains(msg, "错误"), strings.Contains(msg, "非法"),
		strings.Contains(lower, "error"), strings.Contains(lower, "panic"), strings.Contains(lower, "fatal"):
		return LevelError, msg
	case strings.Contains(msg, "告警"), strings.Contains(msg, "超时"), strings.Contains(msg, "异常"),
		strings.Contains(lower, "warn"):
		return LevelWarn, msg
	default:
		return LevelInfo, msg
	}
}

func (r *ring) append(e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.ID = r.nextID
	r.nextID++
	r.entries = append(r.entries, e)
	if len(r.entries) > maxEntries {
		r.entries = r.entries[len(r.entries)-maxEntries:]
	}
}

// Query 返回匹配级别与关键词的日志，按时间倒序（最新在前）。
// level 为空表示全部；afterID>0 时只返回 ID 大于该值的增量（用于实时追加）。
func Query(level, keyword string, afterID int64, limit int) []Entry {
	if limit <= 0 || limit > maxEntries {
		limit = 500
	}
	level = strings.TrimSpace(level)
	if level != "" && level != LevelInfo && level != LevelWarn && level != LevelError {
		level = ""
	}
	keyword = strings.ToLower(strings.TrimSpace(keyword))

	global.mu.Lock()
	defer global.mu.Unlock()
	out := make([]Entry, 0, limit)
	// 从最新往回扫描，命中即收集，直到达到 limit。
	for i := len(global.entries) - 1; i >= 0 && len(out) < limit; i-- {
		e := global.entries[i]
		if afterID > 0 && e.ID <= afterID {
			continue
		}
		if level != "" && e.Level != level {
			continue
		}
		if keyword != "" && !strings.Contains(strings.ToLower(e.Msg), keyword) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Counts 返回各级别当前缓存条数，供页面徽章展示。
func Counts() (info, warn, errCount int) {
	global.mu.Lock()
	defer global.mu.Unlock()
	for _, e := range global.entries {
		switch e.Level {
		case LevelError:
			errCount++
		case LevelWarn:
			warn++
		default:
			info++
		}
	}
	return
}

// NewServerErrorLogger 返回供 http.Server.ErrorLog 使用的日志器：
// 把「客户端原因」的 TLS 握手失败（不信任自签名证书、协议/密码套件不符、端口扫描半开连接等）
// 降为一条精简 info，避免公网暴露时 error 日志被刷满、污染「只看报错」；服务端真正的错误仍按 error 记录。
func NewServerErrorLogger() *log.Logger {
	return log.New(serverErrorWriter{}, "", 0)
}

type serverErrorWriter struct{}

func (serverErrorWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	if msg == "" {
		return len(p), nil
	}
	if IsClientTLSNoise(msg) {
		Infof("客户端 TLS 握手失败（通常为不信任自签名证书或端口扫描，非服务端故障）：%s", msg)
		return len(p), nil
	}
	Errorf("%s", msg)
	return len(p), nil
}

// IsClientTLSNoise 判断一条 http.Server 错误日志是否为「对端原因」导致的 TLS 握手失败（应降噪）。
// 这类错误的特征是 TLS alert 来自客户端（remote error），或为常见的不信任证书/协议不符/半开连接。
func IsClientTLSNoise(msg string) bool {
	if !strings.Contains(msg, "TLS handshake error") {
		return false
	}
	for _, sig := range []string{
		"remote error:", "unknown certificate", "bad certificate", "certificate unknown",
		"certificate expired", "handshake failure", "unsupported protocol", "protocol version",
		"no shared cipher", "no cipher", "insufficient security", "unrecognized_name",
		"access denied", "decode error", "illegal parameter", "EOF", "connection reset",
	} {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}
