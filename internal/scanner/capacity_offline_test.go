//go:build linux || darwin

package scanner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"easm-platform/internal/config"
	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

// 本文件是纯离线容量验证入口：fake naabu 只读取 argv 与 -list 目标文件，
// 不做 DNS、不建立任何 socket、从不回退真实 naabu；目标只是 RFC 5737 文档地址文本。
//
// 隔离与审计：
//   - PATH 是纯临时白名单目录（只含同名 naabu 绊线与 fake 需要的绝对路径系统工具），
//     初始化时用 exec.LookPath 证明 naabu 只能解析到绊线；
//   - -list / -o 的路径安全在调用时由受控 Go 路径哨兵（capacity_pathguard_unix_test.go）判定：
//     逐段规范化 + 逐段符号链接检查 + 临时根目录包含检查，全部在 exec 可写文件的脚本体之前完成；
//     绝不用 shell 通配判断路径安全（`data/scan_*` 的 `*` 能跨斜杠）；
//   - 测试侧还会逐条解析 argv 再审计一次（用与哨兵相同的规则），作为第二道防线；
//   - 链路运行期间用 peakSampler 周期采集 HeapAlloc/HeapSys/Sys/goroutines/FD 峰值，
//     以“相对基线 + 绝对上限”双约束断言峰值不随结果数线性增长（详见 capacity_sampler_unix_test.go）。
//
// 分层：
//   - 快速档：矩阵/暂停/Stop/三轮/参数白名单等小规模路径（scripts/capacity-gate.sh fast）；
//   - 容量档：50 万唯一结果的流式入库链路 + 资源峰值断言（TestFakeNaabu500kStreamingIntoSQLite）；
//   - 压力档：32,767,500 结果默认由容量预检安全拒绝（TestFakeNaabu32767500RejectedWithoutPartialWrite），
//     真正执行需显式 EASM_SCANNER_STRESS=1；
//   - 单命令入口见 scripts/capacity-gate.sh（fast/capacity/repeat/race，stress 需外部显式开启）。

const (
	// fakeInvocationLog 记录 fake naabu 每次调用的完整 argv（含 -version 自检）。
	fakeInvocationLog = "fake_invocations.log"
	// fakeUnexpectedLog 记录非预期动作；wrapper 记录后立即以 96 退出。
	fakeUnexpectedLog = "fake_unexpected_invocation.log"
	fakeBodyFile      = "fake-naabu-body.sh"
	fakeEntryFile     = "fake-naabu.sh"
	// tripwireLogFile 是 PATH 白名单中同名 naabu 绊线的日志文件名（与绊线可执行文件同目录）。
	tripwireLogFile = "naabu.log"
)

// fakeAllowedTools 是 fake 脚本体经 PATH 解析的系统工具白名单。
// 这些工具在 PATH 被替换前先解析成绝对路径，再以符号链接放进临时目录，
// 因此 fake 脚本既不依赖宿主 PATH，也不会意外调用到 PATH 中的其他（真实）工具。
var fakeAllowedTools = []string{"awk", "cat", "head", "sleep", "touch"}

// fakeNaabuWrapper 是所有 fake 脚本的统一入口：
//   - 先记录 argv（唯一可审计的调用凭据），再 exec 真实脚本体，二者 PID 相同；
//   - 在调用时立即执行“完整参数白名单”审核：未知 flag、缺值、重复参数、
//     非预期取值一律写入独立日志并以 96 退出，不会静默通过；
//   - -list/-o 的路径安全交给受控 Go 路径哨兵（capacity_pathguard_unix_test.go）：
//     逐段规范化 + 逐段符号链接检查 + 临时根目录包含检查，全部在 exec 脚本体之前完成，
//     因此任何重定向/文件创建都发生在检查通过之后；
//   - 绝不用 shell 通配判断路径是否安全：`data/scan_*` 里的 `*` 能跨斜杠，
//     会把 data/scan_99/../../../../batch_escape.out 误认为合法产物路径；
//   - 只允许两种形态：单独的 -version（工具自检），或首参为 -list 的受控扫描；
//   - 只用 shell 内建命令（printf/case/[/read/exec），不依赖 PATH，也不做解析/DNS/socket。
const fakeNaabuWrapper = `#!/bin/sh
printf '%s\n' "$*" >> ` + fakeInvocationLog + `
reject() {
  printf '%s\n' "$*" >> ` + fakeUnexpectedLog + `
  exit 96
}
is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  return 0
}
is_port_list() {
  case "$1" in
    ''|*[!0-9,-]*) return 1 ;;
  esac
  case "$1" in
    *[0-9]*) return 0 ;;
  esac
  return 1
}
# 词法拒绝：只判断“是否含有危险片段”，不做“路径是否合法”的通配匹配。
reject_unsafe_path() {
  case "$1" in
    '') reject "路径为空" ;;
    /*) reject "不允许绝对路径: $1" ;;
    *..*) reject "路径不允许包含 ..: $1" ;;
    *//*) reject "路径不允许出现空片段: $1" ;;
    */) reject "路径不允许以 / 结尾: $1" ;;
  esac
}
# 调用受控 Go 路径哨兵：成功输出规范化后的绝对路径，失败输出原因并返回 96。
# 哨兵是必需依赖：缺失或不可执行时直接拒绝，避免“路径检查被静默跳过”。
guard_path() {
  guard_bin="${` + fakePathGuardBinEnv + `:-}"
  [ -n "$guard_bin" ] || { printf '%s' "缺少 ` + fakePathGuardBinEnv + `"; return 96; }
  [ -x "$guard_bin" ] || { printf '%s' "路径哨兵不可执行: $guard_bin"; return 96; }
  guard_out=$("$guard_bin" "$1" "$2" 2>&1) || { printf '%s' "$guard_out"; return 96; }
  printf '%s' "$guard_out"
}
audit() {
  [ "$#" -ge 1 ] || reject "(空参数)"
  if [ "$#" -eq 1 ]; then
    [ "$1" = "-version" ] || reject "只允许单独的 -version: $1"
    return 0
  fi
  [ "$1" = "-list" ] || reject "首个参数必须是 -list: $1"
  [ -n "${2:-}" ] || reject "-list 缺值"
  reject_unsafe_path "$2"
  targets=$(guard_path -list "$2") || reject "路径哨兵拒绝 -list=$2: $targets"
  [ -f "$targets" ] || reject "目标文件不存在: $targets"
  shift 2
  saw_silent=''; saw_json=''; saw_out=''; saw_ports=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -silent) [ -z "$saw_silent" ] || reject "重复的 -silent"; saw_silent=1; shift ;;
      -json) [ -z "$saw_json" ] || reject "重复的 -json"; saw_json=1; shift ;;
      -verify) shift ;;
      -list) reject "重复的 -list" ;;
      -rate|-retries|-c|-top-ports|-timeout|-scan-type|-exclude-ports|-interface|-p|-o)
        [ "$#" -ge 2 ] || reject "$1 缺值"
        flag="$1"; value="$2"; shift 2
        case "$flag" in
          -rate|-retries|-c) is_uint "$value" || reject "$flag 取值非法: $value" ;;
          -top-ports)
            [ -z "$saw_ports" ] || reject "重复的端口参数"
            [ "$value" = "1000" ] || reject "$flag 仅允许受控值 1000: $value"
            saw_ports=1
            ;;
          -timeout)
            case "$value" in
              *[0-9]*) ;;
              *) reject "$flag 取值非法: $value" ;;
            esac
            ;;
          -scan-type)
            case "$value" in
              c|s) ;;
              *) reject "$flag 取值非法: $value" ;;
            esac
            ;;
          -exclude-ports) is_port_list "$value" || reject "$flag 取值非法: $value" ;;
          -interface)
            case "$value" in
              ''|*[!A-Za-z0-9._:-]*) reject "$flag 取值非法: $value" ;;
            esac
            ;;
          -p)
            [ -z "$saw_ports" ] || reject "重复的端口参数"
            if [ "$value" != "-" ]; then
              is_port_list "$value" || reject "$flag 取值非法: $value"
            fi
            saw_ports=1
            ;;
          -o)
            [ -z "$saw_out" ] || reject "重复的 -o"
            reject_unsafe_path "$value"
            out_path=$(guard_path -o "$value") || reject "路径哨兵拒绝 -o=$value: $out_path"
            saw_out=1
            ;;
        esac
        ;;
      *) reject "白名单之外的参数: $1" ;;
    esac
  done
  [ -n "$saw_silent" ] || reject "缺少 -silent"
  [ -n "$saw_json" ] || reject "缺少 -json"
  [ -n "$saw_out" ] || reject "缺少 -o"
  [ -n "$saw_ports" ] || reject "缺少 -p 或 -top-ports"
  while IFS= read -r target; do
    [ -z "$target" ] && continue
    case "$target" in
      192.0.2.*|198.51.100.*|203.0.113.*) ;;
      *) reject "目标不是 RFC 5737 文档地址: $target" ;;
    esac
  done < "$targets"
  return 0
}
audit "$@"
exec ./` + fakeBodyFile + ` "$@"
`

// capacityHarness 是完全隔离的离线执行环境：临时工作目录（含临时 SQLite）、临时 HOME、
// 纯临时 PATH 白名单（同名 naabu 绊线 + 受控系统工具），以及统一审计入口的 fake naabu 脚本。
type capacityHarness struct {
	dir     string
	home    string
	tripDir string
	runner  *Runner
	st      *store.Store
}

// newCapacityHarness 建立隔离 Runner。body 是 fake 的脚本体，只会被 wrapper exec 调用。
func newCapacityHarness(t *testing.T, body string, overrides map[string]string) *capacityHarness {
	t.Helper()
	dir := t.TempDir()
	home := t.TempDir()
	tripDir := t.TempDir()
	// 目标只是文本：切到临时目录、临时 HOME，SQLite 也只落在临时目录。
	t.Chdir(dir)
	t.Setenv("HOME", home)

	// PATH 改为纯临时白名单：目录里只有同名 naabu 绊线与 fake 脚本需要的系统工具。
	// 系统工具先在替换 PATH 之前解析成绝对路径，再以符号链接放入白名单目录，
	// 因此 fake 脚本不依赖宿主 PATH，真实 naabu 也不在可解析范围内。
	for _, name := range fakeAllowedTools {
		resolved, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("解析 fake 脚本依赖的系统工具 %s 失败: %v", name, err)
		}
		absolute, err := filepath.Abs(resolved)
		if err != nil {
			t.Fatalf("系统工具 %s 绝对路径解析失败: %v", name, err)
		}
		if err := os.Symlink(absolute, filepath.Join(tripDir, name)); err != nil {
			t.Fatalf("建立系统工具白名单链接 %s -> %s 失败: %v", name, absolute, err)
		}
	}
	// 白名单目录里的 naabu 永远是绊线：任何“回退真实 naabu”的路径都会先命中它、留下记录并失败。
	tripwire := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$0.log\"\nexit 97\n"
	if err := os.WriteFile(filepath.Join(tripDir, "naabu"), []byte(tripwire), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tripDir)
	// 证明白名单生效：naabu 只能解析到绊线，真实 naabu 已不可达。
	resolved, err := exec.LookPath("naabu")
	if err != nil || resolved != filepath.Join(tripDir, "naabu") {
		t.Fatalf("PATH 白名单未生效：naabu 解析为 %q（err=%v），期望 %q", resolved, err, filepath.Join(tripDir, "naabu"))
	}

	// 路径哨兵：wrapper 调用的受控 Go 代码（复用当前测试二进制），负责把 -list/-o 规范化
	// 并证明仍在临时根目录内。环境变量在这里导出，wrapper 缺它就直接拒绝，
	// 说明它不是“可选的、只靠 Go 事后审计”的检查。
	guardBin, err := os.Executable()
	if err != nil {
		t.Fatalf("解析测试二进制路径（路径哨兵）失败: %v", err)
	}
	t.Setenv(fakePathGuardBinEnv, guardBin)
	t.Setenv(fakePathGuardRootEnv, dir)
	t.Setenv(fakePathGuardEnv, "1")

	if err := os.WriteFile(fakeBodyFile, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeEntryFile, []byte(fakeNaabuWrapper), 0o755); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open("test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	settings := map[string]string{
		"naabu_path":       "./" + fakeEntryFile,
		"naabu_rate":       "1000000",
		"naabu_total_rate": "16000000",
		"naabu_retries":    "0",
		"naabu_workers":    "25",
		"naabu_timeout":    "1s",
		"scan_timeout_min": "1440",
		"naabu_scan_type":  "c",
		"naabu_verify":     "0",
		"resource_monitor": "0",
		"scan_concurrency": "3",
	}
	for key, value := range overrides {
		settings[key] = value
	}
	if err := st.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{NaabuPath: "naabu", NaabuRate: "1000", RealertDays: 7}
	runner := New(st, cfg, engine.New(st, cfg))
	t.Cleanup(runner.Shutdown)
	// 容量预检的 FD/磁盘探测固定注入，避免个别机器 ulimit/磁盘差异改变结论。
	withCapacityEnv(t, 1<<20, 64, 8<<30)
	return &capacityHarness{dir: dir, home: home, tripDir: tripDir, runner: runner, st: st}
}

// invocations 返回 fake naabu 收到的全部 argv 行。
func (h *capacityHarness) invocations(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(fakeInvocationLog)
	if err != nil {
		t.Fatalf("fake naabu 未被调用（缺少 %s）: %v", fakeInvocationLog, err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		t.Fatal("fake naabu 的调用记录为空")
	}
	return strings.Split(trimmed, "\n")
}

// argvValueFlags 是经核实的 naabu 取值参数白名单，与 NaabuSettings.args 一一对应。
var argvValueFlags = map[string]bool{
	"-list": true, "-rate": true, "-retries": true, "-c": true, "-timeout": true,
	"-scan-type": true, "-o": true, "-p": true, "-top-ports": true,
	"-exclude-ports": true, "-interface": true,
}

// argvBoolFlags 是不带取值的开关参数。
var argvBoolFlags = map[string]bool{"-silent": true, "-json": true, "-verify": true}

// fakeInvocation 是一条按白名单解析通过的 argv。
type fakeInvocation struct {
	version bool
	flags   map[string]string
}

// parseInvocation 按白名单解析 fake naabu 的 argv：未知 flag、缺值、重复参数立即失败。
func (h *capacityHarness) parseInvocation(t *testing.T, line string) fakeInvocation {
	t.Helper()
	fields := strings.Fields(line)
	if len(fields) == 0 {
		t.Fatalf("fake naabu 收到空 argv")
	}
	if len(fields) == 1 && fields[0] == "-version" {
		return fakeInvocation{version: true}
	}
	if fields[0] == "-version" {
		t.Fatalf("-version 必须是唯一参数: %q", line)
	}
	parsed := fakeInvocation{flags: make(map[string]string, len(fields)/2)}
	for i := 0; i < len(fields); {
		token := fields[i]
		if argvBoolFlags[token] {
			if _, duplicated := parsed.flags[token]; duplicated {
				t.Fatalf("%s 重复出现: %q", token, line)
			}
			parsed.flags[token] = ""
			i++
			continue
		}
		if !argvValueFlags[token] {
			t.Fatalf("fake naabu 收到白名单之外的参数 %q: %q", token, line)
		}
		if i+1 >= len(fields) {
			t.Fatalf("%s 缺值: %q", token, line)
		}
		if _, duplicated := parsed.flags[token]; duplicated {
			t.Fatalf("%s 重复出现: %q", token, line)
		}
		parsed.flags[token] = fields[i+1]
		i += 2
	}
	return parsed
}

// assertScanArgv 校验扫描调用必须携带的受控参数与取值。
func (h *capacityHarness) assertScanArgv(t *testing.T, parsed fakeInvocation, line string) {
	t.Helper()
	for _, required := range []string{"-list", "-rate", "-retries", "-c", "-timeout", "-scan-type", "-o", "-silent", "-json"} {
		if _, ok := parsed.flags[required]; !ok {
			t.Fatalf("扫描调用缺少必需参数 %s: %q", required, line)
		}
	}
	_, hasPorts := parsed.flags["-p"]
	_, hasTop := parsed.flags["-top-ports"]
	if hasPorts == hasTop {
		t.Fatalf("扫描调用必须且只能指定 -p 或 -top-ports 之一: %q", line)
	}
	if hasTop && parsed.flags["-top-ports"] != "1000" {
		t.Fatalf("-top-ports 只允许受控值 1000，实际 %q: %q", parsed.flags["-top-ports"], line)
	}
	if value, ok := parsed.flags["-p"]; ok && value != "-" && !validPortSpec(value) {
		t.Fatalf("-p 取值非法 %q: %q", value, line)
	}
	if value, ok := parsed.flags["-exclude-ports"]; ok && !validPortSpec(value) {
		t.Fatalf("-exclude-ports 取值非法 %q: %q", value, line)
	}
	if value := parsed.flags["-scan-type"]; value != "c" && value != "s" {
		t.Fatalf("-scan-type 只允许 c 或 s，实际 %q: %q", value, line)
	}
	if value := parsed.flags["-timeout"]; func() bool {
		duration, err := time.ParseDuration(value)
		return err != nil || duration <= 0 || duration > 10*time.Minute
	}() {
		t.Fatalf("-timeout 取值非法 %q: %q", parsed.flags["-timeout"], line)
	}
	for _, key := range []string{"-rate", "-retries", "-c"} {
		if value, err := strconv.Atoi(parsed.flags[key]); err != nil || value < 0 {
			t.Fatalf("%s 取值非法 %q: %q", key, parsed.flags[key], line)
		}
	}
	if value, ok := parsed.flags["-interface"]; ok && !validInterfaceName(value) {
		t.Fatalf("-interface 取值非法 %q: %q", value, line)
	}
	h.assertTempArtifact(t, line, "-list", parsed.flags["-list"], "_targets.txt")
	h.assertTempArtifact(t, line, "-o", parsed.flags["-o"], ".out")
	// 目标文件仍在时再做一次终检：目标必须是 RFC 5737 文档地址（wrapper 已在调用时拦截）。
	if targets, err := os.ReadFile(filepath.Join(h.dir, parsed.flags["-list"])); err == nil {
		for _, target := range strings.Split(strings.TrimSpace(string(targets)), "\n") {
			if target == "" {
				continue
			}
			if !isDocAddress(target) {
				t.Fatalf("目标文件出现非文档地址文本 %q（%q）", target, line)
			}
		}
	}
}

// assertTempArtifact 是路径安全的第二道防线：用与路径哨兵完全相同的规则（逐段规范化 +
// 符号链接检查 + 临时根目录包含检查）复核实际传参，确保“事后 Go 审计”不是唯一防线。
func (h *capacityHarness) assertTempArtifact(t *testing.T, line, flag, value, suffix string) {
	t.Helper()
	resolved, err := resolveFakeArtifact(h.dir, flag, value)
	if err != nil {
		t.Fatalf("Go 侧二次审计拒绝 %s=%q（argv %q）: %v", flag, value, line, err)
	}
	if !strings.HasSuffix(resolved, suffix) {
		t.Fatalf("%s 规范化后为 %q，不以 %q 结尾（argv %q）", flag, resolved, suffix, line)
	}
}

// validPortSpec 判断端口表达式是否只由数字、逗号与连字符构成（且至少包含一个数字）。
func validPortSpec(value string) bool {
	if value == "" {
		return false
	}
	hasDigit := false
	for _, char := range value {
		switch {
		case char >= '0' && char <= '9':
			hasDigit = true
		case char == ',' || char == '-':
		default:
			return false
		}
	}
	return hasDigit
}

// validInterfaceName 判断网卡名是否只包含常规字符（不允许路径分隔符/空白/换行）。
func validInterfaceName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		case char == '.' || char == '_' || char == ':' || char == '-':
		default:
			return false
		}
	}
	return true
}

// assertOfflineOnly 证明整轮执行只经过 fake 工具，且所有参数都在白名单内：
//   - 真实 naabu 绊线没有被触发；
//   - fake 没有收到非预期动作（wrapper 会立即失败并记录）；
//   - 每条 argv 都是“单独的 -version”或携带完整受控参数的 -list 扫描；
//   - 未知 flag、缺值、重复参数、越界/符号链接路径、非文档目标都会立即失败；
//   - 路径参数的二次审计复用 resolveFakeArtifact（与哨兵同一套规则）；
//   - allowScan=false 时不允许出现任何扫描调用（容量拒绝必须发生在启动进程之前）。
func (h *capacityHarness) assertOfflineOnly(t *testing.T, allowScan bool) {
	t.Helper()
	if data, err := os.ReadFile(filepath.Join(h.tripDir, tripwireLogFile)); err == nil {
		t.Fatalf("检测到对真实 naabu 的回退调用（argv=%q），测试必须零公网/零真实工具", string(data))
	}
	if data, err := os.ReadFile(fakeUnexpectedLog); err == nil {
		t.Fatalf("fake naabu 收到非预期动作并已立即失败（argv=%q）", string(data))
	}
	sawScan := false
	for _, line := range h.invocations(t) {
		parsed := h.parseInvocation(t, line)
		if parsed.version {
			continue
		}
		sawScan = true
		h.assertScanArgv(t, parsed, line)
	}
	if !allowScan && sawScan {
		t.Fatal("容量预检应拒绝启动，但仍启动了 naabu 扫描进程")
	}
}

// runFakeExpectReject 执行一次 wrapper 调用并断言它以 96 拒绝，且最后一条拒绝记录包含 wantReason。
func runFakeExpectReject(t *testing.T, args []string, wantReason string) {
	t.Helper()
	err := exec.Command("./"+fakeEntryFile, args...).Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 96 {
		t.Fatalf("非预期参数应立即以 96 失败，实际 err=%v", err)
	}
	logged := readTestFile(t, fakeUnexpectedLog)
	lines := strings.Split(strings.TrimSpace(logged), "\n")
	last := lines[len(lines)-1]
	if !strings.Contains(last, wantReason) {
		t.Fatalf("拒绝原因应包含 %q，实际最后一条记录：%q", wantReason, last)
	}
}

// TestFakeNaabuArgvWhitelistRejectsUnexpectedArgs 是完整参数白名单的负向对照：
// 合法扫描形态可以通过，而未知 flag、缺值、绝对路径、非文档目标、未受控取值
// 都必须在调用时立即失败（退出码 96）并留下可审计原因，证明白名单不是空断言。
func TestFakeNaabuArgvWhitelistRejectsUnexpectedArgs(t *testing.T) {
	h := newCapacityHarness(t, stream500kScript, nil)
	t.Setenv("FAKE_PORTS", "1")
	if err := os.MkdirAll(filepath.Join("data", "scan_99"), 0o755); err != nil {
		t.Fatal(err)
	}
	targets := filepath.Join("data", "scan_99", "batch_0001_targets.txt")
	if err := os.WriteFile(targets, []byte("192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join("data", "scan_99", "batch_0001.out")
	valid := []string{
		"-list", targets, "-rate", "1000", "-retries", "0", "-c", "5", "-timeout", "1s",
		"-scan-type", "c", "-silent", "-json", "-o", out, "-top-ports", "1000",
	}
	withArgs := func(extra ...string) []string {
		args := make([]string, 0, len(valid)+len(extra))
		args = append(args, valid...)
		return append(args, extra...)
	}

	// 合法形态必须通过（真正执行脚本体，单个目标 × 单个端口）。
	if output, err := exec.Command("./"+fakeEntryFile, valid...).CombinedOutput(); err != nil {
		t.Fatalf("合法参数不应被拒绝: %v\n%s", err, output)
	}

	badTargets := filepath.Join("data", "scan_99", "batch_0002_targets.txt")
	if err := os.WriteFile(badTargets, []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	absoluteTargets := filepath.Join(h.dir, targets)
	withTargets := func(path string) []string {
		args := make([]string, len(valid))
		copy(args, valid)
		args[1] = path
		return args
	}

	cases := []struct {
		name   string
		args   []string
		reason string
	}{
		{name: "未知 flag", args: withArgs("-top-hosts", "5"), reason: "白名单之外"},
		{name: "缺值", args: []string{"-list", targets, "-rate"}, reason: "缺值"},
		{name: "绝对路径目标", args: []string{"-list", "/etc/hosts"}, reason: "不允许绝对路径"},
		{name: "绝对路径越出临时根", args: withTargets(absoluteTargets), reason: "不允许绝对路径"},
		{name: "非预期目标", args: withTargets(badTargets), reason: "RFC 5737"},
		{name: "缺少端口参数", args: valid[:len(valid)-2], reason: "缺少"},
		{name: "重复参数", args: withArgs("-json"), reason: "重复"},
		{name: "绝对路径输出", args: []string{"-list", targets, "-silent", "-json", "-o", "/tmp/x.out", "-top-ports", "1000"}, reason: "不允许绝对路径"},
		{name: "未受控的取值", args: []string{"-list", targets, "-silent", "-json", "-o", out, "-top-ports", "10"}, reason: "受控值"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runFakeExpectReject(t, tc.args, tc.reason)
		})
	}
}

// TestFakeNaabuWrapperRejectsPathEscapes 是路径安全的负向对照：越界相对路径（含 ..）、
// 符号链接逃逸、绝对越界路径、重复路径参数、上级目录不存在都必须在任何重定向/文件创建
// 之前被拒绝（96），且临时根目录之外不会产生任何文件。
//
// 该用例直接复现旧实现的缺陷：shell 的 `data/scan_*/batch_*.out` 通配里 `*` 可以跨斜杠，
// 因此 data/scan_99/../../../../batch_escape.out 会被误判为合法产物路径。
func TestFakeNaabuWrapperRejectsPathEscapes(t *testing.T) {
	h := newCapacityHarness(t, stream500kScript, nil)
	t.Setenv("FAKE_PORTS", "1")
	scanDir := filepath.Join("data", "scan_99")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	targets := filepath.Join(scanDir, "batch_0001_targets.txt")
	if err := os.WriteFile(targets, []byte("192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(scanDir, "batch_0001.out")
	base := []string{
		"-list", targets, "-rate", "1000", "-retries", "0", "-c", "5", "-timeout", "1s",
		"-scan-type", "c", "-silent", "-json", "-o", out, "-top-ports", "1000",
	}
	withList := func(path string) []string {
		args := append([]string(nil), base...)
		args[1] = path
		return args
	}
	withOut := func(path string) []string {
		args := append([]string(nil), base...)
		args[len(args)-3] = path // -o 的取值位置
		return args
	}

	outside := t.TempDir()
	// 越界相对路径的真实落点必须在临时根之外，否则这个用例毫无意义。
	escapeRel := "data/scan_99/../../../../batch_escape.out"
	escapedAbs := filepath.Clean(filepath.Join(h.dir, escapeRel))
	if withinRoot(h.dir, escapedAbs) {
		t.Fatalf("用例构造错误：%q 解析为 %q，仍在临时根 %q 内", escapeRel, escapedAbs, h.dir)
	}
	// 符号链接逃逸：data/scan_77 指向临时根之外的目录，且根外放有内容合法的目标文件，
	// 证明“内容合法”不能取代路径包含检查。
	if err := os.Symlink(outside, filepath.Join("data", "scan_77")); err != nil {
		t.Fatal(err)
	}
	outsideTargets := filepath.Join(outside, "batch_0001_targets.txt")
	if err := os.WriteFile(outsideTargets, []byte("192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlinkOut := filepath.Join(outside, "batch_0009.out")

	cases := []struct {
		name   string
		args   []string
		reason string
		absent string
	}{
		{name: "相对路径越界", args: withOut(escapeRel), reason: "..", absent: escapedAbs},
		{name: "相对目标路径越界", args: withList("data/scan_99/../../../../etc/hosts"), reason: ".."},
		{name: "符号链接输出逃逸", args: withOut("data/scan_77/batch_0009.out"), reason: "符号链接", absent: symlinkOut},
		{name: "符号链接目标逃逸", args: withList("data/scan_77/batch_0001_targets.txt"), reason: "符号链接"},
		{name: "绝对输出路径越界", args: withOut(filepath.Join(outside, "abs_escape.out")), reason: "不允许绝对路径", absent: filepath.Join(outside, "abs_escape.out")},
		{name: "重复输出路径参数", args: append(withOut(out), "-o", filepath.Join(scanDir, "batch_0002.out")), reason: "重复的 -o", absent: filepath.Join(scanDir, "batch_0002.out")},
		{name: "上级目录不存在", args: withOut(filepath.Join("data", "scan_55", "batch_0001.out")), reason: "上级目录不存在", absent: filepath.Join("data", "scan_55", "batch_0001.out")},
		{name: "路径形态不受控", args: withOut(filepath.Join(scanDir, "escape.out")), reason: "形态不受控", absent: filepath.Join(scanDir, "escape.out")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runFakeExpectReject(t, tc.args, tc.reason)
			if tc.absent == "" {
				return
			}
			if _, err := os.Stat(tc.absent); !os.IsNotExist(err) {
				t.Fatalf("拒绝后仍产生了文件 %q（err=%v），路径检查必须发生在任何重定向/创建之前", tc.absent, err)
			}
		})
	}

	// 临时根之外只允许存在本用例自己写入的那一个目标文件，不得出现任何 .out 产物。
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != filepath.Base(outsideTargets) {
			t.Fatalf("临时根之外出现了非法文件: %q", filepath.Join(outside, entry.Name()))
		}
	}

	// 哨兵是必需依赖：缺失时必须拒绝，而不是退化成“没人做路径检查”。
	t.Run("路径哨兵缺失必须拒绝", func(t *testing.T) {
		t.Setenv(fakePathGuardBinEnv, filepath.Join(t.TempDir(), "missing-guard"))
		runFakeExpectReject(t, base, "路径哨兵")
	})
}

// stream500kScript：为 -list 中的每个目标输出 port 1000 起的 FAKE_PORTS 个端口（默认 1000），
// 500 个目标 × 1000 端口 ≈ 50 万条唯一结果。只写 stdout，-o 文件保持为空，
// 避免同一批 50 万行再被文件补读路径读一遍（文件补读由小规模用例覆盖）。
//
// 用 exec 让 awk 顶替 shell 成为唯一进程：fake 与真实 naabu 一样只有单个进程持有
// stdout，不会制造“主进程退出但子进程仍占管道”的伪信号。
//
// 每目标端口数由 FAKE_PORTS 控制：race 档用它把单批行数压到消费者能在
// stdoutDrainGrace 内排空的量级（详见 capacityProfile）。
const stream500kScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu fake v1'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -list) list="$2"; shift 2;;
    *) shift;;
  esac
done
: > "$out"
exec awk -v ports="${FAKE_PORTS:-1000}" '{ for (i=0;i<ports;i++) printf "{\"host\":\"%s\",\"ip\":\"%s\",\"port\":%d,\"protocol\":\"tcp\"}\n", $0, $0, 1000 + i }' "$list"
`

const (
	capacityTargets = 500
	capacityPorts   = 1000
	capacityResults = capacityTargets * capacityPorts // 500000
	capacityBatch   = 20                              // 每批目标数（scan_concurrency 无关）
)

// capacityProfile 返回当前档位的（目标数, 每目标端口数）：常规构建为 500×1000=50 万条，
// race 构建降为 20×200=4000 条。降档只针对 -race 插桩造成的两类假故障：
//
//  1. 并发写事务变慢后偶发超过 store 的 busy_timeout(5s)，报 SQLITE_BUSY；
//  2. 消费者解析/写库变慢后，naabu 退出时的 stdout 排空可能超过 stdoutDrainGrace(3s)，
//     被误判为“实时输出截断”。压缩单批行数即可让消费者在宽限期内排空。
//
// 竞态检查关心的是并发正确性而不是规模：50 万行与全部断言由容量档（无 race）保证。
func capacityProfile() (targets, ports int) {
	if raceDetectorEnabled {
		return 20, 200
	}
	return capacityTargets, capacityPorts
}

// capacityDeadline 放宽时间上界：race 构建下的耗时不能与常规构建共用同一阀值。
func capacityDeadline(d time.Duration) time.Duration {
	if raceDetectorEnabled {
		return d * 6
	}
	return d
}

// TestFakeNaabu500kStreamingIntoSQLite 验证 50 万条唯一结果经 scanner 流式链路
// 写入临时 SQLite：
//   - 唯一行数 = 500000，且 (ip,port) 在全量分页读取后无重复；
//   - 分块写入：每次刷库提交 ≤ dbFlushRows 行、内部单事务（chunks=1），刷库次数 ≥ 2500；
//   - 终态 done、异常目标 0、开放端口与结果行计数一致；
//   - 链路运行期间周期采样 HeapAlloc/HeapSys/Sys/goroutines/FD 峰值，
//     在“相对基线 + 绝对上限”双约束下断言峰值不随结果数线性增长（流式而非全量收集）；
//   - 记录耗时与运行期资源指标（日志不逐行、不爆量）。
//
// 该用例属于容量档：-short 跳过，显式运行方式见 scripts/capacity-gate.sh capacity。
func TestFakeNaabu500kStreamingIntoSQLite(t *testing.T) {
	if testing.Short() {
		t.Skip("50 万结果链路属于容量档，-short 跳过；显式运行：go test ./internal/scanner -run TestFakeNaabu500kStreamingIntoSQLite -count=1 -v")
	}
	// race 档降档：同一条流式链路、同样的断言，只是规模缩小（详见 capacityProfile）。
	targets, ports := capacityProfile()
	results := targets * ports
	batches := targets / capacityBatch
	// fake 的每目标端口数由 FAKE_PORTS 控制，与断言的规模保持一致。
	t.Setenv("FAKE_PORTS", strconv.Itoa(ports))
	h := newCapacityHarness(t, stream500kScript, map[string]string{"scan_concurrency": "3"})

	// 观察批量写库的分块规模：hook 仅在测试注册时生效，生产为 nil。
	var mu sync.Mutex
	flushes := make([]store.ResultInsertStats, 0, results/dbFlushRows)
	previous := resultFlushHook
	resultFlushHook = func(stats store.ResultInsertStats) {
		mu.Lock()
		flushes = append(flushes, stats)
		mu.Unlock()
	}
	t.Cleanup(func() { resultFlushHook = previous })

	taskID := newManualTask(t, h.st, "top", docIPv4(targets))
	// 基线在启动前、GC 之后的稳态点采集；采样器只读运行时数据、绝不触发 GC。
	baseline := snapshotRuntime(t)
	t.Logf("基线（启动前）：%s；临时库 %s", baseline.String(), humanBytes(tempDBSize(t)))
	started := time.Now()
	scanID, err := h.runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("%d 目标 × %d 端口（%d 条结果）应通过容量预检: %v", targets, ports, results, err)
	}
	// 采样器覆盖整条 fake naabu → 解析 → 分块入库链路；t.Cleanup 兼底保证任何失败路径都能停下。
	sampler := startPeakSampler(resourceSampleInterval)
	t.Cleanup(func() { sampler.stop() })
	waitForScanStatusWithin(t, h.st, scanID, "done", capacityDeadline(240*time.Second))
	waitForRunnerIdleWithin(t, h.runner, 60*time.Second)
	elapsed := time.Since(started)
	// 先停采样器再做题验用的全量分页读取：避免测试自身的大切片污染峰值。
	// 最少样本数按实际耗时推导，确保“峰值”真的来自运行期采样而不是启动瞬间的读数。
	peaks := measurePeaks(t, fmt.Sprintf("%d 条结果链路", results), sampler, baseline, minSamplesFor(elapsed))
	assertStreamingWithoutFullSlice(t, results, peaks)

	scan, err := h.st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
	}
	if scan.Status != "done" || scan.FailedTargets != 0 {
		t.Fatalf("终态=%q 异常目标=%d，期望 done/0: %+v", scan.Status, scan.FailedTargets, scan)
	}
	if scan.TargetCount != targets || scan.ProcessedTargets != targets {
		t.Fatalf("目标数=%d 已处理=%d，期望均为 %d", scan.TargetCount, scan.ProcessedTargets, targets)
	}
	if scan.TotalBatches != batches || scan.CurrentBatch != batches {
		t.Fatalf("批次数=%d 已完成=%d，期望 %d（%d/%d）", scan.TotalBatches, scan.CurrentBatch, batches, targets, capacityBatch)
	}
	if scan.OpenPorts != results || scan.ResultCount != results {
		t.Fatalf("开放端口=%d 结果行=%d，期望均为 %d", scan.OpenPorts, scan.ResultCount, results)
	}
	stored, err := h.st.CountResultsByScan(scanID)
	if err != nil || stored != results {
		t.Fatalf("库内结果行数=%d err=%v，期望 %d", stored, err, results)
	}

	// 全量分页读取后按 (ipv4,port) 校验唯一性：只保留 8 字节键切片，内存有界。
	keys := make([]uint64, 0, results)
	cursor := int64(0)
	pages := 0
	for {
		page, err := h.st.ResultsPage(scanID, cursor, store.ResultPageMaxLimit)
		if err != nil {
			t.Fatalf("分页读取结果失败: %v", err)
		}
		pages++
		for _, result := range page.Results {
			keys = append(keys, resultKeyValue(t, result))
		}
		cursor = page.NextCursor
		if !page.HasMore {
			break
		}
	}
	if len(keys) != results {
		t.Fatalf("分页读取到 %d 行，期望 %d", len(keys), results)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for i := 1; i < len(keys); i++ {
		if keys[i] == keys[i-1] {
			t.Fatalf("结果存在重复键: %d 与 %d", keys[i-1], keys[i])
		}
	}
	if len(keys) != results {
		t.Fatalf("唯一键数=%d，期望 %d", len(keys), results)
	}

	// 分块写入：固定批量刷库，单次提交不超过 dbFlushRows，内部只开 1 个事务。
	mu.Lock()
	inserted, maxSubmitted, chunksPerCall := 0, 0, 0
	for _, stats := range flushes {
		inserted += stats.Inserted
		if stats.Submitted > maxSubmitted {
			maxSubmitted = stats.Submitted
		}
		if stats.Chunks > chunksPerCall {
			chunksPerCall = stats.Chunks
		}
	}
	flushCalls := len(flushes)
	mu.Unlock()
	if inserted != results {
		t.Fatalf("分块刷库累计新增=%d，期望 %d", inserted, results)
	}
	if maxSubmitted > dbFlushRows {
		t.Fatalf("单次刷库提交 %d 行，超过固定批量上限 %d（写入不再分块）", maxSubmitted, dbFlushRows)
	}
	if chunksPerCall != 1 {
		t.Fatalf("单次刷库内部事务数=%d，期望 1（每批 ≤ %d 行 < 分块阈值 %d）", chunksPerCall, dbFlushRows, store.ResultInsertChunkSize)
	}
	if flushCalls < results/dbFlushRows {
		t.Fatalf("刷库次数=%d，少于 %d（未按固定批量分块写入）", flushCalls, results/dbFlushRows)
	}

	// 目标文件只包含 RFC 5737 文档地址文本，证明“目标只是文本”。
	targetFiles, err := filepath.Glob(filepath.Join("data", fmt.Sprintf("scan_%d", scanID), "batch_*_targets.txt"))
	if err != nil || len(targetFiles) != batches {
		t.Fatalf("批次目标文件数=%d err=%v，期望 %d", len(targetFiles), err, batches)
	}
	for _, path := range targetFiles {
		for _, line := range strings.Split(strings.TrimSpace(readTestFile(t, path)), "\n") {
			if !isDocAddress(line) {
				t.Fatalf("目标文件出现非文档地址文本: %q", line)
			}
		}
	}

	snapshot := snapshotRuntime(t)
	t.Logf("%d 条结果链路（%d 目标 × %d 端口，race 构建=%v）：耗时 %s，分页读取 %d 页，刷库 %d 次（单次最多 %d 行），子进程 %d 次；%s；临时库 %s",
		results, targets, ports, raceDetectorEnabled, elapsed.Round(time.Millisecond), pages, flushCalls, maxSubmitted,
		len(h.invocations(t))-1, snapshot.String(), humanBytes(tempDBSize(t)))
	if limit := capacityDeadline(4 * time.Minute); elapsed > limit {
		t.Fatalf("%d 条结果链路耗时 %s，超过 %s 上界（流式链路可能出现退化为全量加载/逐行事务）", results, elapsed, limit)
	}
	h.assertOfflineOnly(t, true)
}

// resultKeyValue 把 (ipv4, port) 压缩为 48 位整数键：ipv4 左移 16 位后按位或端口。
func resultKeyValue(t *testing.T, result store.Result) uint64 {
	t.Helper()
	parsed := net.ParseIP(result.IP)
	if parsed == nil || parsed.To4() == nil {
		t.Fatalf("结果 IP 不是合法 IPv4: %q", result.IP)
	}
	v4 := parsed.To4()
	value := uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3])
	return value<<16 | uint64(result.Port)
}

// isDocAddress 判断文本是否为 RFC 5737 文档保留地址，用于证明测试目标不指向任何真实主机。
func isDocAddress(value string) bool {
	for _, prefix := range []string{"192.0.2.", "198.51.100.", "203.0.113."} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// TestFakeNaabu32767500RejectedWithoutPartialWrite 是 32,767,500 结果（500 目标 × 65535 端口）
// 压力档的默认安全验证：不得真的执行，必须由容量保护阈值明确拒绝，且零部分写入。
func TestFakeNaabu32767500RejectedWithoutPartialWrite(t *testing.T) {
	// 生产默认预算：单进程 2000/s、总速率 6000/s、并发 3、重试 2、任务超时 60 分钟。
	// 500 × 65535 × 3 次尝试约 9800 万探测，按 6000/s 需要数小时，必然被容量预检拒绝。
	// 禁用自动拆分功能，以验证容量预检的拒绝逻辑。
	h := newCapacityHarness(t, matrixScript, map[string]string{
		"naabu_rate":            "2000",
		"naabu_total_rate":      "6000",
		"naabu_retries":         "2",
		"scan_timeout_min":      "60",
		"scan_concurrency":      "3",
		"auto_split_on_timeout": "0", // 禁用自动拆分，测试容量拒绝
	})
	taskID := newManualTask(t, h.st, "full", docIPv4(capacityTargets))

	started := time.Now()
	scanID, rejectErr := h.runner.StartTask(taskID)
	elapsed := time.Since(started)
	if rejectErr == nil {
		t.Fatalf("32,767,500 结果规模在默认预算下不应通过容量预检，实际已启动 scan=%d", scanID)
	}
	for _, marker := range []string{"容量预检未通过", "超过任务超时", "分钟", "总速率"} {
		if !strings.Contains(rejectErr.Error(), marker) {
			t.Fatalf("拒绝原因缺少可操作提示 %q: %v", marker, rejectErr)
		}
	}
	if h.runner.IsRunning() {
		t.Fatal("容量拒绝后运行锁未释放")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("容量拒绝耗时 %s，超过 10 秒（预检阻塞会拖住运行锁）", elapsed)
	}

	scan, err := h.st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("拒绝时仍应留下失败详情记录: %+v err=%v", scan, err)
	}
	if scan.Status != "failed" {
		t.Fatalf("拒绝后执行状态=%q，期望 failed: %+v", scan.Status, scan)
	}
	// 零部分写入：库内无任何结果行，也没有任何批次产物（data/scan_*/batch_*）。
	if count, err := h.st.CountResultsByScan(scanID); err != nil || count != 0 {
		t.Fatalf("容量拒绝后库内结果行数=%d err=%v，期望 0（零部分写入）", count, err)
	}
	artifacts, err := filepath.Glob(filepath.Join("data", "scan_*", "batch_*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("容量拒绝后仍生成批次产物: %v", artifacts)
	}
	// 只允许发生 -version 自检，绝不允许启动扫描进程。
	h.assertOfflineOnly(t, false)

	// 健康轮：拒绝不得损坏 Runner，小任务仍可正常完成。
	healthyID := newManualTask(t, h.st, "top", []string{"192.0.2.31", "192.0.2.32"})
	healthyScan, err := h.runner.StartTask(healthyID)
	if err != nil {
		t.Fatalf("容量拒绝后无法启动小任务: %v", err)
	}
	waitForScanStatusWithin(t, h.st, healthyScan, "done", 60*time.Second)
	waitForRunnerIdleWithin(t, h.runner, 30*time.Second)
	t.Logf("32,767,500 结果压力档：默认拒绝耗时 %s，拒绝原因=%v", elapsed.Round(time.Millisecond), rejectErr)
}

// fullPortStreamScript：为每个目标流式输出 1-65535 全部端口（32,767,500 条唯一结果），
// 只在显式开启压力档时使用。
const fullPortStreamScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu fake v1'; exit 0; fi
out=''; list=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    -list) list="$2"; shift 2;;
    *) shift;;
  esac
done
: > "$out"
exec awk '{ for (p=1;p<=65535;p++) printf "{\"host\":\"%s\",\"ip\":\"%s\",\"port\":%d,\"protocol\":\"tcp\"}\n", $0, $0, p }' "$list"
`

// pressureResults 是 500 目标 × 65535 端口的完整结果规模。
const pressureResults = capacityTargets * 65535

// TestFakeNaabuPressure32767500Explicit 是显式开启的专用压力档：
// 真正把 32,767,500 条结果流式写入临时 SQLite。默认（EASM_SCANNER_STRESS != 1）直接跳过，
// 保证常规测试绝不耗尽本机资源；磁盘余量不足 8 GiB 时同样跳过。
//
// 显式运行（约数分钟、需要 ≥ 8 GiB 空闲磁盘）：
//
//	EASM_SCANNER_STRESS=1 go test ./internal/scanner -run TestFakeNaabuPressure32767500Explicit -count=1 -v -timeout 3h
func TestFakeNaabuPressure32767500Explicit(t *testing.T) {
	if os.Getenv("EASM_SCANNER_STRESS") != "1" {
		t.Skip("32,767,500 结果压力档默认不执行（防止耗尽本机资源）；显式开启：EASM_SCANNER_STRESS=1 go test ./internal/scanner -run TestFakeNaabuPressure32767500Explicit -timeout 3h")
	}
	if testing.Short() {
		t.Skip("压力档在 -short 下跳过")
	}
	if free, ok := platformDiskFreeBytes("."); ok && free < 8<<30 {
		t.Skipf("剩余磁盘 %s 不足 8 GiB，跳过压力档以免耗尽本机资源", humanBytes(free))
	}
	h := newCapacityHarness(t, fullPortStreamScript, map[string]string{
		"scan_concurrency": "16",
		"scan_timeout_min": "1440",
	})
	taskID := newManualTask(t, h.st, "full", docIPv4(capacityTargets))
	started := time.Now()
	scanID, err := h.runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("提高预算后压力档应可执行: %v", err)
	}
	waitForScanStatusWithin(t, h.st, scanID, "done", 3*time.Hour)
	waitForRunnerIdleWithin(t, h.runner, 5*time.Minute)
	elapsed := time.Since(started)

	scan, err := h.st.Scan(scanID)
	if err != nil || scan == nil || scan.Status != "done" {
		t.Fatalf("压力档终态异常: %+v err=%v", scan, err)
	}
	if count, err := h.st.CountResultsByScan(scanID); err != nil || count != pressureResults {
		t.Fatalf("压力档库内结果行数=%d err=%v，期望 %d", count, err, pressureResults)
	}
	if scan.OpenPorts != pressureResults || scan.ResultCount != pressureResults {
		t.Fatalf("压力档计数不一致: open=%d result=%d，期望 %d", scan.OpenPorts, scan.ResultCount, pressureResults)
	}
	t.Logf("32,767,500 结果压力档：耗时 %s；%s；临时库 %s", elapsed.Round(time.Second), snapshotRuntime(t).String(), humanBytes(tempDBSize(t)))
	h.assertOfflineOnly(t, true)
}

// TestOfflineNaabuTripwireCatchesFallback 是离线验证自身的负向对照：
// 故意把 naabu_path 指向 PATH 中的同名工具，确认绊线会立即失败并记录 argv。
// 它证明 assertOfflineOnly 的“无真实 naabu 回退”断言确实能发现问题，
// 而不是一个永远通过的空断言。
func TestOfflineNaabuTripwireCatchesFallback(t *testing.T) {
	h := newCapacityHarness(t, stream500kScript, map[string]string{"naabu_path": "naabu"})
	taskID := newManualTask(t, h.st, "top", []string{"192.0.2.61"})
	if _, err := h.runner.StartTask(taskID); err == nil {
		t.Fatal("naabu_path 指向真实工具时 StartTask 应失败")
	}
	if h.runner.IsRunning() {
		t.Fatal("绊线失败后运行锁未释放")
	}
	tripwire := readTestFile(t, filepath.Join(h.tripDir, tripwireLogFile))
	if !strings.Contains(tripwire, "-version") {
		t.Fatalf("绊线未记录到回退调用: %q", tripwire)
	}
	if _, err := os.Stat(fakeInvocationLog); !os.IsNotExist(err) {
		t.Fatal("回退路径不应经过 fake 脚本")
	}
	t.Logf("绊线已捕获真实 naabu 回退调用: %q", strings.TrimSpace(tripwire))
}

// runtimeSnapshot 是一次进程级资源快照，用于泄漏断言与指标日志。
type runtimeSnapshot struct {
	HeapAlloc  uint64
	HeapSys    uint64
	Sys        uint64
	Goroutines int
	FDs        int
}

func snapshotRuntime(t *testing.T) runtimeSnapshot {
	t.Helper()
	// 稳态快照先 GC 一次，用来看“每轮结束后的残留”；运行期峰值由 peakSampler 采样。
	runtime.GC()
	return readMemSnapshot()
}

func (s runtimeSnapshot) String() string {
	return fmt.Sprintf("HeapAlloc=%s HeapSys=%s Sys=%s goroutines=%d fds=%d",
		humanBytes(int64(s.HeapAlloc)), humanBytes(int64(s.HeapSys)), humanBytes(int64(s.Sys)), s.Goroutines, s.FDs)
}

// countOpenFDs 统计当前进程打开的 Unix 文件描述符数；读取失败返回 -1（指标缺失不影响判定）。
func countOpenFDs(t *testing.T) int {
	t.Helper()
	return countOpenFDsQuiet()
}

// countOpenFDsQuiet 是不带 *testing.T 的 FD 计数，供后台采样器安全调用（失败返回 -1）。
func countOpenFDsQuiet() int {
	dir := "/proc/self/fd"
	if runtime.GOOS == "darwin" {
		dir = "/dev/fd"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	return len(entries)
}

// tempDBSize 返回临时工作目录下 SQLite 主库与 WAL/SHM 的总字节数。
func tempDBSize(t *testing.T) int64 {
	t.Helper()
	paths, err := filepath.Glob("test.db*")
	if err != nil {
		return 0
	}
	var total int64
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			total += info.Size()
		}
	}
	return total
}

func humanBytes(n int64) string {
	if n < 0 {
		return "unknown"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(n)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", n, units[unit])
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}
