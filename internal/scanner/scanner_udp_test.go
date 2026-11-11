package scanner

import (
	"strings"
	"testing"
)

func TestUDPPortSpec(t *testing.T) {
	if got := udpPortSpec("53,161,500-510"); got != "u:53,u:161,u:500-510" {
		t.Fatalf("udpPortSpec 错误: %q", got)
	}
	if udpPortSpec("") != "" || udpPortSpec("  ") != "" {
		t.Fatal("空输入应返回空串")
	}
}

func TestUDPPortCount(t *testing.T) {
	if n := udpPortCount("53,161,53"); n != 2 {
		t.Fatalf("去重计数应 2: %d", n)
	}
	if n := udpPortCount("500-502"); n != 3 {
		t.Fatalf("范围计数应 3: %d", n)
	}
	if n := udpPortCount("bad,70000"); n != 0 {
		t.Fatalf("非法项应跳过: %d", n)
	}
}

func udpSettings() NaabuSettings {
	return NaabuSettings{Rate: "1000", Retries: "2", Workers: "25", ResponseTimeout: "1s", UDP: true, UDPPorts: "53,161", ScanType: "s"}
}

func TestNaabuArgsUDPFullCustomTop(t *testing.T) {
	s := udpSettings()
	full := strings.Join(s.args("t.txt", "o.txt", "full", ""), " ")
	if !strings.Contains(full, "u:53") || !strings.Contains(full, "1-65535") || !strings.Contains(full, "-scan-type s") {
		t.Fatalf("full+UDP 应含 1-65535 与 u:53 且 SYN: %s", full)
	}
	custom := strings.Join(s.args("t.txt", "o.txt", "custom", "22,80"), " ")
	if !strings.Contains(custom, "22,80,u:53") {
		t.Fatalf("custom+UDP 应拼接 TCP+UDP: %s", custom)
	}
	top := strings.Join(s.args("t.txt", "o.txt", "top", ""), " ")
	if !strings.Contains(top, "u:53") || strings.Contains(top, "-top-ports") {
		t.Fatalf("top+UDP 应用显式 -p 而非 -top-ports: %s", top)
	}
}

func TestNaabuArgsUDPDroppedOnConnectFallback(t *testing.T) {
	s := udpSettings()
	s.ScanType = "c" // SYN 降级 CONNECT 后应丢弃 UDP
	joined := strings.Join(s.args("t.txt", "o.txt", "full", ""), " ")
	if strings.Contains(joined, "u:") {
		t.Fatalf("CONNECT 降级后不应含 UDP: %s", joined)
	}
}

func TestNaabuArgsUDPOnlyNoTCPPorts(t *testing.T) {
	s := udpSettings()
	s.UDPOnly = true
	// 仅 UDP：不论 mode 为 full/custom/top，都只下发 u: 端口，不附加任何 TCP 端口。
	for _, mode := range []string{"full", "custom", "top"} {
		custom := "22,80"
		if mode != "custom" {
			custom = ""
		}
		joined := strings.Join(s.args("t.txt", "o.txt", mode, custom), " ")
		if !strings.Contains(joined, "u:53") {
			t.Fatalf("%s+仅UDP 应含 u:53: %s", mode, joined)
		}
		if strings.Contains(joined, "1-65535") || strings.Contains(joined, "-top-ports") || strings.Contains(joined, "22,80,") {
			t.Fatalf("%s+仅UDP 不应下发任何 TCP 端口: %s", mode, joined)
		}
	}
}

func TestNaabuArgsUDPOnlyDroppedOnConnectFallback(t *testing.T) {
	s := udpSettings()
	s.UDPOnly = true
	s.ScanType = "c" // SYN 降级后 udpSpec 为空：必须返回 nil（无任何端口可扫），由执行层跳过本批
	if args := s.args("t.txt", "o.txt", "top", ""); args != nil {
		t.Fatalf("仅 UDP 降级 CONNECT 后不得下发任何端口（尤其是 TCP top），实际: %v", args)
	}
}

// TestNaabuArgsSilentOnlyForConnect 验证只有 CONNECT 模式带 -silent：
// SYN 模式必须保留 naabu 的降级自述（stderr），否则非 root 自动降级 CONNECT、UDP 静默失效平台无从感知。
func TestNaabuArgsSilentOnlyForConnect(t *testing.T) {
	s := udpSettings()
	syn := strings.Join(s.args("t.txt", "o.txt", "top", ""), " ")
	if strings.Contains(syn, "-silent") {
		t.Fatalf("SYN 模式不应带 -silent（会吞掉降级提示）: %s", syn)
	}
	s.ScanType = "c"
	connect := strings.Join(s.args("t.txt", "o.txt", "top", ""), " ")
	if !strings.Contains(connect, "-silent") {
		t.Fatalf("CONNECT 模式应保持 -silent: %s", connect)
	}
}

// TestNaabuFellBackToConnect 验证降级提示识别：只命中 naabu 的自动降级文案，
// 不把有权限时的 "Running SYN scan with root privileges" 误判为降级。
func TestNaabuFellBackToConnect(t *testing.T) {
	cases := []struct {
		stderr string
		want   bool
	}{
		{"[INF] Running CONNECT scan with non root privileges", true},
		{"[INF] Running connect scan without root privileges", true},
		{"[INF] Running SYN scan with root privileges", false},
		{"[INF] Found 1 ports on host 127.0.0.1", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := naabuFellBackToConnect(tc.stderr); got != tc.want {
			t.Fatalf("naabuFellBackToConnect(%q)=%v，期望 %v", tc.stderr, got, tc.want)
		}
	}
}

func TestNaabuArgsNoUDPUnchanged(t *testing.T) {
	s := NaabuSettings{Rate: "1000", Retries: "2", Workers: "25", ResponseTimeout: "1s", ScanType: "c"}
	top := strings.Join(s.args("t.txt", "o.txt", "top", ""), " ")
	if !strings.Contains(top, "-top-ports 1000") || strings.Contains(top, "u:") {
		t.Fatalf("未启用 UDP 应保持 -top-ports 且无 u:: %s", top)
	}
	full := strings.Join(s.args("t.txt", "o.txt", "full", ""), " ")
	if !strings.Contains(full, "-p -") {
		t.Fatalf("未启用 UDP full 应保持 -p -: %s", full)
	}
}

func TestParseUDPProtocol(t *testing.T) {
	p := parseOutputLine(`{"ip":"192.0.2.1","port":53,"protocol":"udp"}`)
	if p.kind != parseResult || p.result.Proto != "udp" || p.result.Port != 53 {
		t.Fatalf("UDP JSON 应解析为 udp: %+v", p)
	}
}

func TestNaabuSettingsUDPForcesSYN(t *testing.T) {
	r, st := newFscanRunner(t)
	_ = st.SetSetting("scan_udp", "1")
	_ = st.SetSetting("naabu_scan_type", "c")
	s := r.naabuSettings()
	if !s.UDP || s.ScanType != "s" {
		t.Fatalf("启用 UDP 应强制 SYN: %+v", s)
	}
	if s.UDPPorts != DefaultUDPPorts {
		t.Fatalf("UDP 端口应回退默认: %q", s.UDPPorts)
	}
}
