package scanner

import (
	"strings"
	"testing"
)

// TestValidatePortList 覆盖自定义/排除端口的合法与非法输入。
func TestValidatePortList(t *testing.T) {
	valid := []string{"22", "22,80,443", "8000-9000", "22,80,443,8000-9000", "1-65535", " 22 , 80 "}
	for _, v := range valid {
		if err := ValidatePortList(v, "自定义端口"); err != nil {
			t.Fatalf("合法端口 %q 被拒: %v", v, err)
		}
	}
	invalid := []string{"", "   ", "0", "65536", "22,", ",22", "abc", "8000-7000", "22-80-100", "-1", "70000", "80-"}
	for _, v := range invalid {
		if err := ValidatePortList(v, "自定义端口"); err == nil {
			t.Fatalf("非法端口 %q 未被拒", v)
		}
	}
	// 排除端口空值放行（不影响扫描），非空走同一校验
	if err := validateExcludedPorts(""); err != nil {
		t.Fatalf("排除端口空值应放行: %v", err)
	}
	if err := validateExcludedPorts("99999"); err == nil {
		t.Fatal("排除端口非法值应被拒")
	}
}

// TestNaabuArgsPortModes 验证三种端口模式拼接的 naabu 参数。
func TestNaabuArgsPortModes(t *testing.T) {
	s := NaabuSettings{Path: "naabu", Rate: "1000", Retries: "2", Workers: "25", ResponseTimeout: "1s", ScanType: "c"}

	custom := strings.Join(s.args("t.txt", "o.txt", "custom", "22,80,8000-9000"), " ")
	if !strings.Contains(custom, "-p 22,80,8000-9000") {
		t.Fatalf("custom 模式应拼 -p <ports>: %s", custom)
	}
	if strings.Contains(custom, "-top-ports") {
		t.Fatalf("custom 模式不应含 -top-ports: %s", custom)
	}

	full := strings.Join(s.args("t.txt", "o.txt", "full", ""), " ")
	if !strings.Contains(full, "-p -") || strings.Contains(full, "-top-ports") {
		t.Fatalf("full 模式应为 -p -: %s", full)
	}

	top := strings.Join(s.args("t.txt", "o.txt", "top", ""), " ")
	if !strings.Contains(top, "-top-ports 1000") || strings.Contains(top, " -p ") {
		t.Fatalf("top 模式应为 -top-ports 1000: %s", top)
	}
}
