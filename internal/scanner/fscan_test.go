package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"easm-platform/internal/config"
	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

func TestParseFscanOutput(t *testing.T) {
	cases := []struct {
		line    string
		ok      bool
		ip      string
		port    int
		service string
		vuln    string
	}{
		{"192.0.2.1:445 SMB SMBGhost CVE-2020-0796", true, "192.0.2.1", 445, "SMB", "SMBGhost CVE-2020-0796"},
		{"[+] 192.0.2.1:445 open", true, "192.0.2.1", 445, "", ""},
		{"[*] 192.0.2.2:8080 HTTP Struts2 RCE", true, "192.0.2.2", 8080, "HTTP", "Struts2 RCE"},
		{"192.0.2.3:22", true, "192.0.2.3", 22, "", ""},
		{"", false, "", 0, "", ""},
		{"not a result line", false, "", 0, "", ""},
		{"[+] hostname:80 open", false, "", 0, "", ""}, // 非 IP 不入库
	}
	for _, c := range cases {
		res, ok := parseFscanOutput(c.line)
		if ok != c.ok {
			t.Fatalf("parseFscanOutput(%q) ok=%v，期望 %v", c.line, ok, c.ok)
		}
		if !ok {
			continue
		}
		if res.IP != c.ip || res.Port != c.port || res.Service != c.service || res.Vuln != c.vuln {
			t.Fatalf("parseFscanOutput(%q)=%+v，期望 ip=%s port=%d svc=%s vuln=%s", c.line, res, c.ip, c.port, c.service, c.vuln)
		}
	}
}

func TestFscanArgs(t *testing.T) {
	s := FscanSettings{Path: "fscan", Workers: 50, VulnScan: true}
	joined := " " + joinArgs(fscanArgs("t.txt", "o.txt", s)) + " "
	for _, want := range []string{"-t 50", "-hf t.txt", "-o o.txt", "-nobr"} {
		if !contains(joined, want) {
			t.Fatalf("fscan 参数缺少 %q: %v", want, joined)
		}
	}
	// 漏洞模式保留 PoC；-h/-nobrute/-np 均不是 fscan 1.8.x 的正确用法。
	for _, bad := range []string{" -np ", " -nobrute ", " -nopoc ", " -noredis ", " -h t.txt "} {
		if contains(joined, bad) {
			t.Fatalf("漏洞模式不应包含 %q: %v", bad, joined)
		}
	}

	s.VulnScan = false
	port := " " + joinArgs(fscanArgs("t.txt", "o.txt", s)) + " "
	for _, want := range []string{" -nopoc ", " -noredis ", " -nobr "} {
		if !contains(port, want) {
			t.Fatalf("纯端口模式应包含 %q 关闭漏洞检测: %s", want, port)
		}
	}
	if contains(port, " -np ") {
		t.Fatal("-np 在 fscan 中是跳过 ping，不是关闭 PoC，纯端口模式不应使用")
	}
}

// TestFscanErrorDetailKeepsOutput 回归：运行失败时不能只回传「exit status 2」，
// 必须带上 fscan 实际打印的参数错误，便于直接定位版本/参数不兼容。
func TestFscanErrorDetailKeepsOutput(t *testing.T) {
	msg := fscanErrorDetail(errors.New("exit status 2"), "fscan version: 1.8.4\nflag provided but not defined: -nobrute", "")
	if !strings.Contains(msg, "exit status 2") || !strings.Contains(msg, "flag provided but not defined") {
		t.Fatalf("失败详情应包含错误与输出: %s", msg)
	}
	long := strings.Repeat("a", 5000) + "TAIL"
	got := fscanOutputDetail(long, 100)
	if !strings.HasSuffix(got, "TAIL") || len(got) > 200 {
		t.Fatalf("输出应只保留有界尾部: len=%d tail=%q", len(got), got[len(got)-8:])
	}
}

func joinArgs(args []string) string {
	out := ""
	for _, a := range args {
		out += a + " "
	}
	return out
}
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestSeverityForVuln(t *testing.T) {
	if severityForVuln("SMBGhost CVE-2020-0796") != "high" {
		t.Fatal("SMBGhost 应为 high")
	}
	if severityForVuln("Struts2 RCE") != "high" {
		t.Fatal("Struts2 应为 high")
	}
	if severityForVuln("some-info-leak") != "mid" {
		t.Fatal("普通漏洞应为 mid")
	}
	if severityForVuln("") != "low" {
		t.Fatal("空漏洞应为 low")
	}
}

func TestEstimateFscanDuration(t *testing.T) {
	// 500 目标、100 线程：500*7.5min/100 = 37.5min < 60min，不应误拒。
	d := estimateFscanDuration(500, 100)
	if d > 60*time.Minute {
		t.Fatalf("500 IP fscan 估算 %s 超过 60 分钟，会误拒", d)
	}
	if estimateFscanDuration(0, 100) != 0 {
		t.Fatal("0 目标应为 0")
	}
	// 线程数越少耗时越长。
	if estimateFscanDuration(500, 10) <= estimateFscanDuration(500, 100) {
		t.Fatal("线程少应更慢")
	}
}

func TestCollectFscanResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fscan.out")
	content := "[+] 192.0.2.1:445 open\n[*] 192.0.2.1:445 SMB SMBGhost\nnoise line\n192.0.2.2:80 HTTP\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	results, vulns := collectFscanResults(path)
	if len(results) != 3 {
		t.Fatalf("结果数=%d，期望 3", len(results))
	}
	if len(vulns) != 1 || vulns[0].Vuln != "SMBGhost" || vulns[0].Severity != "high" {
		t.Fatalf("漏洞解析错误: %+v", vulns)
	}
	// 不存在的文件返回空。
	r2, v2 := collectFscanResults(filepath.Join(dir, "nope.out"))
	if len(r2) != 0 || len(v2) != 0 {
		t.Fatal("缺失文件应返回空")
	}
}

func TestCheckFscanMissingPath(t *testing.T) {
	if _, err := checkFscan("definitely-not-exist-fscan-xyz"); err == nil {
		t.Fatal("不存在的 fscan 路径应报错")
	}
}

func TestNormalizeFscanModeAndLabel(t *testing.T) {
	if normalizeFscanMode("") != FscanModePort || normalizeFscanMode("bogus") != FscanModePort {
		t.Fatal("空/非法模式应回退纯端口")
	}
	if normalizeFscanMode("VULN") != FscanModeVuln || normalizeFscanMode("mixed") != FscanModeMixed {
		t.Fatal("模式归一化错误")
	}
	if fscanModeLabel(FscanModePort) != "纯端口" || fscanModeLabel(FscanModeVuln) != "漏洞检测" || fscanModeLabel(FscanModeMixed) != "混合" {
		t.Fatal("模式标签错误")
	}
}

func TestEngineIsFscanAndMode(t *testing.T) {
	if engineIsFscan("naabu") || engineIsFscan("") {
		t.Fatal("naabu/空不应判定为 fscan")
	}
	for _, e := range []string{"fscan", "fscan-vuln", "fscan-mixed", "mixed"} {
		if !engineIsFscan(e) {
			t.Fatalf("%s 应判定为 fscan", e)
		}
	}
	if engineFscanMode("fscan") != FscanModePort || engineFscanMode("fscan-vuln") != FscanModeVuln || engineFscanMode("mixed") != FscanModeMixed {
		t.Fatal("引擎→子模式映射错误")
	}
}

func TestFscanArgsPortsAndModes(t *testing.T) {
	port := FscanSettings{Workers: 50, Mode: FscanModePort, CustomPorts: "22,80,8000-9000"}
	j := " " + joinArgs(fscanArgs("t.txt", "o.txt", port)) + " "
	if !contains(j, "-p 22,80,8000-9000") || !contains(j, " -nopoc ") || !contains(j, " -noredis ") {
		t.Fatalf("纯端口应带 -p 自定义与 -nopoc/-noredis: %v", j)
	}
	full := joinArgs(fscanArgs("t.txt", "o.txt", FscanSettings{Mode: FscanModePort}))
	if !contains(full, "-p 1-65535") {
		t.Fatalf("留空应默认全端口: %v", full)
	}
	vuln := " " + joinArgs(fscanArgs("t.txt", "o.txt", FscanSettings{Mode: FscanModeVuln})) + " "
	if contains(vuln, " -nopoc ") || contains(vuln, " -np ") {
		t.Fatalf("漏洞模式不应关闭 PoC 或跳过 ping: %v", vuln)
	}
	if !contains(vuln, " -nobr ") {
		t.Fatalf("应始终关闭弱口令爆破: %v", vuln)
	}
}

func TestEstimateFscanPortMode(t *testing.T) {
	port := estimateFscanDuration(500, 100, FscanModePort)
	vuln := estimateFscanDuration(500, 100, FscanModeVuln)
	if port >= vuln {
		t.Fatalf("纯端口应快于漏洞模式: port=%s vuln=%s", port, vuln)
	}
	if port > 60*time.Minute {
		t.Fatalf("500 IP 纯端口不应误拒: %s", port)
	}
}

// TestFscanSplitAggregation 验证 fscan 拆分：子任务命名/关联、结果与漏洞聚合到主扫描（仅 unix）。
func TestFscanSplitAggregation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	r, st := newFscanRunner(t)
	script := writeFakeFscan(t, t.TempDir())
	_ = st.SetSetting("fscan_path", script)
	_ = st.SetSetting("split_batch_size", "2")
	taskID, _ := st.CreateScanTask(store.ScanTask{Name: "全台账·常用端口", Mode: "top", Engine: "fscan-vuln", TargetType: "all"})
	parentID, _ := st.CreateScan(taskID, "全台账·常用端口 · fscan-漏洞检测 · 20261109-120000", "top")
	r.mu.Lock()
	r.scanID = parentID
	r.active = newExecutionControl()
	r.mu.Unlock()

	specs := []store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}, {Raw: "192.0.2.2", Kind: "ip"}, {Raw: "192.0.2.3", Kind: "ip"}, {Raw: "192.0.2.4", Kind: "ip"}, {Raw: "192.0.2.5", Kind: "ip"}}
	fs := r.fscanSettings()
	fs.Mode = FscanModeVuln
	if _, err := r.startFscanSplitTask(parentID, specs, fs); err != nil {
		t.Fatalf("startFscanSplitTask 应成功: %v", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		sc, _ := st.Scan(parentID)
		if sc != nil && sc.Status != "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	sc, _ := st.Scan(parentID)
	if sc == nil || sc.Status != "done" {
		t.Fatalf("主扫描终态应 done: %+v", sc)
	}
	if !sc.IsSplitTask || sc.SplitTotal != 3 {
		t.Fatalf("应标记拆分 3 子任务: %+v", sc)
	}
	if !contains(sc.Name, "[自动拆分]") {
		t.Fatalf("主扫描名应含 [自动拆分]: %s", sc.Name)
	}
	subs, _ := st.SubTasksByParent(parentID)
	if len(subs) != 3 {
		t.Fatalf("子任务数应 3: %d", len(subs))
	}
	for _, sub := range subs {
		subScan, _ := st.Scan(sub.SubScanID)
		if subScan == nil || subScan.TaskID != taskID {
			t.Fatalf("子扫描 task_id 应关联主任务: %+v", subScan)
		}
		if !contains(subScan.Name, "子任务") || !contains(subScan.Name, "fscan-漏洞检测") {
			t.Fatalf("子扫描名应沿用主任务格式: %s", subScan.Name)
		}
	}
	// 结果与漏洞应聚合到主扫描。
	n, _ := st.CountResultsByScan(parentID)
	if n == 0 {
		t.Fatal("主扫描应聚合端口结果")
	}
	vulns, _ := st.VulnsByScan(parentID)
	if len(vulns) == 0 {
		t.Fatal("主扫描应聚合漏洞明细")
	}
}

func newFscanRunner(t *testing.T) (*Runner, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{}
	return New(st, cfg, engine.New(st, cfg)), st
}

func writeFakeFscan(t *testing.T, dir string) string {
	t.Helper()
	script := filepath.Join(dir, "fscan")
	body := "#!/bin/sh\nout=\"\"; prev=\"\"\nfor a in \"$@\"; do if [ \"$prev\" = \"-o\" ]; then out=\"$a\"; fi; prev=\"$a\"; done\nif [ -z \"$out\" ]; then echo \"fscan help\"; exit 0; fi\nprintf '[+] 192.0.2.1:445 open\\n[*] 192.0.2.1:445 SMB SMBGhost\\n' > \"$out\"\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// TestUnlimitedTimeoutDefault 验证默认不限制超时：scan_timeout_min=0 时 overallTimeout/settingsOverallTimeout 为 0，
// 且 naabu 配置默认 OverallTimeout 为 "0"。
func TestUnlimitedTimeoutDefault(t *testing.T) {
	r, st := newFscanRunner(t)
	_ = st.SetSetting("scan_timeout_min", "0")
	if settingsOverallTimeout(r) != 0 {
		t.Fatal("scan_timeout_min=0 应不限制")
	}
	if r.naabuSettings().overallTimeout() != 0 {
		t.Fatal("naabu overallTimeout 应为 0")
	}
	_ = st.SetSetting("scan_timeout_min", "30")
	if settingsOverallTimeout(r) != 30*time.Minute {
		t.Fatal("显式 30 分钟应生效")
	}
}

func TestFscanSettingsAndTimeout(t *testing.T) {
	r, st := newFscanRunner(t)
	_ = st.SetSetting("fscan_path", "/usr/local/bin/fscan")
	_ = st.SetSetting("fscan_workers", "80")
	_ = st.SetSetting("fscan_vuln", "0")
	_ = st.SetSetting("scan_timeout_min", "30")
	fs := r.fscanSettings()
	if fs.Path != "/usr/local/bin/fscan" || fs.Workers != 80 || fs.VulnScan {
		t.Fatalf("fscan 配置读取错误: %+v", fs)
	}
	if fs.Timeout != 30*time.Minute {
		t.Fatalf("超时错误: %s", fs.Timeout)
	}
}

func TestCheckFscanSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	script := writeFakeFscan(t, t.TempDir())
	resolved, err := checkFscan(script)
	if err != nil || resolved == "" {
		t.Fatalf("fake fscan 自检应通过: %v", err)
	}
}

func TestStartFscanTask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	r, st := newFscanRunner(t)
	script := writeFakeFscan(t, t.TempDir())
	_ = st.SetSetting("fscan_path", script)
	scanID, _ := st.CreateScan(0, "fscan start", "top")
	r.mu.Lock()
	r.scanID = scanID
	r.active = newExecutionControl()
	r.mu.Unlock()

	if _, err := r.startFscanTask(scanID, []store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}}, r.fscanSettings(), ""); err != nil {
		t.Fatalf("startFscanTask 应成功: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sc, _ := st.Scan(scanID)
		if sc != nil && sc.Status != "running" {
			if sc.Status != "done" {
				t.Fatalf("终态应 done: %s", sc.Status)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("fscan 未在超时内完成")
}

func TestStartFscanTaskBadPath(t *testing.T) {
	r, st := newFscanRunner(t)
	_ = st.SetSetting("fscan_path", "not-exist-fscan-xyz")
	scanID, _ := st.CreateScan(0, "fscan bad", "top")
	if _, err := r.startFscanTask(scanID, []store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}}, r.fscanSettings(), ""); err == nil {
		t.Fatal("非法 fscan 路径应拒绝")
	}
}

// TestRunFscanScanWithFakeTool 用 fake fscan 脚本覆盖执行→解析→入库→收尾链路（仅 unix）。
func TestRunFscanScanWithFakeTool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell 脚本仅 unix")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "fscan")
	body := "#!/bin/sh\nout=\"\"; prev=\"\"\nfor a in \"$@\"; do if [ \"$prev\" = \"-o\" ]; then out=\"$a\"; fi; prev=\"$a\"; done\nif [ -z \"$out\" ]; then echo \"fscan help\"; exit 0; fi\nprintf '[+] 192.0.2.1:445 open\\n[*] 192.0.2.1:445 SMB SMBGhost\\n' > \"$out\"\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &config.Config{}
	eng := engine.New(st, cfg)
	r := New(st, cfg, eng)
	scanID, err := st.CreateScan(0, "fscan 测试", "top")
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.scanID = scanID
	r.active = newExecutionControl()
	r.mu.Unlock()

	r.runFscanScan(scanID, []store.TargetSpec{{Raw: "192.0.2.1", Kind: "ip"}}, FscanSettings{Path: script, Workers: 10, VulnScan: true, Timeout: time.Minute})

	scan, _ := st.Scan(scanID)
	if scan == nil || scan.Status != "done" {
		t.Fatalf("fscan 执行终态应为 done: %+v", scan)
	}
	if scan.OpenPorts < 1 {
		t.Fatalf("应入库开放端口: %+v", scan)
	}
	vulns, _ := st.VulnsByScan(scanID)
	if len(vulns) != 1 || vulns[0].Severity != "high" {
		t.Fatalf("漏洞应入库: %+v", vulns)
	}
}
