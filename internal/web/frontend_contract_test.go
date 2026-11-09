package web

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"easm-platform/internal/store"
)

// scanDetailPageData 与 pageScanDetail 的模板数据同构，供契约测试直接渲染模板。
type scanDetailPageData struct {
	pageData
	Scan             store.Scan
	Results          []store.Result
	ResultTotal      int
	NextCursor       int64
	HasMore          bool
	Events           []store.ScanEvent
	LastEventID      int64
	CapacityRejected bool
	CapacityAdvice   []string
	TargetStatus     []store.TargetStatus
	TSDone           int
	TSPending        int
	TSRunning        int
	TSFailed         int
	UnfinishedCount  int
	CanResume        bool
}

func renderScanDetail(t *testing.T, server *Server, running bool, scan store.Scan) string {
	t.Helper()
	bd := pageData{
		Title: "执行详情 #" + strconv.FormatInt(scan.ID, 10), Section: "扫描", Active: "scans",
		AppName: "测试平台", Version: "test", User: "operator", Role: "operator", Running: running,
	}
	var buf bytes.Buffer
	if err := server.tpl.ExecuteTemplate(&buf, "scan_detail.html", scanDetailPageData{pageData: bd, Scan: scan}); err != nil {
		t.Fatalf("渲染执行详情模板失败: %v", err)
	}
	return buf.String()
}

// inlineScriptWith 提取页面中包含指定标记的内联脚本（跳过外链与主题初始化脚本）。
func inlineScriptWith(t *testing.T, html, marker string) string {
	t.Helper()
	rest := html
	for {
		start := strings.Index(rest, "<script>")
		if start < 0 {
			break
		}
		body := rest[start+len("<script>"):]
		end := strings.Index(body, "</script>")
		if end < 0 {
			break
		}
		script := body[:end]
		if strings.Contains(script, marker) {
			return script
		}
		rest = body[end+len("</script>"):]
	}
	t.Fatalf("页面中未找到包含 %q 的内联脚本", marker)
	return ""
}

// buttonTag 取出指定 id 的按钮起始标签，用于断言服务端渲染的可见性。
func buttonTag(t *testing.T, html, id string) string {
	t.Helper()
	marker := `id="` + id + `"`
	idx := strings.Index(html, marker)
	if idx < 0 {
		t.Fatalf("页面缺少按钮 %s", id)
	}
	start := strings.LastIndex(html[:idx], "<button")
	if start < 0 {
		t.Fatalf("按钮 %s 缺少 <button 起始标签", id)
	}
	end := strings.Index(html[idx:], ">")
	if end < 0 {
		t.Fatalf("按钮 %s 标签未闭合", id)
	}
	return html[start : idx+end+1]
}

// runNodeContract 在临时目录写入页面脚本与断言脚本并执行；未安装 node 时跳过。
func runNodeContract(t *testing.T, harness, script string) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("未安装 node，跳过前端契约测试")
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "page.js")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	harnessPath := filepath.Join(dir, "contract.js")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, harnessPath, scriptPath).CombinedOutput()
	if err != nil {
		t.Fatalf("前端契约测试失败: %v\n%s", err, out)
	}
	return string(out)
}

// nodeDomStub 是执行页面脚本所需的最小 DOM/fetch 桩：元素按 id 懒创建，
// 定时器只登记不执行，fetch 永不返回，保证页面初始化不会发起真实轮询。
const nodeDomStub = `
const vm = require('vm');
const fs = require('fs');
const code = fs.readFileSync(process.argv[2], 'utf8');
function makeEl(id) {
  const el = {
    id: id, style: {}, className: '', textContent: '', dataset: {}, children: [],
    appendChild: function (child) { this.children.push(child); child.parentNode = this; return child; },
    append: function () { for (let i = 0; i < arguments.length; i++) this.appendChild(arguments[i]); },
    removeChild: function (child) { const i = this.children.indexOf(child); if (i >= 0) this.children.splice(i, 1); return child; },
    classList: { toggle: function () {}, contains: function () { return false; }, add: function () {}, remove: function () {} },
    scrollIntoView: function () {}, setAttribute: function () {}, getAttribute: function () { return null; }
  };
  Object.defineProperty(el, 'firstElementChild', { get: function () { return this.children[0] || null; } });
  return el;
}
const elements = new Map();
const context = {
  document: {
    getElementById: function (id) { if (!elements.has(id)) elements.set(id, makeEl(id)); return elements.get(id); },
    createElement: function (tag) { return makeEl('created-' + tag); },
    querySelector: function () { return null; },
    querySelectorAll: function () { return []; },
    documentElement: { getAttribute: function () { return 'light'; }, setAttribute: function () {} }
  },
  setTimeout: function () { return 0; },
  clearTimeout: function () {},
  fetch: function () { return new Promise(function () {}); },
  localStorage: { getItem: function () { return null; }, setItem: function () {} },
  console: console
};
vm.createContext(context);
vm.runInContext(code, context, { filename: 'page.js' });
const run = function (src) { return vm.runInContext(src, context); };
const check = function (cond, msg) { if (!cond) { console.error('契约失败: ' + msg); process.exit(1); } };
const statusText = function () {
  return run("(function(){var el=document.getElementById('scan-status');var c=el.children;return c.length?c[c.length-1].textContent:'';})()");
};
const display = function (id) { return run("document.getElementById('" + id + "').style.display"); };
`

// TestScanDetailTerminalStatusOnlySticky 锁定终态粘滞契约：
// running/paused 永不写入 terminalStatus，running→paused→running→done 期间恢复/暂停按钮正确切换，
// 只有真正的终态才粘滞且迟到的 running 不得让页面回退。
func TestScanDetailTerminalStatusOnlySticky(t *testing.T) {
	server, _ := newScanLiveTestServer(t)

	// 模板源码契约：终态判定必须走白名单函数，禁止无条件写入。
	raw, err := assets.ReadFile("templates/scan_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, "function isTerminalStatus(status)") {
		t.Fatal("scan_detail.html 必须用 isTerminalStatus 白名单判定终态")
	}
	if strings.Contains(src, "terminalStatus = data.scan.status") {
		t.Fatal("轮询响应不得把未过滤的 scan.status 直接写入 terminalStatus")
	}
	if strings.Contains(src, "let terminalStatus = {{if .Running}}''{{else}}'{{.Scan.Status}}'{{end}}") {
		t.Fatal("首屏初始化不得把 running/paused 写入 terminalStatus")
	}

	// 悬空状态（服务重启后库里仍是 running 但实际未运行）：不得当作终态粘滞。
	stale := renderScanDetail(t, server, false, store.Scan{ID: 11, TaskID: 1, Status: "running", TargetCount: 5})
	if !strings.Contains(stale, "let terminalStatus = '';") {
		t.Fatal("悬空 running 页面不得把 running 写入 terminalStatus")
	}
	if strings.Contains(stale, `id="resume-btn"`) {
		t.Fatal("未运行的悬空状态不应渲染扫描控制按钮")
	}
	if !strings.Contains(stale, "重新同步状态") {
		t.Fatal("悬空状态应提供重新同步入口")
	}
	runNodeContract(t, nodeDomStub+`
check(run('terminalStatus') === '', '悬空 running 页面首屏 terminalStatus 必须为空');
check(run('canControl') === false, '未运行页面不应允许控制');
run("updateScan({status:'running', target_count:5, processed_targets:1})");
check(run('terminalStatus') === '', '首次轮询的 running 不得写入 terminalStatus');
check(run("mergeScan({status:'done'}).status") === 'done', 'running 未被钉住时应能进入 done');
run("updateScan({status:'done', target_count:5, processed_targets:5})");
check(run('terminalStatus') === 'done', 'done 必须写入 terminalStatus');
run("updateScan({status:'running', target_count:5, processed_targets:5})");
check(run("mergeScan({status:'running'}).status") === 'done', '终态后迟到的 running 不得回退');
`, inlineScriptWith(t, stale, "terminalStatus"))

	// 真实运行中的 paused 页面：恢复按钮必须由服务端直接渲染为可见。
	paused := renderScanDetail(t, server, true, store.Scan{ID: 12, TaskID: 1, Status: "paused", TargetCount: 5, ProcessedTargets: 2})
	resumeTag := buttonTag(t, paused, "resume-btn")
	if strings.Contains(resumeTag, "display:none") {
		t.Fatalf("paused 状态下恢复按钮必须可见: %s", resumeTag)
	}
	pauseTag := buttonTag(t, paused, "pause-btn")
	if !strings.Contains(pauseTag, "display:none") {
		t.Fatalf("paused 状态下暂停按钮必须隐藏: %s", pauseTag)
	}

	// JS 契约：running → paused → running → done 全链路。
	running := renderScanDetail(t, server, true, store.Scan{ID: 13, TaskID: 1, Status: "running", TargetCount: 10, ProcessedTargets: 1})
	runNodeContract(t, nodeDomStub+`
check(run('terminalStatus') === '', '运行中页面首屏不得写入 terminalStatus');
check(run('canControl') === true, 'operator 运行中页面应允许控制');
run("updateScan({status:'running', target_count:10, processed_targets:1})");
check(statusText() === '运行中', 'running 状态文案错误: ' + statusText());
check(display('pause-btn') === '', 'running 时暂停按钮必须可见');
check(display('resume-btn') === 'none', 'running 时恢复按钮必须隐藏');
run("updateScan({status:'paused', target_count:10, processed_targets:2})");
check(run('terminalStatus') === '', 'paused 不得写入 terminalStatus');
check(statusText() === '已暂停', 'paused 状态文案错误: ' + statusText());
check(display('resume-btn') === '', 'paused 时恢复按钮必须可见');
check(display('pause-btn') === 'none', 'paused 时暂停按钮必须隐藏');
run("updateScan({status:'running', target_count:10, processed_targets:3})");
check(run('terminalStatus') === '', '恢复 running 后 terminalStatus 仍必须为空');
check(display('pause-btn') === '', '恢复 running 后暂停按钮必须可见');
check(display('resume-btn') === 'none', '恢复 running 后恢复按钮必须隐藏');
run("updateScan({status:'done', target_count:10, processed_targets:10})");
check(run('terminalStatus') === 'done', 'done 必须写入 terminalStatus');
check(statusText() === '完成', 'done 状态文案错误: ' + statusText());
check(display('pause-btn') === 'none' && display('resume-btn') === 'none' && display('stop-btn') === 'none', '终态必须隐藏全部控制按钮');
run("updateScan({status:'paused', target_count:10, processed_targets:10})");
check(statusText() === '完成', '终态后迟到的 paused 不得覆盖完成状态: ' + statusText());
check(display('resume-btn') === 'none', '终态后不得再出现恢复按钮');
`, inlineScriptWith(t, running, "terminalStatus"))
}

// TestPollRunStatusRequiresRequestID 锁定 app.js 轮询契约：
// 必须携带 request_id；404/410/编号不匹配一律按失败处理，绝不表示启动成功。
func TestPollRunStatusRequiresRequestID(t *testing.T) {
	appJS, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	harness := `
const vm = require('vm');
const fs = require('fs');
const code = fs.readFileSync(process.argv[2], 'utf8');
const responseQueue = [];
const calls = [];
const context = {
  document: { getElementById: function () { return null; }, querySelectorAll: function () { return []; } },
  localStorage: { getItem: function () { return null; }, setItem: function () {} },
  fetch: async function (url) {
    calls.push(url);
    const next = responseQueue.length > 1 ? responseQueue.shift() : responseQueue[0];
    return { ok: next.status >= 200 && next.status < 300, status: next.status, json: async function () { return next.body; } };
  },
  setTimeout: function (fn) { Promise.resolve().then(fn); return 0; },
  console: console
};
vm.createContext(context);
vm.runInContext(code, context, { filename: 'app.js' });
const poll = context.pollRunStatus;
const check = function (cond, msg) { if (!cond) { console.error('契约失败: ' + msg); process.exit(1); } };
(async function () {
  // 1) 缺少 request_id：直接失败，且不得发起请求。
  let result = null;
  await poll('/api/tasks/1/run-status', '', function () { result = 'done'; }, function (msg) { result = 'error:' + msg; });
  check(String(result).indexOf('error:') === 0, '缺少 request_id 必须直接报错，实际: ' + result);
  check(calls.length === 0, '缺少 request_id 时不得发起轮询请求');

  // 2) 404 未知编号：明确失败，不得调用 onDone。
  calls.length = 0;
  responseQueue.length = 0;
  responseQueue.push({ status: 404, body: { error: '未找到启动请求编号', done: false } });
  result = null;
  await poll('/api/tasks/1/run-status', 'req-404', function (scanID) { result = 'done:' + scanID; }, function (msg) { result = 'error:' + msg; });
  check(String(result).indexOf('error:') === 0, '404 必须按失败处理，实际: ' + result);
  check(calls.length === 1 && calls[0].indexOf('request_id=req-404') >= 0, '轮询地址必须携带 request_id: ' + calls.join(','));

  // 3) 410 已过期：明确失败。
  calls.length = 0;
  responseQueue.length = 0;
  responseQueue.push({ status: 410, body: { error: '启动请求状态已过期', done: false } });
  result = null;
  await poll('/api/tasks/1/run-status?x=1', 'req-expired', function (scanID) { result = 'done:' + scanID; }, function (msg) { result = 'error:' + msg; });
  check(String(result).indexOf('error:') === 0, '410 必须按失败处理，实际: ' + result);
  check(calls[0].indexOf('request_id=req-expired') >= 0 && calls[0].indexOf('x=1') >= 0, '已有查询参数时应追加 request_id: ' + calls[0]);

  // 4) 编号不匹配：按失败处理，避免读到别人的结果。
  responseQueue.length = 0;
  responseQueue.push({ status: 200, body: { request_id: 'other', done: true, scan_id: 9 } });
  result = null;
  await poll('/api/tasks/1/run-status', 'req-mismatch', function (scanID) { result = 'done:' + scanID; }, function (msg) { result = 'error:' + msg; });
  check(String(result).indexOf('error:') === 0, 'request_id 不匹配必须按失败处理，实际: ' + result);

  // 5) 失败完成：onError 且携带原始错误。
  responseQueue.length = 0;
  responseQueue.push({ status: 200, body: { request_id: 'req-a', done: true, error: '容量预检未通过', scan_id: 3, advice: ['提高超时'] } });
  let advice = null;
  result = null;
  await poll('/api/tasks/1/run-status', 'req-a', function (scanID) { result = 'done:' + scanID; }, function (msg, adv) { result = 'error:' + msg; advice = adv; });
  check(result === 'error:容量预检未通过', '失败完成必须回传原始错误，实际: ' + result);
  check(advice && advice.length === 1 && advice[0] === '提高超时', '失败完成必须回传可操作建议');

  // 6) 进行中 → 成功：只有 done 且无 error 才算成功。
  responseQueue.length = 0;
  responseQueue.push({ status: 200, body: { request_id: 'req-b', done: false } });
  responseQueue.push({ status: 200, body: { request_id: 'req-b', done: true, scan_id: 42 } });
  result = null;
  await poll('/api/tasks/1/run-status', 'req-b', function (scanID) { result = 'done:' + scanID; }, function (msg) { result = 'error:' + msg; });
  check(result === 'done:42', '成功完成应回调 scan_id，实际: ' + result);
  process.exit(0);
})().catch(function (error) { console.error('契约执行异常: ' + error); process.exit(1); });
`
	runNodeContract(t, harness, string(appJS))
}

// TestRunPollingTemplatesPassRequestID 页面必须把启动 API 返回的 request_id 传给轮询，
// 且保持「运行」按钮只对可写角色可见、重复启动仍由服务端闸门拦截。
func TestRunPollingTemplatesPassRequestID(t *testing.T) {
	for _, name := range []string{"templates/tasks.html", "templates/task_form.html"} {
		raw, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		if !strings.Contains(src, "pollRunStatus(") || !strings.Contains(src, "request_id") {
			t.Fatalf("%s 轮询未传递 request_id", name)
		}
	}
	rawTasks, err := assets.ReadFile("templates/tasks.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(rawTasks)
	if !strings.Contains(src, "const requestID = res.json.request_id || '';") {
		t.Fatal("tasks.html 必须显式取出启动 API 返回的 request_id")
	}
	if !strings.Contains(src, `{{if ne $.Role "viewer"}}`) {
		t.Fatal("tasks.html 的运行按钮必须保留写角色限制")
	}
	// 重复启动防护仍然依赖服务端闸门：409 响应直接展示错误，不进入轮询。
	if !strings.Contains(src, "if (!res.ok) { showRunError(") {
		t.Fatal("tasks.html 必须在启动被拒绝（如 409）时直接展示错误")
	}
}
