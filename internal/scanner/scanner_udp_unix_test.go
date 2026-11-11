package scanner

import (
	"strings"
	"testing"

	"easm-platform/internal/store"
)

// TestStartTaskUDPSnapshot 验证任务级协议写入执行快照（udp_enabled）：
// tcp→false（纯 TCP）；udp/both→true（强制 SYN+UDP）。仅 unix（fake naabu）。
func TestStartTaskUDPSnapshot(t *testing.T) {
	script := "#!/bin/sh\necho \"192.0.2.1:80\"\nexit 0\n"
	for _, tc := range []struct {
		name     string
		protocol string
		udp      bool
	}{{"tcp", "tcp", false}, {"udp", "udp", true}, {"both", "both", true}} {
		t.Run(tc.name, func(t *testing.T) {
			runner, st, _ := newControlledRunner(t, script)
			taskID, err := st.CreateScanTask(store.ScanTask{Name: "proto-" + tc.name, Mode: "top", Engine: "naabu", Protocol: tc.protocol, TargetType: "manual", IPs: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			scanID, err := runner.StartTask(taskID)
			if err != nil {
				t.Fatalf("StartTask 失败: %v", err)
			}
			sc, _ := st.Scan(scanID)
			if sc == nil || sc.UDPEnabled != tc.udp {
				t.Fatalf("执行 UDP 快照应为 %v: %+v", tc.udp, sc)
			}
		})
	}
}

// naabuDowngradeScript 模拟 naabu 非 root 的真实行为：不报错退出，而是自行降级为 CONNECT，
// 并在 stderr 自述降级（UDP 端口随之被静默丢弃）。平台必须据此提示，而不是静默当作成功。
const naabuDowngradeScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    *) shift;;
  esac
done
echo '[INF] Running CONNECT scan with non root privileges' >&2
: > "$out"
exit 0
`

// TestNaabuDowngradeMarksUDPDisabled 验证 tcp+udp 任务在 naabu 自动降级 CONNECT 时：
// UDP 快照被纠正为未启用，且记录一次降级事件（兑现 README “不会静默丢失”的承诺）。
func TestNaabuDowngradeMarksUDPDisabled(t *testing.T) {
	runner, st, _ := newControlledRunner(t, naabuDowngradeScript)
	taskID, err := st.CreateScanTask(store.ScanTask{Name: "both-downgrade", Mode: "top", Engine: "naabu", Protocol: "both", TargetType: "manual", IPs: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("StartTask 失败: %v", err)
	}
	waitForScanStatus(t, st, scanID, "done")
	if sc, _ := st.Scan(scanID); sc == nil || sc.UDPEnabled {
		t.Fatalf("降级后 UDP 快照应纠正为未启用: %+v", sc)
	}
	if events := scanEventMessages(t, st, scanID); !strings.Contains(events, "降级为 CONNECT") {
		t.Fatalf("缺少降级事件: %s", events)
	}
}

// TestNaabuDowngradeUDPOnlyNoTCPFallback 验证「仅 UDP」任务在 naabu 自动降级 CONNECT 后：
// 终态不能是 done（避免 0 结果被误读为端口已关）、不产生任何 TCP 结果，并给出原因。
func TestNaabuDowngradeUDPOnlyNoTCPFallback(t *testing.T) {
	runner, st, _ := newControlledRunner(t, naabuDowngradeScript)
	taskID, err := st.CreateScanTask(store.ScanTask{Name: "udp-only-downgrade", Mode: "top", Engine: "naabu", Protocol: "udp", TargetType: "manual", IPs: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatalf("StartTask 失败: %v", err)
	}
	waitForScanStatus(t, st, scanID, "failed")
	results, err := st.ResultsByScan(scanID)
	if err != nil || len(results) != 0 {
		t.Fatalf("仅 UDP 降级后不应产生任何结果: %+v err=%v", results, err)
	}
	if events := scanEventMessages(t, st, scanID); !strings.Contains(events, "仅 UDP") {
		t.Fatalf("缺少仅 UDP 降级说明: %s", events)
	}
}
