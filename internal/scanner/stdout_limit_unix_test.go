//go:build linux || darwin

package scanner

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"easm-platform/internal/store"
)

// oversizedStdoutScript：先向 -o 写入一条正常结果，然后在 stdout 输出一条 2 MiB 的无换行前缀超长行
// （超过 1 MiB 单行硬上限），最后再输出一条正常结果。用来验证：
//   - 超限行被有界丢弃且不会阻塞后续行解析；
//   - 丢弃事实被记录为告警事件，终态不得为 done；
//   - 输出文件补读与实时输出仍按端口去重补齐结果。
const oversizedStdoutScript = `#!/bin/sh
if [ "${1:-}" = "-version" ]; then echo 'naabu test'; exit 0; fi
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
printf '192.0.2.1:443\n' > "$out"
awk 'BEGIN{ chunk=sprintf("%1024s","x"); for(i=0;i<2048;i++) printf "%s", chunk; printf "\n" }'
printf '192.0.2.2:8443\n'
printf '192.0.2.2:8443\n' >> "$out"
`

// TestOversizedStdoutLineIsDroppedAndRecorded 验证端到端行为：
// 超长单行不会让内存无界增长，也不会让批次虚报成功；其后的正常行仍被实时解析入库。
func TestOversizedStdoutLineIsDroppedAndRecorded(t *testing.T) {
	runner, st, _ := newControlledRunner(t, oversizedStdoutScript)
	if err := st.SaveSettings(map[string]string{"scan_timeout_min": "10"}); err != nil {
		t.Fatal(err)
	}
	taskID, err := st.CreateScanTask(store.ScanTask{
		Name: "超长输出测试", Mode: "top", TargetType: "manual", IPs: "192.0.2.1\n192.0.2.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	scanID, err := runner.StartTask(taskID)
	if err != nil {
		t.Fatal(err)
	}
	waitForScanStatusWithin(t, st, scanID, "partial", 20*time.Second)
	waitForRunnerIdleWithin(t, runner, 20*time.Second)

	scan, err := st.Scan(scanID)
	if err != nil || scan == nil {
		t.Fatalf("执行记录缺失: %+v err=%v", scan, err)
	}
	if scan.Status == "done" {
		t.Fatalf("存在被丢弃的超限行时终态不得为 done: %+v", scan)
	}
	if !strings.Contains(scanEventMessages(t, st, scanID), "超过单行上限") {
		t.Fatalf("未记录超限行被有界丢弃的事件: %s", scanEventMessages(t, st, scanID))
	}

	results, err := st.ResultsByScan(scanID)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, result := range results {
		found[fmt.Sprintf("%s:%d", result.IP, result.Port)] = true
	}
	// 超限行之前的文件结果（-o 补读）与之后的实时结果都必须存在。
	for _, key := range []string{"192.0.2.1:443", "192.0.2.2:8443"} {
		if !found[key] {
			t.Fatalf("缺少结果 %s：超限行丢弃后必须继续消费后续行/补读输出文件", key)
		}
	}
}
