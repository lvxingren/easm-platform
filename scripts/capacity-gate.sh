#!/usr/bin/env bash
# 纯离线容量验证单命令入口（不访问公网、不启动真实 naabu、不使用 data/easm.db）。
#
# 用法：
#   scripts/capacity-gate.sh fast       # 快速档：矩阵/暂停/Stop/三轮/参数白名单等小规模路径（约 30s）
#   scripts/capacity-gate.sh capacity   # 容量档：50 万唯一结果流式入库 + 运行期资源峰值断言
#   scripts/capacity-gate.sh repeat     # 定向重复：容量链路/三轮/退避 Stop/参数白名单各重复 3 次
#   scripts/capacity-gate.sh race       # 竞态档：internal/scanner 全量 + -race
#   scripts/capacity-gate.sh stress     # 压力档：32,767,500 结果（必须由调用方显式开启，见下）
#   scripts/capacity-gate.sh all        # fast + capacity + race
#
# 重要约定：
#   - race 档把容量用例自动降档为 20 目标 × 200 端口（4000 条），只为规避 -race 插桩放大导致的
#     两类假故障（SQLITE_BUSY、stdout 排空超时）。因此“峰值不随 50 万结果线性增长”的断言
#     只在 capacity 档成立；race 档报告里必须注明这是降档规模。
#   - 本脚本不会自行设置 EASM_SCANNER_STRESS：常规验证绝不执行 32,767,500 结果压力档。
set -euo pipefail

cd "$(dirname "$0")/.."

mode="${1:-fast}"
pkg="./internal/scanner"
# 快速档用“显式锚定的用例名”而不是 -short：-short 会同时跳过 500 目标矩阵，
# 而矩阵本身就是要求一的离线证据（约 6s）；锚定后 50 万与压力档不会被带到快速档。
fast_pattern='^(TestFakeNaabu500TargetsFullPortMatrix|TestPauseAcrossOldDeadlineResumesAllBatches|TestFakeNaabuFailureLingeringPipeRetryAndRestart|TestFakeNaabuBulkOutputStreamsAndDeduplicates|TestConcurrentBatchesAllStopTogether|TestStopConvergesAfterPausedProcessExit|TestBatchRetryExhaustedKeepsStderr|TestRunBatchBoundedWhenChildHoldsStderr|TestRunBatchBoundedWhenChildHoldsStdout|TestFakeNaabu32767500RejectedWithoutPartialWrite|TestOfflineNaabuTripwireCatchesFallback|TestFakeNaabuArgvWhitelistRejectsUnexpectedArgs|TestFakeNaabuWrapperRejectsPathEscapes|TestFakeNaabuThreeRoundsLockReleaseAndNoLeak|TestStopDuringRetryBackoffReleasesLock|TestIgnoreSignalErrorDoesNotSwallowRealPermissionErrors|TestProbeProcessGroupDistinguishesReap|TestProbeProcessGroupSeesReparentedGrandchild|TestProbeProcessGroupForLiveProcess)$'
# 定向重复档：容量链路 + 资源峰值 + 三轮泄漏 + 退避中 Stop + 参数/路径白名单 + 进程组探活。
repeat_pattern='^(TestFakeNaabu500kStreamingIntoSQLite|TestFakeNaabuThreeRoundsLockReleaseAndNoLeak|TestStopDuringRetryBackoffReleasesLock|TestFakeNaabuArgvWhitelistRejectsUnexpectedArgs|TestFakeNaabuWrapperRejectsPathEscapes|TestProbeProcessGroupDistinguishesReap|TestProbeProcessGroupForLiveProcess|TestIgnoreSignalErrorDoesNotSwallowRealPermissionErrors)$'

banner() {
  printf '\n=== %s ===\n' "$*"
}

case "$mode" in
  fast)
    banner "快速档：小规模路径（-race 无关，无 50 万/压力档）"
    go test "$pkg" -count=1 -timeout 10m -run "$fast_pattern" -v
    ;;
  capacity)
    banner "容量档：50 万条结果流式入库 + HeapAlloc/HeapSys/Sys/goroutines/FD 峰值断言"
    go test "$pkg" -count=1 -timeout 30m -run 'TestFakeNaabu500kStreamingIntoSQLite' -v
    ;;
  repeat)
    banner "定向重复档：容量与异常路径各重复 3 次（检查峰值与泄漏断言的稳定性）"
    go test "$pkg" -count=3 -timeout 60m -run "$repeat_pattern" -v
    ;;
  race)
    banner "竞态档：internal/scanner 全量 + -race（容量用例已降档为 20 目标 × 200 端口 = 4000 条）"
    go test "$pkg" -race -count=1 -timeout 40m
    ;;
  stress)
    if [ "${EASM_SCANNER_STRESS:-}" != "1" ]; then
      echo "压力档未启用：本档会真正执行 32,767,500 条结果，必须由调用方显式 EASM_SCANNER_STRESS=1 开启。" >&2
      exit 2
    fi
    banner "压力档：32,767,500 条结果（需 >=8 GiB 空闲磁盘，数分钟到数十分钟）"
    go test "$pkg" -count=1 -timeout 3h -run 'TestFakeNaabuPressure32767500Explicit' -v
    ;;
  all)
    banner "容量档：50 万条结果流式入库 + 资源峰值断言"
    go test "$pkg" -count=1 -timeout 30m -run 'TestFakeNaabu500kStreamingIntoSQLite' -v
    banner "快速档：小规模路径"
    go test "$pkg" -count=1 -timeout 10m -run "$fast_pattern" -v
    banner "竞态档：全量 + -race（容量用例降档为 4000 条）"
    go test "$pkg" -race -count=1 -timeout 40m
    ;;
  *)
    echo "用法: $0 {fast|capacity|repeat|race|stress|all}" >&2
    exit 2
    ;;
esac
