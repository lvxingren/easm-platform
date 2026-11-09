//go:build linux || darwin

package scanner

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// 本文件提供“运行期资源采样器”与“相对基线 + 绝对上限”双约束断言，
// 用于证明 50 万条结果的链路始终是流式的：峰值不会随总结果数线性接近全量驻留规模。
//
// 采样要点：
//   - 采样器只读 runtime.MemStats / NumGoroutine / FD 数量，绝不调用 runtime.GC()：
//     GC 会把 HeapAlloc 峰值抹平，只有“不干预运行时”的读数才能反映真实峰值；
//   - 采样状态全部在互斥锁内累积，stop() 通过 sync.Once + WaitGroup 保证幂等且一定能停；
//   - 采样周期足够密（20ms），既能捕捉短时峰值，也不会明显拖慢链路（50 万条约 300 次采样）。

// resourceSampleInterval 是采样周期。
const resourceSampleInterval = 20 * time.Millisecond

// resultFootprintBytes 是对单条 store.Result 全量驻留内存的保守下限估算：
// 结果含 IP/域名/协议等 5 个字符串头（16B）+ 端口/时间等字段 + 切片元素开销，
// 取 256B 已明显高于实际驻留规模，因此“全量驻留估算”是一个偏严格的参照线。
const resultFootprintBytes = 256

// 以下上限同时满足两个前提：
//   - 对当前 16 GiB 开发机极其保守（连总峰值上限也远低于内存余量）；
//   - 对 CI 上也安全（GitHub 标准 runner 为 7-16 GiB，且流式链路的实测峰值只有几十 MiB）。
//
// 每个指标有两条彼此独立的约束，分别断言、分别报告：
//   - peakCap：进程级“总峰值”的绝对上限；
//   - relFactor/relSlack：相对基线“增量”的上限 = relFactor×基线 + relSlack。
//
// 两者不能互相替代：绝对上限防止“峰值本身失控”，相对约束防止“随结果数线性增长”。
var (
	heapAllocBudget = resourceBudget{label: "HeapAlloc", peakCap: 256 << 20, relFactor: 2, relSlack: 48 << 20}
	heapSysBudget   = resourceBudget{label: "HeapSys", peakCap: 384 << 20, relFactor: 2, relSlack: 64 << 20}
	sysBudget       = resourceBudget{label: "Sys", peakCap: 512 << 20, relFactor: 2, relSlack: 96 << 20}
	// goroutines/FD 是计数类指标，不能按字节展示；总峰值上限压在 64（实测 50 万条链路的峰值是 23/22），
	// 相对增量上限作为“随规模增长”的补充约束。
	goroutineBudget = resourceBudget{label: "goroutines", peakCap: 64, relFactor: 2, relSlack: 20, plain: true}
	fdBudget        = resourceBudget{label: "fds", peakCap: 64, relFactor: 2, relSlack: 20, plain: true}
)

// readMemSnapshot 读取一次进程级资源读数，不触发 GC（保证峰值真实）。
func readMemSnapshot() runtimeSnapshot {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return runtimeSnapshot{
		HeapAlloc:  stats.HeapAlloc,
		HeapSys:    stats.HeapSys,
		Sys:        stats.Sys,
		Goroutines: runtime.NumGoroutine(),
		FDs:        countOpenFDsQuiet(),
	}
}

// peakSampler 在后台周期采样资源并只保留峰值。
type peakSampler struct {
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	mu      sync.Mutex
	peak    runtimeSnapshot
	samples int
}

// startPeakSampler 立即采一次基线读数，然后启动后台采样 goroutine。
func startPeakSampler(interval time.Duration) *peakSampler {
	s := &peakSampler{stopCh: make(chan struct{})}
	s.observe(readMemSnapshot())
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.observe(readMemSnapshot())
			}
		}
	}()
	return s
}

// observe 在锁内累积峰值；FD 读数不可用时（-1）不参与比较。
func (s *peakSampler) observe(snapshot runtimeSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples++
	if snapshot.HeapAlloc > s.peak.HeapAlloc {
		s.peak.HeapAlloc = snapshot.HeapAlloc
	}
	if snapshot.HeapSys > s.peak.HeapSys {
		s.peak.HeapSys = snapshot.HeapSys
	}
	if snapshot.Sys > s.peak.Sys {
		s.peak.Sys = snapshot.Sys
	}
	if snapshot.Goroutines > s.peak.Goroutines {
		s.peak.Goroutines = snapshot.Goroutines
	}
	if snapshot.FDs > s.peak.FDs {
		s.peak.FDs = snapshot.FDs
	}
}

// sampledPeak 是停止采样后的结果：峰值快照与采样次数。
type sampledPeak struct {
	peak    runtimeSnapshot
	samples int
}

// stop 幂等停止采样并等待 goroutine 退出；重复调用返回同一份峰值。
func (s *peakSampler) stop() sampledPeak {
	s.stopOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return sampledPeak{peak: s.peak, samples: s.samples}
}

// resourceBudget 描述单个指标的两条独立约束（绝对总峰值 + 相对基线增量）。
type resourceBudget struct {
	label     string
	peakCap   int64   // 总峰值的绝对上限（不是增量）
	relFactor float64 // 增量相对基线的倍数
	relSlack  int64   // 增量在倍数之外的固定余量
	plain     bool    // 计数类指标按数字展示，其余按字节
}

// deltaLimit 返回相对基线的增量上限。
func (b resourceBudget) deltaLimit(baseline int64) int64 {
	if baseline <= 0 {
		return b.relSlack
	}
	return int64(float64(baseline)*b.relFactor) + b.relSlack
}

// assertPeaks 分别断言“总峰值 ≤ 绝对上限”和“增量 ≤ 相对基线上限”，返回增量供日志汇总。
// 所有失败信息与日志都明确区分“总峰值”和“增量”，不会把增量当成绝对值。
func (b resourceBudget) assertPeaks(t *testing.T, peak, baseline uint64) int64 {
	t.Helper()
	delta := deltaOf(peak, baseline)
	if int64(peak) > b.peakCap {
		t.Fatalf("%s 总峰值 %s 超过绝对上限 %s（基线 %s）",
			b.label, b.format(int64(peak)), b.format(b.peakCap), b.format(int64(baseline)))
	}
	limit := b.deltaLimit(int64(baseline))
	if delta > limit {
		t.Fatalf("%s 相对基线增量 +%s 超过增量上限 %s（=%2.1f×基线 %s + %s；总峰值 %s，绝对上限 %s）",
			b.label, b.format(delta), b.format(limit), b.relFactor, b.format(int64(baseline)),
			b.format(b.relSlack), b.format(int64(peak)), b.format(b.peakCap))
	}
	return delta
}

// format 按指标类型展示数值。
func (b resourceBudget) format(value int64) string {
	if b.plain {
		return fmt.Sprintf("%d", value)
	}
	return humanBytes(value)
}

// deltaOf 返回峰值相对基线的增量；峰值低于基线时按 0 计。
func deltaOf(peak, baseline uint64) int64 {
	if peak <= baseline {
		return 0
	}
	return int64(peak - baseline)
}

// resourcePeaks 汇总一次执行的峰值与增量，便于用例统一打印。
type resourcePeaks struct {
	base    runtimeSnapshot
	peak    runtimeSnapshot
	samples int
}

// measurePeaks 停止采样器后逐项做双约束断言，并打印“总峰值 + 增量 + 两条上限”，返回峰值汇总。
// minSamples > 0 时还会断言运行期样本数不少于该下界：峰值断言必须建立在足够的运行期读数上。
func measurePeaks(t *testing.T, label string, sampler *peakSampler, baseline runtimeSnapshot, minSamples int) resourcePeaks {
	t.Helper()
	sampled := sampler.stop()
	if sampled.samples < 2 {
		t.Fatalf("%s 只采到 %d 次样本：至少需要启动基线 + 一次运行期读数", label, sampled.samples)
	}
	if minSamples > 0 && sampled.samples < minSamples {
		t.Fatalf("%s 运行期只采到 %d 次样本，少于最少样本数 %d（采样周期 %s）：峰值断言缺少足够的运行期证据",
			label, sampled.samples, minSamples, resourceSampleInterval)
	}
	peaks := resourcePeaks{base: baseline, peak: sampled.peak, samples: sampled.samples}
	heapDelta := heapAllocBudget.assertPeaks(t, sampled.peak.HeapAlloc, baseline.HeapAlloc)
	heapSysDelta := heapSysBudget.assertPeaks(t, sampled.peak.HeapSys, baseline.HeapSys)
	sysDelta := sysBudget.assertPeaks(t, sampled.peak.Sys, baseline.Sys)
	goroutineDelta := goroutineBudget.assertPeaks(t, u64(sampled.peak.Goroutines), u64(baseline.Goroutines))
	fdDelta := fdBudget.assertPeaks(t, u64(sampled.peak.FDs), u64(baseline.FDs))
	t.Logf("%s 运行期峰值（%d 次采样，最少要求 %d 次）：总峰值 %s；相对基线增量 +HeapAlloc=%s +HeapSys=%s +Sys=%s +goroutines=%d +fds=%d",
		label, sampled.samples, minSamples, sampled.peak.String(),
		humanBytes(heapDelta), humanBytes(heapSysDelta), humanBytes(sysDelta), goroutineDelta, fdDelta)
	t.Logf("%s 双约束：总峰值绝对上限 HeapAlloc=%s HeapSys=%s Sys=%s goroutines=%d fds=%d；"+
		"相对增量上限=%2.1f×基线+固定余量（失败时逐项报出）",
		label, heapAllocBudget.format(heapAllocBudget.peakCap), heapSysBudget.format(heapSysBudget.peakCap),
		sysBudget.format(sysBudget.peakCap), goroutineBudget.peakCap, fdBudget.peakCap, heapAllocBudget.relFactor)
	return peaks
}

// minSamplesFor 按实际耗时推导“足够运行期样本”的下界：
// 采样周期是 20ms，正常情况下样本数约为 耗时/周期；这里取 1/3 作为下界以留出调度抖动余量，
// 且不低于 10，确保 50 万链路不会在“几乎没采到运行期读数”的情况下通过峰值断言。
func minSamplesFor(elapsed time.Duration) int {
	want := int(elapsed / (3 * resourceSampleInterval))
	if want < 10 {
		want = 10
	}
	return want
}

// u64 把可能为 -1 的整数指标转换为无符号值：负值按 0 处理（指标缺失不参与比较）。
func u64(value int) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

// assertStreamingWithoutFullSlice 断言峰值不随总结果数线性接近全量驻留规模：
// 若链路退化为“收集全部结果后再写库”，光结果切片就会达到 results×256B，
// 因此 HeapAlloc 增量必须显著低于该规模（不足其一半），Sys 增量也不得超过该规模。
//
// -race 构建把规模降到 20 目标 × 200 端口（4000 条），此时全量驻留估算只有 1 MiB，
// 与竞态检测器自身的固定开销无关，故线性增长断言只在容量档（50 万条）执行，
// 并在报告里明确标注档位差异。
func assertStreamingWithoutFullSlice(t *testing.T, results int, peaks resourcePeaks) {
	t.Helper()
	fullSet := int64(results) * resultFootprintBytes
	heapDelta := deltaOf(peaks.peak.HeapAlloc, peaks.base.HeapAlloc)
	sysDelta := deltaOf(peaks.peak.Sys, peaks.base.Sys)
	if raceDetectorEnabled {
		t.Logf("race 构建已降档到 %d 条结果：全量驻留估算 %s（峰值 HeapAlloc 增量 %s / Sys 增量 %s），"+
			"不适用线性增长断言；50 万条的线性断言由容量档执行", results, humanBytes(fullSet), humanBytes(heapDelta), humanBytes(sysDelta))
		return
	}
	heapGuard := fullSet / 2
	if heapDelta >= heapGuard {
		t.Fatalf("HeapAlloc 峰值增量 %s 已达到全量驻留估算 %s 的一半（%s）：%d 条结果链路疑似退化为全量收集后写库",
			humanBytes(heapDelta), humanBytes(fullSet), humanBytes(heapGuard), results)
	}
	if sysDelta >= fullSet {
		t.Fatalf("Sys 峰值增量 %s 已达到全量驻留估算 %s：%d 条结果链路的内存占用随结果数线性增长",
			humanBytes(sysDelta), humanBytes(fullSet), results)
	}
	t.Logf("流式证据（%d 条结果）：全量驻留估算 %s；HeapAlloc 峰值增量 %s（< %s），Sys 峰值增量 %s（< %s）",
		results, humanBytes(fullSet), humanBytes(heapDelta), humanBytes(heapGuard),
		humanBytes(sysDelta), humanBytes(fullSet))
}
