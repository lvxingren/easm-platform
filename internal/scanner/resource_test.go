package scanner

import (
	"testing"
	"time"

	"easm-platform/internal/config"
	"easm-platform/internal/engine"
	"easm-platform/internal/store"
)

type fakeResourceSampler struct {
	sample resourceSample
}

func (s *fakeResourceSampler) Sample() (resourceSample, error) {
	return s.sample, nil
}

func TestResourceAlertRequiresSustainedUsageAndRearmsAfterRecovery(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scanID, err := st.CreateScan(1, "资源测试", "top")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	sampler := &fakeResourceSampler{sample: resourceSample{cpu: 95, memoryRSS: 128 * 1024 * 1024}}
	monitor := &resourceMonitor{
		scanID: scanID, store: st, engine: engine.New(st, cfg), sampler: sampler,
		cpuLimit: 90, memoryMax: 1024 * 1024 * 1024, duration: 5 * time.Second,
	}
	start := time.Now()
	monitor.Sample(start)
	monitor.Sample(start.Add(3 * time.Second))
	assertEventCount(t, st, scanID, 0)
	monitor.Sample(start.Add(5 * time.Second))
	assertEventCount(t, st, scanID, 1)
	monitor.Sample(start.Add(10 * time.Second))
	assertEventCount(t, st, scanID, 1)

	sampler.sample = resourceSample{cpu: 10, memoryRSS: 128 * 1024 * 1024}
	monitor.Sample(start.Add(11 * time.Second))
	sampler.sample = resourceSample{cpu: 96, memoryRSS: 128 * 1024 * 1024}
	monitor.Sample(start.Add(12 * time.Second))
	monitor.Sample(start.Add(17 * time.Second))
	assertEventCount(t, st, scanID, 2)

	scan, _ := st.Scan(scanID)
	if scan.Status != "running" || scan.MaxCPUPercent != 96 {
		t.Fatalf("资源告警不应改变执行状态，峰值记录错误: %+v", scan)
	}
}

func TestResourceAlertTriggersForMemoryOnly(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scanID, err := st.CreateScan(1, "内存资源测试", "top")
	if err != nil {
		t.Fatal(err)
	}
	sampler := &fakeResourceSampler{sample: resourceSample{cpu: 10, memoryRSS: 128 * 1024 * 1024}}
	monitor := &resourceMonitor{
		scanID: scanID, store: st, engine: engine.New(st, &config.Config{}), sampler: sampler,
		cpuLimit: 90, memoryMax: 64 * 1024 * 1024, duration: 5 * time.Second,
	}
	start := time.Now()
	monitor.Sample(start)
	monitor.Sample(start.Add(4 * time.Second))
	assertEventCount(t, st, scanID, 0)
	monitor.Sample(start.Add(5 * time.Second))
	assertEventCount(t, st, scanID, 1)
	scan, _ := st.Scan(scanID)
	if scan.Status != "running" || scan.MaxMemoryRSS != 128*1024*1024 {
		t.Fatalf("内存告警改变了执行状态或峰值记录错误: %+v", scan)
	}
}

func assertEventCount(t *testing.T, st *store.Store, scanID int64, want int) {
	t.Helper()
	events, err := st.ScanEvents(scanID, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != want {
		t.Fatalf("资源事件数量=%d，期望 %d: %+v", len(events), want, events)
	}
}
