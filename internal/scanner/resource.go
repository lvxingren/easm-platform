package scanner

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"easm-platform/internal/engine"
	"easm-platform/internal/store"

	"github.com/shirou/gopsutil/v4/process"
)

type resourceSample struct {
	cpu       float64
	memoryRSS int64
}

type resourceSampler interface {
	Sample() (resourceSample, error)
}

type processSampler struct {
	process *process.Process
}

func (s *processSampler) Sample() (resourceSample, error) {
	cpu, err := s.process.Percent(0)
	if err != nil {
		return resourceSample{}, err
	}
	memory, err := s.process.MemoryInfo()
	if err != nil {
		return resourceSample{}, err
	}
	return resourceSample{cpu: cpu, memoryRSS: int64(memory.RSS)}, nil
}

type resourceMonitor struct {
	scanID    int64
	store     *store.Store
	engine    *engine.Engine
	sampler   resourceSampler
	cpuLimit  float64
	memoryMax int64
	duration  time.Duration
	highSince time.Time
	alerted   bool
}

func newResourceMonitor(scanID, pid int64, settings NaabuSettings, st *store.Store, eng *engine.Engine) *resourceMonitor {
	cpu, _ := strconv.ParseFloat(settings.ResourceCPU, 64)
	memoryMB, _ := strconv.ParseInt(settings.ResourceMemory, 10, 64)
	durationSeconds, _ := strconv.ParseInt(settings.ResourceDuration, 10, 64)
	monitor := &resourceMonitor{
		scanID: scanID, store: st, engine: eng,
		cpuLimit: cpu, memoryMax: memoryMB * 1024 * 1024,
		duration: time.Duration(durationSeconds) * time.Second,
	}
	if !settings.ResourceMonitor {
		return monitor
	}
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		log.Printf("扫描 %d 初始化 naabu 资源监测失败: %v", scanID, err)
		return monitor
	}
	monitor.sampler = &processSampler{process: proc}
	return monitor
}

// Sample 更新当前值和峰值；只有持续超阈值才告警，持续高占用期间不重复轰炸。
func (m *resourceMonitor) Sample(now time.Time) {
	if m == nil || m.sampler == nil {
		return
	}
	sample, err := m.sampler.Sample()
	if err != nil {
		log.Printf("扫描 %d 采样 naabu 资源失败: %v", m.scanID, err)
		return
	}
	if err := m.store.UpdateScanResource(m.scanID, sample.cpu, sample.memoryRSS); err != nil {
		log.Printf("扫描 %d 保存 naabu 资源采样失败: %v", m.scanID, err)
	}

	high := sample.cpu >= m.cpuLimit || sample.memoryRSS >= m.memoryMax
	if !high {
		m.highSince = time.Time{}
		m.alerted = false
		return
	}
	if m.highSince.IsZero() {
		m.highSince = now
		return
	}
	if m.alerted || now.Sub(m.highSince) < m.duration {
		return
	}
	m.alerted = true
	message := fmt.Sprintf("naabu 资源占用持续超阈值：当前 CPU %.1f%%（阈值 %.0f%%），RSS %.1f MiB（阈值 %d MiB），持续至少 %s；仅告警，任务继续运行",
		sample.cpu, m.cpuLimit, float64(sample.memoryRSS)/(1024*1024), m.memoryMax/(1024*1024), m.duration)
	if err := m.store.AddScanEvent(m.scanID, "warn", "resource", message); err != nil {
		log.Printf("扫描 %d 保存资源告警失败: %v", m.scanID, err)
	}
	// 资源告警仅记事件与日志，飞书推送统一并入任务结束汇总，避免过程中多条通知。
	log.Printf("扫描 %d 资源告警: %s", m.scanID, message)
}
