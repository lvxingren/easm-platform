package scanner

import (
	"testing"
	"time"
)

// TestCalculateSmartBatchSize 验证智能批次计算功能
func TestCalculateSmartBatchSize(t *testing.T) {
	tests := []struct {
		name           string
		targetCount    int
		portsPerTarget int
		ratePerSecond  int
		timeout        time.Duration
		expectedMin    int
		expectedMax    int
	}{
		{
			name:           "小规模任务（100目标，top-1000端口，60分钟超时）",
			targetCount:    100,
			portsPerTarget: 1000,
			ratePerSecond:  2000,
			timeout:        60 * time.Minute,
			expectedMin:    100, // 不需要拆分
			expectedMax:    100,
		},
		{
			name:           "中等规模任务（500目标，top-1000端口，60分钟超时）",
			targetCount:    500,
			portsPerTarget: 1000,
			ratePerSecond:  2000,
			timeout:        60 * time.Minute,
			expectedMin:    500, // 不需要拆分，单批可完成
			expectedMax:    500,
		},
		{
			name:           "大规模任务（1000目标，全端口65535，60分钟超时）",
			targetCount:    1000,
			portsPerTarget: 65535,
			ratePerSecond:  2000,
			timeout:        60 * time.Minute,
			expectedMin:    50, // 智能计算约 87
			expectedMax:    100,
		},
		{
			name:           "超大规模任务（5000目标，全端口，120分钟超时）",
			targetCount:    5000,
			portsPerTarget: 65535,
			ratePerSecond:  6000,
			timeout:        120 * time.Minute,
			expectedMin:    10,
			expectedMax:    100,
		},
		{
			name:           "边界情况（0目标）",
			targetCount:    0,
			portsPerTarget: 1000,
			ratePerSecond:  2000,
			timeout:        60 * time.Minute,
			expectedMin:    defaultSplitBatchSize,
			expectedMax:    defaultSplitBatchSize,
		},
		{
			name:           "边界情况（0端口）",
			targetCount:    100,
			portsPerTarget: 0,
			ratePerSecond:  2000,
			timeout:        60 * time.Minute,
			expectedMin:    defaultSplitBatchSize,
			expectedMax:    defaultSplitBatchSize,
		},
		{
			name:           "边界情况（0速率）",
			targetCount:    100,
			portsPerTarget: 1000,
			ratePerSecond:  0,
			timeout:        60 * time.Minute,
			expectedMin:    defaultSplitBatchSize,
			expectedMax:    defaultSplitBatchSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateSmartBatchSize(tt.targetCount, tt.portsPerTarget, tt.ratePerSecond, tt.timeout)
			if result < tt.expectedMin || result > tt.expectedMax {
				t.Errorf("CalculateSmartBatchSize(%d, %d, %d, %s) = %d, 期望在 [%d, %d] 范围内",
					tt.targetCount, tt.portsPerTarget, tt.ratePerSecond, tt.timeout, result, tt.expectedMin, tt.expectedMax)
			}
			t.Logf("目标 %d, 端口 %d, 速率 %d/s, 超时 %s -> 推荐批次 %d",
				tt.targetCount, tt.portsPerTarget, tt.ratePerSecond, tt.timeout, result)
		})
	}
}

// TestSmartBatchSizeVsFixedBatchSize 对比智能批次和固定批次的差异
func TestSmartBatchSizeVsFixedBatchSize(t *testing.T) {
	// 场景：471 个目标 × 65535 端口，速率 2000/s，超时 60 分钟
	targetCount := 471
	ports := 65535
	rate := 2000
	timeout := 60 * time.Minute

	smartBatch := CalculateSmartBatchSize(targetCount, ports, rate, timeout)
	fixedBatch := defaultSplitBatchSize

	t.Logf("场景: %d 目标 × %d 端口, 速率 %d/s, 超时 %s", targetCount, ports, rate, timeout)
	t.Logf("智能批次: %d, 固定批次: %d", smartBatch, fixedBatch)
	t.Logf("智能批次拆分为 %d 个子任务, 固定批次拆分为 %d 个子任务",
		(targetCount+smartBatch-1)/smartBatch, (targetCount+fixedBatch-1)/fixedBatch)

	// 智能批次应该根据实际计算，可能大于或小于固定批次
	if smartBatch < 1 {
		t.Errorf("智能批次不应小于 1，实际 %d", smartBatch)
	}
}
