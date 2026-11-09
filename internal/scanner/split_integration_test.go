package scanner

import (
	"encoding/json"
	"testing"

	"easm-platform/internal/store"
)

// TestSplitTaskIntegration 验证拆分任务的完整流程
func TestSplitTaskIntegration(t *testing.T) {
	// 测试 CalculateSplitBatches
	t.Run("CalculateSplitBatches", func(t *testing.T) {
		specs := []store.TargetSpec{
			{Raw: "192.168.1.1"},
			{Raw: "192.168.1.2"},
			{Raw: "192.168.1.3"},
			{Raw: "192.168.1.4"},
			{Raw: "192.168.1.5"},
		}

		// 测试正常拆分
		batches := CalculateSplitBatches(specs, 2)
		if len(batches) != 3 {
			t.Errorf("期望 3 个批次，实际 %d", len(batches))
		}
		if len(batches[0]) != 2 {
			t.Errorf("第 1 批次期望 2 个目标，实际 %d", len(batches[0]))
		}
		if len(batches[1]) != 2 {
			t.Errorf("第 2 批次期望 2 个目标，实际 %d", len(batches[1]))
		}
		if len(batches[2]) != 1 {
			t.Errorf("第 3 批次期望 1 个目标，实际 %d", len(batches[2]))
		}

		// 测试 batchSize 大于目标数
		batches = CalculateSplitBatches(specs, 10)
		if len(batches) != 1 {
			t.Errorf("期望 1 个批次，实际 %d", len(batches))
		}
		if len(batches[0]) != 5 {
			t.Errorf("批次期望 5 个目标，实际 %d", len(batches[0]))
		}

		// 测试空目标
		batches = CalculateSplitBatches([]store.TargetSpec{}, 2)
		if len(batches) != 0 {
			t.Errorf("空目标期望 0 个批次，实际 %d", len(batches))
		}
	})

	// 测试 EncodeSpecsJSON
	t.Run("EncodeSpecsJSON", func(t *testing.T) {
		specs := []store.TargetSpec{
			{Raw: "192.168.1.1"},
			{Raw: "192.168.1.2"},
		}

		jsonStr := EncodeSpecsJSON(specs)
		if jsonStr == "" {
			t.Error("JSON 编码不应为空")
		}

		// 验证可以解码
		var decoded []store.TargetSpec
		if err := json.Unmarshal([]byte(jsonStr), &decoded); err != nil {
			t.Errorf("JSON 解码失败: %v", err)
		}
		if len(decoded) != 2 {
			t.Errorf("期望 2 个目标，实际 %d", len(decoded))
		}
	})

	// 测试 IsTimeoutError
	t.Run("IsTimeoutError", func(t *testing.T) {
		tests := []struct {
			name     string
			err      error
			expected bool
		}{
			{"nil error", nil, false},
			{"timeout error 1", &testError{"容量预检未通过：预估耗时超过任务超时"}, true},
			{"timeout error 2", &testError{"预估耗时 3h，超过任务超时 1h"}, true},
			{"non-timeout error", &testError{"FD 不足"}, false},
			{"other error", &testError{"磁盘空间不足"}, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := IsTimeoutError(tt.err)
				if result != tt.expected {
					t.Errorf("期望 %v，实际 %v", tt.expected, result)
				}
			})
		}
	})
}
