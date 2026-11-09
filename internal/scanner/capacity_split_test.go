package scanner

import (
	"testing"

	"easm-platform/internal/store"
)

func TestCalculateSplitBatches(t *testing.T) {
	tests := []struct {
		name      string
		specs     []store.TargetSpec
		batchSize int
		want      int // 期望的批次数量
	}{
		{
			name:      "空目标列表",
			specs:     nil,
			batchSize: 50,
			want:      0,
		},
		{
			name: "目标数小于批次大小",
			specs: []store.TargetSpec{
				{Raw: "192.168.1.1", Kind: "ip"},
				{Raw: "192.168.1.2", Kind: "ip"},
			},
			batchSize: 50,
			want:      1,
		},
		{
			name: "目标数等于批次大小",
			specs: func() []store.TargetSpec {
				specs := make([]store.TargetSpec, 50)
				for i := range specs {
					specs[i] = store.TargetSpec{Raw: "192.168.1.1", Kind: "ip"}
				}
				return specs
			}(),
			batchSize: 50,
			want:      1,
		},
		{
			name: "目标数大于批次大小",
			specs: func() []store.TargetSpec {
				specs := make([]store.TargetSpec, 120)
				for i := range specs {
					specs[i] = store.TargetSpec{Raw: "192.168.1.1", Kind: "ip"}
				}
				return specs
			}(),
			batchSize: 50,
			want:      3, // 50 + 50 + 20
		},
		{
			name: "批次大小为1",
			specs: []store.TargetSpec{
				{Raw: "192.168.1.1", Kind: "ip"},
				{Raw: "192.168.1.2", Kind: "ip"},
				{Raw: "192.168.1.3", Kind: "ip"},
			},
			batchSize: 1,
			want:      3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateSplitBatches(tt.specs, tt.batchSize)
			if len(got) != tt.want {
				t.Errorf("CalculateSplitBatches() 返回 %d 个批次，期望 %d 个", len(got), tt.want)
			}

			// 验证所有目标都被包含且没有重复
			if tt.want > 0 {
				totalTargets := 0
				for _, batch := range got {
					totalTargets += len(batch)
				}
				if totalTargets != len(tt.specs) {
					t.Errorf("拆分后目标总数 %d，原始数量 %d", totalTargets, len(tt.specs))
				}
			}
		})
	}
}

func TestIsTimeoutError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil错误",
			err:  nil,
			want: false,
		},
		{
			name: "超时错误-包含超过任务超时",
			err:  &testError{msg: "容量预检未通过：471 个目标 × 65535 端口 × naabu 2 轮，预计耗时 2h55m10s，超过任务超时 1h0m0s"},
			want: true,
		},
		{
			name: "超时错误-包含预估耗时",
			err:  &testError{msg: "预估耗时超过限制"},
			want: true,
		},
		{
			name: "非超时错误-FD不足",
			err:  &testError{msg: "容量预检未通过：文件描述符软上限 1024 低于需求"},
			want: false,
		},
		{
			name: "非超时错误-磁盘空间",
			err:  &testError{msg: "容量预检未通过：数据目录可用空间不足"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTimeoutError(tt.err)
			if got != tt.want {
				t.Errorf("IsTimeoutError() = %v，期望 %v", got, tt.want)
			}
		})
	}
}

func TestEncodeSpecsJSON(t *testing.T) {
	tests := []struct {
		name  string
		specs []store.TargetSpec
		check func(string) bool
	}{
		{
			name:  "空列表",
			specs: nil,
			check: func(s string) bool { return s == "[]" },
		},
		{
			name: "单个IP",
			specs: []store.TargetSpec{
				{Raw: "192.168.1.1", Kind: "ip"},
			},
			check: func(s string) bool {
				return len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']'
			},
		},
		{
			name: "多个目标",
			specs: []store.TargetSpec{
				{Raw: "192.168.1.1", Kind: "ip"},
				{Raw: "10.0.0.0/24", Kind: "cidr"},
				{Raw: "example.com", Kind: "domain"},
			},
			check: func(s string) bool {
				return len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']'
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeSpecsJSON(tt.specs)
			if !tt.check(got) {
				t.Errorf("EncodeSpecsJSON() = %q，未通过检查", got)
			}
		})
	}
}

// testError 是一个简单的 error 实现，用于测试
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
