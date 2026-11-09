package scanner

import (
	"bufio"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
)

// TestReadBoundedLineKeepsNormalAndOversizedLinesSeparate 验证单行硬上限的核心语义：
//   - 未超限的行原样返回；
//   - 超限行被整体丢弃（不返回前缀，避免把截断内容当成结构化数据）；
//   - 丢弃后已消费到行尾，后续正常行仍能完整读出；
//   - 恰好等于上限的行属于合法行（只丢弃超过上限的行）。
func TestReadBoundedLineKeepsNormalAndOversizedLinesSeparate(t *testing.T) {
	const limit = 32
	payload := "first\n" + strings.Repeat("x", limit+1) + "\n" + strings.Repeat("y", limit) + "\nlast\n"
	reader := bufio.NewReaderSize(strings.NewReader(payload), 8)

	line, oversized, truncated, err := readBoundedLine(reader, limit)
	if err != nil || oversized || truncated || line != "first" {
		t.Fatalf("首行应完整返回: line=%q oversized=%v truncated=%v err=%v", line, oversized, truncated, err)
	}

	line, oversized, truncated, err = readBoundedLine(reader, limit)
	if err != nil || !oversized || truncated || line != "" {
		t.Fatalf("超限行必须被有界丢弃: line=%q oversized=%v truncated=%v err=%v", line, oversized, truncated, err)
	}

	line, oversized, truncated, err = readBoundedLine(reader, limit)
	if err != nil || oversized || truncated || line != strings.Repeat("y", limit) {
		t.Fatalf("恰好等于上限的行应保留: len=%d oversized=%v truncated=%v err=%v", len(line), oversized, truncated, err)
	}

	line, oversized, truncated, err = readBoundedLine(reader, limit)
	if err != nil || oversized || truncated || line != "last" {
		t.Fatalf("超限行之后的正常行必须可读: line=%q oversized=%v truncated=%v err=%v", line, oversized, truncated, err)
	}

	if _, _, _, err := readBoundedLine(reader, limit); !errors.Is(err, io.EOF) {
		t.Fatalf("流结束应返回 io.EOF，实际 %v", err)
	}
}

// TestReadBoundedLineMarksNewlineFreeTailAsTruncated 验证文件/管道在行中被截断时不会被当成完整行：
// 没有换行结尾的残行必须标记 truncated，由上层按“实时输出不完整”处理。
func TestReadBoundedLineMarksNewlineFreeTailAsTruncated(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader("partial-line-without-newline"), 8)
	_, oversized, truncated, err := readBoundedLine(reader, 1<<10)
	if !truncated || oversized || !errors.Is(err, io.EOF) {
		t.Fatalf("无换行残行应标记 truncated 并返回 io.EOF: truncated=%v oversized=%v err=%v", truncated, oversized, err)
	}

	// 超长且无换行的残行同样只能标记截断，不能把（已丢弃的）内容当作完整行。
	hugeReader := bufio.NewReaderSize(&fillerReader{remaining: 4 << 10, value: 'z'}, 128)
	_, oversized, truncated, err = readBoundedLine(hugeReader, 256)
	if !truncated || !oversized || !errors.Is(err, io.EOF) {
		t.Fatalf("超长无换行残行应标记 truncated+oversized: truncated=%v oversized=%v err=%v", truncated, oversized, err)
	}
}

// TestReadBoundedLineBoundsMemoryForNewlineFreeStream 验证“永不换行的 16 MiB 输出”
// 不会让内存无界增长：读取过程的堆峰值增量必须远小于输入总量。
// 旧实现用 ReadString('\n') 会把整行累积进内存，这里用堆采样直接暴露该回归。
func TestReadBoundedLineBoundsMemoryForNewlineFreeStream(t *testing.T) {
	const streamBytes = 16 << 20
	const allowedGrowth = 4 << 20

	runtime.GC()
	baseline := heapAllocBytes()
	sampler := &heapSamplingReader{
		r: io.MultiReader(&fillerReader{remaining: streamBytes, value: 'z'}, strings.NewReader("\n192.0.2.1:443\n")),
	}
	reader := bufio.NewReaderSize(sampler, 64<<10)

	line, oversized, truncated, err := readBoundedLine(reader, stdoutLineLimit)
	if err != nil || truncated || !oversized || line != "" {
		t.Fatalf("16 MiB 无换行行必须被有界丢弃: len=%d oversized=%v truncated=%v err=%v", len(line), oversized, truncated, err)
	}
	next, nextOversized, nextTruncated, nextErr := readBoundedLine(reader, stdoutLineLimit)
	if nextErr != nil || nextTruncated || nextOversized || next != "192.0.2.1:443" {
		t.Fatalf("丢弃超限行后必须能继续读到下一行: line=%q oversized=%v truncated=%v err=%v", next, nextOversized, nextTruncated, nextErr)
	}

	if sampler.peak > baseline && sampler.peak-baseline > allowedGrowth {
		t.Fatalf("读取 %d 字节无换行输出时堆峰值增长 %d KiB，超过上限 %d KiB：单行上限没有真正约束内存",
			streamBytes, (sampler.peak-baseline)/1024, allowedGrowth/1024)
	}
}

// fillerReader 按需生成重复字节，避免测试自身持有大块输入缓冲。
type fillerReader struct {
	remaining int64
	value     byte
}

func (f *fillerReader) Read(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > f.remaining {
		p = p[:f.remaining]
	}
	for index := range p {
		p[index] = f.value
	}
	f.remaining -= int64(len(p))
	return len(p), nil
}

// heapSamplingReader 在每次底层读取后采样一次堆占用，用于验证有界读取的峰值内存。
type heapSamplingReader struct {
	r    io.Reader
	peak uint64
}

func (h *heapSamplingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if current := heapAllocBytes(); current > h.peak {
		h.peak = current
	}
	return n, err
}

func heapAllocBytes() uint64 {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}
