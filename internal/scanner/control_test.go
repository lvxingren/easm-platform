package scanner

import (
	"sync"
	"testing"
	"time"
)

// TestExecutionControlNotifyIsBroadcast 验证控制变更通知是真广播而不是容量为 1 的共享通道：
// 所有在通知前取得通道的等待者都会同时被唤醒（每个活跃批次都感知 Pause/Resume/Stop）。
func TestExecutionControlNotifyIsBroadcast(t *testing.T) {
	runner := &Runner{running: true, scanID: 7, active: newExecutionControl()}

	const waiters = 8
	channels := make([]<-chan struct{}, waiters)
	for index := range channels {
		channels[index] = runner.changedChan(7)
		if channels[index] == nil {
			t.Fatal("活跃执行应返回非空通知通道")
		}
	}

	var wg sync.WaitGroup
	awoken := make([]bool, waiters)
	for index, channel := range channels {
		wg.Add(1)
		go func(index int, channel <-chan struct{}) {
			defer wg.Done()
			select {
			case <-channel:
				awoken[index] = true
			case <-time.After(2 * time.Second):
			}
		}(index, channel)
	}

	runner.mu.Lock()
	runner.active.notify()
	runner.mu.Unlock()
	wg.Wait()

	for index, ok := range awoken {
		if !ok {
			t.Fatalf("等待者 %d 未被唤醒：通知仍是容量 1 的共享通道，无法广播给所有活跃批次", index)
		}
	}
}

// TestExecutionControlGenerationAdvances 验证每次通知都会推进控制版本并建立新一代通道，
// 旧代通道关闭、新代通道保持打开，等待者必须重新订阅。
func TestExecutionControlGenerationAdvances(t *testing.T) {
	runner := &Runner{running: true, scanID: 9, active: newExecutionControl()}
	first := runner.changedChan(9)

	runner.mu.Lock()
	before := runner.active.version
	runner.active.notify()
	runner.active.notify()
	after := runner.active.version
	runner.mu.Unlock()
	if after != before+2 {
		t.Fatalf("控制版本未单调递增：%d -> %d", before, after)
	}
	select {
	case <-first:
	default:
		t.Fatal("旧代通道应已关闭（广播）")
	}

	current := runner.changedChan(9)
	select {
	case <-current:
		t.Fatal("新一代通道不应处于关闭状态")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestChangedChanRejectsStaleExecution 验证扫描已结束或 ID 不匹配时不返回残留通道，
// 等待者据此可以立即停止等待而不是永久阻塞。
func TestChangedChanRejectsStaleExecution(t *testing.T) {
	runner := &Runner{running: true, scanID: 3, active: newExecutionControl()}
	if channel := runner.changedChan(4); channel != nil {
		t.Fatal("扫描 ID 不匹配时应返回 nil")
	}
	runner.setRunning(false)
	if channel := runner.changedChan(3); channel != nil {
		t.Fatal("执行结束后应返回 nil")
	}
}

// TestControlWatchSnapshotDeliversResumeWithoutLoss 验证“状态 + 代际通道”同锁快照的关键不变量：
// Resume 发生在快照之后时，它关闭的正是快照返回的通道，等待者不会丢失这次唤醒；
// 快照之后的新一代通道保持打开，必须再次订阅。
func TestControlWatchSnapshotDeliversResumeWithoutLoss(t *testing.T) {
	runner := &Runner{running: true, scanID: 21, active: newExecutionControl()}
	runner.active.paused = true
	runner.active.pauseStarted = time.Now()
	runner.active.deadline = time.Now().Add(time.Hour)

	paused, stopped, deadline, changed, ok := runner.controlWatch(21)
	if !ok || !paused || stopped {
		t.Fatalf("快照应返回 paused=true stopped=false ok=true，实际 paused=%v stopped=%v ok=%v", paused, stopped, ok)
	}
	if changed == nil {
		t.Fatal("快照必须同时返回非空代际通道（否则等待者只能依赖轮询）")
	}
	if deadline.IsZero() {
		t.Fatal("快照必须同时返回有效截止时间")
	}

	// 模拟 Resume 恰好发生在快照返回之后、等待者进入 select 之前。
	runner.mu.Lock()
	runner.active.deadline = runner.active.deadline.Add(time.Minute)
	runner.active.paused = false
	runner.active.pauseStarted = time.Time{}
	runner.active.notify()
	runner.mu.Unlock()

	select {
	case <-changed:
		// 期望：Resume 关闭的正是快照返回的这一代通道。
	default:
		t.Fatal("Resume 丢失：快照返回的通道未被关闭，等待者只能等 300ms 巡检才恢复")
	}

	paused, stopped, nextDeadline, nextChanged, ok := runner.controlWatch(21)
	if !ok || paused || stopped {
		t.Fatalf("新快照应看到已恢复且未终止，实际 paused=%v stopped=%v ok=%v", paused, stopped, ok)
	}
	if !nextDeadline.After(deadline) {
		t.Fatalf("恢复后截止时间应顺延：旧=%v 新=%v", deadline, nextDeadline)
	}
	select {
	case <-nextChanged:
		t.Fatal("新一代通道不应处于关闭状态")
	default:
	}
}
