package scheduler

import (
	"context"
	"log"
	"time"

	"easm-platform/internal/store"
)

type Scheduler struct {
	st        *store.Store
	startTask func(taskID int64) (int64, error)
}

func New(st *store.Store, startTask func(taskID int64) (int64, error)) *Scheduler {
	return &Scheduler{st: st, startTask: startTask}
}

func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick()
		}
	}
}

func (s *Scheduler) tick() {
	tasks, err := s.st.ScanTasks()
	if err != nil {
		log.Printf("读取扫描任务失败: %v", err)
		return
	}
	now := time.Now()
	for _, t := range tasks {
		if !t.SchedEnabled {
			continue
		}
		due := latestDue(t, now)
		if now.Before(due) {
			continue
		}
		if t.LastRun != "" {
			if last, err := time.Parse(time.RFC3339, t.LastRun); err == nil && !last.Before(due) {
				continue
			}
		}
		log.Printf("调度触发任务: %s (mode=%s)", t.Name, t.Mode)
		// StartTask 内部已写 last_run；若已有扫描在跑会返回错误，此处记录后跳过
		if _, err := s.startTask(t.ID); err != nil {
			log.Printf("调度启动任务失败: %v", err)
			continue
		}
	}
}

// latestDue 返回当前已经到期的最近一次计划时间。调度器据此补跑停机期间错过的当日/当周任务，
// 并用 last_run 防止同一计划周期重复执行。
func latestDue(t store.ScanTask, now time.Time) time.Time {
	loc := now.Location()
	if t.SchedType == "weekly" {
		weekday := t.Weekday
		if weekday < 0 || weekday > 6 {
			weekday = 0
		}
		daysSince := (int(now.Weekday()) - weekday + 7) % 7
		d := now.AddDate(0, 0, -daysSince)
		due := time.Date(d.Year(), d.Month(), d.Day(), t.Hour, t.Minute, 0, 0, loc)
		return due
	}
	return time.Date(now.Year(), now.Month(), now.Day(), t.Hour, t.Minute, 0, 0, loc)
}
