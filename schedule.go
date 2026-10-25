package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
	_ "time/tzdata"
)

type ScheduleState struct {
	Day         string    `json:"day"`
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
	Error       string    `json:"error"`
}

func due(now time.Time, s Settings, state ScheduleState) bool {
	if !s.AutoUpdate {
		return false
	}
	loc, e := time.LoadLocation(s.Timezone)
	if e != nil {
		return false
	}
	local := now.In(loc)
	target, e := time.ParseInLocation("2006-01-02 15:04", local.Format("2006-01-02")+" "+s.UpdateTime, loc)
	if e != nil || local.Before(target) {
		return false
	}
	if state.Day != local.Format("2006-01-02") {
		return true
	}
	return state.Attempts < 3 && state.Error != "" && now.Sub(state.LastAttempt) >= time.Duration(1<<state.Attempts)*5*time.Minute
}
func (m *Manager) update(ctx context.Context, rules bool) (updateErr error) {
	result, observe := m.observeUpdate(ctx)
	m.buildObserver = observe
	defer func() {
		m.buildObserver = nil
		result.Finished = time.Now()
		result.ActiveRevision = m.currentID()
		result.Applied = result.CandidateRevision != "" && result.ActiveRevision == result.CandidateRevision
		if updateErr != nil {
			result.State = "failed"
			result.Stage = "failed"
			result.Error = updateErr.Error()
			result.Message = "拉取未完成；请查看错误信息和当前版本状态"
		} else {
			result.State = "success"
			result.Stage = "done"
			result.Applied = true
			result.Validation = "passed"
			result.Message = fmt.Sprintf("已读取 %d 个节点，原生校验通过并切换到当前版本", len(result.Nodes))
		}
		m.storeSync(*result)
	}()
	state := ScheduleState{}
	path := filepath.Join(m.Root, "schedule.json")
	_ = readJSON(path, &state)
	now := time.Now()
	s := m.settings()
	loc, _ := time.LoadLocation(s.Timezone)
	day := now.In(loc).Format("2006-01-02")
	if state.Day != day {
		state.Attempts = 0
	}
	state.Day = day
	state.Attempts++
	state.LastAttempt = now
	state.Error = "上次更新中断"
	if e := writeJSON(path, state); e != nil {
		return e
	}
	source, e := m.subscriptionSource()
	var id string
	var report Report
	if e == nil {
		id, report, e = m.build(ctx, true, rules, source, nil, s)
	}
	result.CandidateRevision = id
	if len(report.Nodes) > 0 {
		observe(func() string {
			if result.NodesComplete {
				return "validate"
			}
			return "nodes"
		}(), "节点读取结果已生成", report)
	}
	if e == nil {
		observe("apply", "原生校验通过，正在切换配置并按设置应用", report)
		e = m.activate(ctx, id, false)
		if e == nil {
			m.clearAppliedSubscriptions()
		}
	}
	state.Error = ""
	if e != nil {
		state.Error = e.Error()
	} else {
		state.LastSuccess = time.Now()
	}
	if err := writeJSON(path, state); err != nil && e == nil {
		return err
	}
	return e
}
func (m *Manager) scheduler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s := m.settings()
			state := ScheduleState{}
			_ = readJSON(filepath.Join(m.Root, "schedule.json"), &state)
			if due(now, s, state) {
				_, e := m.startJob("scheduled-update", func(c context.Context) error { return m.update(c, s.RefreshRules) })
				if e != nil {
					continue
				}
				m.audit("scheduled_update", fmt.Sprintf("%s %s", s.Timezone, s.UpdateTime))
			}
		}
	}
}
