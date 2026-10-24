package monitor

import (
	"context"
	"testing"
	"time"
)

func TestHeartbeatCheckerBoundaries(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	checker := HeartbeatChecker{now: func() time.Time { return now }}
	ago := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	base := Monitor{ID: 1, Interval: time.Hour, Timeout: 5 * time.Minute, CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour)}

	cases := []struct {
		name   string
		mutate func(m *Monitor)
		want   Status
	}{
		{"fresh ping", func(m *Monitor) { m.LastHeartbeatAt = ago(time.Minute) }, StatusUp},
		{"exactly at deadline", func(m *Monitor) { m.LastHeartbeatAt = ago(65 * time.Minute) }, StatusUp},
		{"one second past deadline", func(m *Monitor) { m.LastHeartbeatAt = ago(65*time.Minute + time.Second) }, StatusDown},
		{"zero grace at period", func(m *Monitor) { m.Timeout = 0; m.LastHeartbeatAt = ago(time.Hour) }, StatusUp},
		{"zero grace past period", func(m *Monitor) { m.Timeout = 0; m.LastHeartbeatAt = ago(time.Hour + time.Second) }, StatusDown},
		{"job reported failure", func(m *Monitor) { m.LastHeartbeatAt = ago(time.Minute); m.LastHeartbeatFailed = true }, StatusDown},
		{"never pinged, young monitor", func(m *Monitor) { m.CreatedAt, m.UpdatedAt = now.Add(-30*time.Minute), now.Add(-30*time.Minute) }, StatusUnknown},
		{"never pinged, at deadline", func(m *Monitor) { m.CreatedAt, m.UpdatedAt = now.Add(-65*time.Minute), now.Add(-65*time.Minute) }, StatusUnknown},
		{"never pinged, past deadline", func(m *Monitor) {
			m.CreatedAt, m.UpdatedAt = now.Add(-65*time.Minute-time.Second), now.Add(-65*time.Minute-time.Second)
		}, StatusDown},
		{"never pinged, recently edited", func(m *Monitor) { m.UpdatedAt = now.Add(-time.Minute) }, StatusUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item := base
			tc.mutate(&item)
			got := checker.Check(context.Background(), item)
			if got.Status != tc.want {
				t.Fatalf("status = %s (%s), want %s", got.Status, got.Message, tc.want)
			}
			if got.MonitorID != 1 || !got.CheckedAt.Equal(now) {
				t.Fatalf("result not filled: %+v", got)
			}
		})
	}
}

func TestHeartbeatScheduleInterval(t *testing.T) {
	if got := (Monitor{Kind: KindHeartbeat, Interval: 24 * time.Hour}).ScheduleInterval(); got != MaxHeartbeatCheckInterval {
		t.Fatalf("daily heartbeat schedule = %s", got)
	}
	if got := (Monitor{Kind: KindHeartbeat, Interval: time.Minute}).ScheduleInterval(); got != time.Minute {
		t.Fatalf("minute heartbeat schedule = %s", got)
	}
	if got := (Monitor{Kind: KindHTTPS, Interval: time.Hour}).ScheduleInterval(); got != time.Hour {
		t.Fatalf("https schedule changed: %s", got)
	}
}

func TestRunnerSchedulesDailyHeartbeatEveryMinute(t *testing.T) {
	r := NewRunner(nil, nil)
	now := time.Date(2026, 5, 1, 12, 0, 30, 0, time.UTC)
	snapshot := Snapshot{Monitor: Monitor{ID: 7, Kind: KindHeartbeat, Enabled: true, ExecutorKind: "local", Interval: 24 * time.Hour}}
	r.dueSnapshots([]Snapshot{snapshot}, now)
	state := r.schedule[7]
	if state == nil || state.interval != MaxHeartbeatCheckInterval {
		t.Fatalf("unexpected schedule state: %+v", state)
	}
	if state.nextDue.After(now.Add(MaxHeartbeatCheckInterval)) {
		t.Fatalf("next check %s is more than a minute away", state.nextDue)
	}
}

func TestHeartbeatCheckerRegisteredInRunner(t *testing.T) {
	r := NewRunner(nil, nil)
	if _, ok := r.checkers[KindHeartbeat]; !ok {
		t.Fatalf("heartbeat checker not registered")
	}
}
