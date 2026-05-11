package monitor

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

type runnerTestStore struct {
	results []Result
	states  []Result
}

func (s *runnerTestStore) ListMonitorSnapshots(context.Context) ([]Snapshot, error) {
	return nil, nil
}

func (s *runnerTestStore) SaveMonitorResult(_ context.Context, result Result) error {
	s.results = append(s.results, result)
	return nil
}

func (s *runnerTestStore) RecordMonitorState(_ context.Context, monitorID int64, status Status, message string, checkedAt time.Time) error {
	s.states = append(s.states, Result{MonitorID: monitorID, Status: status, Message: message, CheckedAt: checkedAt})
	return nil
}

func (s *runnerTestStore) RecordNotificationEvent(context.Context, int64, int64, string, *time.Time, string) error {
	return nil
}

func (s *runnerTestStore) EnqueueNotificationRetry(context.Context, NotificationRetryParams) error {
	return nil
}

func (s *runnerTestStore) ListDueNotificationRetries(context.Context, time.Time, int) ([]NotificationRetry, error) {
	return nil, nil
}

func (s *runnerTestStore) UpdateNotificationRetry(context.Context, int64, bool, string, time.Time, bool) error {
	return nil
}

type sequenceChecker struct {
	results []Result
}

func (c *sequenceChecker) Check(context.Context, Monitor) Result {
	if len(c.results) == 0 {
		return Result{Status: StatusUp}
	}
	result := c.results[0]
	c.results = c.results[1:]
	return result
}

func TestMonitorPhaseOffsetCascadesMonitorsAcrossInterval(t *testing.T) {
	interval := time.Minute
	seen := make(map[time.Duration]struct{})
	for id := int64(1); id <= 20; id++ {
		offset := MonitorPhaseOffset(id, interval)
		if offset < 0 || offset >= interval {
			t.Fatalf("offset for monitor %d = %s, want within %s", id, offset, interval)
		}
		seen[offset] = struct{}{}
	}
	if len(seen) < 10 {
		t.Fatalf("got only %d unique phase offsets for 20 monitors", len(seen))
	}
}

func TestRunnerSchedulesFixedSlotsWithoutCompletionDrift(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := NewRunner(logger, &runnerTestStore{})
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	snapshot := Snapshot{
		Monitor: Monitor{ID: 7, Enabled: true, Interval: time.Minute},
	}

	firstDue := r.dueSnapshots([]Snapshot{snapshot}, now)
	if len(firstDue) > 1 {
		t.Fatalf("got %d due snapshots, want at most 1", len(firstDue))
	}

	state := r.schedule[snapshot.Monitor.ID]
	if state == nil {
		t.Fatalf("expected schedule state")
	}
	state.nextDue = now
	due := r.dueSnapshots([]Snapshot{snapshot}, now)
	if len(due) != 1 {
		t.Fatalf("got %d due snapshots, want 1", len(due))
	}
	if !due[0].dueAt.Equal(now) {
		t.Fatalf("dueAt = %s, want %s", due[0].dueAt, now)
	}

	state.nextDue = due[0].dueAt.Add(snapshot.Monitor.Interval)
	later := now.Add(4 * time.Second)
	if due := r.dueSnapshots([]Snapshot{snapshot}, later); len(due) != 0 {
		t.Fatalf("got %d due snapshots while next fixed slot is still in the future", len(due))
	}
}

func TestRunnerSkipsSlotWhenPreviousCheckStillRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := NewRunner(logger, &runnerTestStore{})
	now := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	snapshot := Snapshot{Monitor: Monitor{ID: 11, Enabled: true, Interval: time.Minute}}
	r.schedule[snapshot.Monitor.ID] = &monitorScheduleState{
		nextDue:  now,
		inFlight: true,
	}

	due := r.dueSnapshots([]Snapshot{snapshot}, now.Add(61*time.Second))
	if len(due) != 0 {
		t.Fatalf("got %d due snapshots while previous check is in flight", len(due))
	}
	nextDue := r.schedule[snapshot.Monitor.ID].nextDue
	if !nextDue.After(now.Add(61 * time.Second)) {
		t.Fatalf("nextDue = %s, want after overloaded time", nextDue)
	}
}

func TestRunnerUsesScheduledAtForRetryResult(t *testing.T) {
	store := &runnerTestStore{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := NewRunner(logger, store)
	checker := &sequenceChecker{results: []Result{
		{Status: StatusDown, CheckedAt: time.Date(2026, 5, 11, 10, 0, 5, 0, time.UTC), Message: "down"},
		{Status: StatusUp, CheckedAt: time.Date(2026, 5, 11, 10, 0, 7, 0, time.UTC), Message: "up"},
	}}
	r.checkers[KindHTTPS] = checker
	scheduledAt := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	snapshot := Snapshot{
		Monitor: Monitor{ID: 3, Kind: KindHTTPS, Enabled: true, Timeout: time.Second, RetryCount: 1},
	}

	r.runSnapshot(context.Background(), snapshot, scheduledAt)

	if len(store.results) != 1 {
		t.Fatalf("saved %d results, want 1", len(store.results))
	}
	if !store.results[0].CheckedAt.Equal(scheduledAt) {
		t.Fatalf("saved CheckedAt = %s, want scheduled slot %s", store.results[0].CheckedAt, scheduledAt)
	}
	if store.results[0].Status != StatusUp {
		t.Fatalf("saved status = %s, want retry status up", store.results[0].Status)
	}
}
