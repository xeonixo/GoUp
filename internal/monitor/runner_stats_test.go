package monitor

import (
	"context"
	"testing"
	"time"
)

func TestRunnerStatsCountersAndWindow(t *testing.T) {
	var s runnerStats
	now := time.Now()

	// Outside the five minute window: must be pruned once newer checks finish.
	s.checkStarted()
	s.checkFinished(now.Add(-10*time.Minute), time.Second)

	s.checkStarted()
	s.checkStarted()
	if snap := s.snapshot(now); snap.Running != 2 {
		t.Fatalf("running = %d, want 2", snap.Running)
	}
	s.checkFinished(now, 100*time.Millisecond)
	s.checkFinished(now, 300*time.Millisecond)

	snap := s.snapshot(now)
	if snap.Running != 0 {
		t.Fatalf("running = %d, want 0", snap.Running)
	}
	if snap.ChecksLast5Min != 2 || snap.AvgCheckDuration != 200*time.Millisecond {
		t.Fatalf("window = %d avg=%s, want 2 / 200ms", snap.ChecksLast5Min, snap.AvgCheckDuration)
	}

	s.setBacklog(-3)
	s.setBacklog(4)
	s.recordLoop(now, 25*time.Millisecond)
	snap = s.snapshot(now)
	if snap.Backlog != 4 || snap.LastLoopDuration != 25*time.Millisecond {
		t.Fatalf("backlog/loop = %d / %s", snap.Backlog, snap.LastLoopDuration)
	}

	later := s.snapshot(now.Add(6 * time.Minute))
	if later.ChecksLast5Min != 0 || later.AvgCheckDuration != 0 {
		t.Fatalf("stale window not pruned: %+v", later)
	}
}

func TestRunnerStatsConcurrentUse(t *testing.T) {
	var s runnerStats
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				s.checkStarted()
				s.checkFinished(time.Now(), time.Millisecond)
				_ = s.snapshot(time.Now())
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if snap := s.snapshot(time.Now()); snap.ChecksLast5Min != 1600 || snap.Running != 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestRunnerStatsAccessorReportsWorkers(t *testing.T) {
	r := NewRunner(nil, nil)
	r.SetWorkers(7)
	if got := r.Stats().Workers; got != 7 {
		t.Fatalf("workers = %d, want 7", got)
	}
}

type retryStatsFakeStore struct {
	Store
	pending int
	oldest  *time.Time
}

func (f retryStatsFakeStore) NotificationRetryQueueStats(context.Context) (int, *time.Time, error) {
	return f.pending, f.oldest, nil
}

func TestDispatcherRetryQueueStats(t *testing.T) {
	at := time.Now().UTC()
	d := &Dispatcher{store: retryStatsFakeStore{pending: 3, oldest: &at}}
	stats, err := d.RetryQueueStats(context.Background())
	if err != nil || stats.Pending != 3 || stats.OldestAttemptAt == nil || !stats.OldestAttemptAt.Equal(at) {
		t.Fatalf("stats = %+v err=%v", stats, err)
	}

	empty := &Dispatcher{store: nil}
	stats, err = empty.RetryQueueStats(context.Background())
	if err != nil || stats.Pending != 0 || stats.OldestAttemptAt != nil {
		t.Fatalf("store without stats = %+v err=%v", stats, err)
	}
}
