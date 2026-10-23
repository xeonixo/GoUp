package monitor

import (
	"context"
	"testing"
	"time"
)

func downSnapshot(remindMinutes int, lastAlert *time.Time) Snapshot {
	return Snapshot{
		Monitor:    Monitor{ID: 7, Name: "api", RemindEveryMinutes: remindMinutes, LastAlertAt: lastAlert, NotifyOnRecovery: true},
		LastResult: &Result{Status: StatusDown},
	}
}

func TestReminderSentAfterInterval(t *testing.T) {
	now := time.Now().UTC()
	last := now.Add(-61 * time.Minute)
	store := &runnerTestStore{outageStart: now.Add(-135 * time.Minute)}
	var captured []Transition
	d := testDispatcher(store, notifierFunc(func(tr Transition) { captured = append(captured, tr) }))
	d.now = func() time.Time { return now }

	d.ProcessResult(context.Background(), downSnapshot(60, &last), Result{MonitorID: 7, Status: StatusDown, CheckedAt: now, Message: "timeout"})
	if len(captured) != 1 {
		t.Fatalf("notifications = %d, want 1 reminder", len(captured))
	}
	tr := captured[0]
	if !tr.Reminder || tr.Current != StatusDown || tr.Previous != StatusDown {
		t.Fatalf("not a down reminder: %+v", tr)
	}
	if tr.OutageDuration != 135*time.Minute {
		t.Fatalf("outage duration = %v, want 2h15m", tr.OutageDuration)
	}
	if len(store.lastAlerts) != 1 || store.lastAlerts[0] == nil || !store.lastAlerts[0].Equal(now) {
		t.Fatalf("last alert not persisted at send time: %v", store.lastAlerts)
	}
}

func TestReminderNotDueYetOrOff(t *testing.T) {
	now := time.Now().UTC()
	recent := now.Add(-59 * time.Minute)
	old := now.Add(-5 * time.Hour)
	for _, tc := range []struct {
		name   string
		remind int
		last   *time.Time
	}{
		{"interval not elapsed (restart keeps the persisted timestamp)", 60, &recent},
		{"reminders off", 0, &old},
		{"down never announced", 60, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &runnerTestStore{}
			notifier := &countingNotifier{}
			d := testDispatcher(store, notifier)
			d.now = func() time.Time { return now }
			d.ProcessResult(context.Background(), downSnapshot(tc.remind, tc.last), Result{MonitorID: 7, Status: StatusDown, CheckedAt: now})
			if notifier.calls != 0 {
				t.Fatalf("notified %d times", notifier.calls)
			}
		})
	}
}

func TestReminderRepeatsEveryIntervalMeasuredFromLastAlert(t *testing.T) {
	now := time.Now().UTC()
	store := &runnerTestStore{}
	notifier := &countingNotifier{}
	d := testDispatcher(store, notifier)
	last := now.Add(-30 * time.Minute)
	for i := 0; i < 3; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		d.now = func() time.Time { return at }
		d.ProcessResult(context.Background(), downSnapshot(30, &last), Result{MonitorID: 7, Status: StatusDown, CheckedAt: at})
		if i == 0 && notifier.calls != 1 {
			t.Fatalf("first check: calls = %d", notifier.calls)
		}
		// The persisted timestamp now equals the first reminder.
		if len(store.lastAlerts) > 0 {
			l := *store.lastAlerts[len(store.lastAlerts)-1]
			last = l
		}
	}
	if notifier.calls != 1 {
		t.Fatalf("reminders = %d, want exactly 1 within one interval", notifier.calls)
	}
}

func TestReminderSuppressedWhileMutedOrInMaintenance(t *testing.T) {
	now := time.Now().UTC()
	last := now.Add(-3 * time.Hour)

	store := &runnerTestStore{}
	notifier := &countingNotifier{}
	d := testDispatcher(store, notifier)
	d.now = func() time.Time { return now }
	until := now.Add(time.Hour)
	snap := downSnapshot(60, &last)
	snap.Monitor.MutedUntil = &until
	d.ProcessResult(context.Background(), snap, Result{MonitorID: 7, Status: StatusDown, CheckedAt: now})
	if notifier.calls != 0 {
		t.Fatalf("muted monitor reminded")
	}

	store = &runnerTestStore{inMaintenance: true}
	notifier = &countingNotifier{}
	d = testDispatcher(store, notifier)
	d.now = func() time.Time { return now }
	d.ProcessResult(context.Background(), downSnapshot(60, &last), Result{MonitorID: 7, Status: StatusDown, CheckedAt: now})
	if notifier.calls != 0 {
		t.Fatalf("monitor in maintenance reminded")
	}
}

func TestReminderStopsOnRecovery(t *testing.T) {
	now := time.Now().UTC()
	last := now.Add(-3 * time.Hour)
	store := &runnerTestStore{}
	notifier := &countingNotifier{}
	d := testDispatcher(store, notifier)
	d.now = func() time.Time { return now }
	d.ProcessResult(context.Background(), downSnapshot(60, &last), Result{MonitorID: 7, Status: StatusUp, CheckedAt: now})
	if len(store.lastAlerts) != 1 || store.lastAlerts[0] != nil {
		t.Fatalf("last alert not cleared on recovery: %v", store.lastAlerts)
	}
	if notifier.calls != 1 { // the recovery itself, not a reminder
		t.Fatalf("calls = %d", notifier.calls)
	}
}

func TestDownTransitionStartsReminderSeries(t *testing.T) {
	now := time.Now().UTC()
	store := &runnerTestStore{}
	d := testDispatcher(store, &countingNotifier{})
	d.now = func() time.Time { return now }
	snap := Snapshot{Monitor: Monitor{ID: 7, RemindEveryMinutes: 15}, LastResult: &Result{Status: StatusUp}}
	d.ProcessResult(context.Background(), snap, Result{MonitorID: 7, Status: StatusDown, CheckedAt: now})
	if len(store.lastAlerts) != 1 || store.lastAlerts[0] == nil {
		t.Fatalf("announced down alert must persist last_alert_at: %v", store.lastAlerts)
	}
}

func TestFailedReminderIsQueuedAndStaleOnesDropped(t *testing.T) {
	now := time.Now().UTC()
	last := now.Add(-2 * time.Hour)
	store := &runnerTestStore{}
	d := testDispatcher(store, &failingNotifier{})
	d.now = func() time.Time { return now }
	d.ProcessResult(context.Background(), downSnapshot(60, &last), Result{MonitorID: 7, Status: StatusDown, CheckedAt: now})
	if len(store.enqueued) != 1 || !store.enqueued[0].Transition.Reminder {
		t.Fatalf("reminder retry not queued: %+v", store.enqueued)
	}

	// Retry for a monitor that is now muted / has reminders off / recovered is dropped.
	until := now.Add(time.Hour)
	for i, snap := range []Snapshot{
		{Monitor: Monitor{ID: 7, RemindEveryMinutes: 60, MutedUntil: &until}, LastResult: &Result{Status: StatusDown}},
		{Monitor: Monitor{ID: 7, RemindEveryMinutes: 0}, LastResult: &Result{Status: StatusDown}},
		{Monitor: Monitor{ID: 7, RemindEveryMinutes: 60}, LastResult: &Result{Status: StatusUp}},
	} {
		store.snapshots = map[int64]Snapshot{7: snap}
		notifier := &countingNotifier{}
		d := testDispatcher(store, notifier)
		d.now = func() time.Time { return now }
		d.dispatchRetry(context.Background(), NotificationRetry{
			ID: int64(100 + i), EndpointID: 1, EventType: "status_transition", MaxAttempts: 3,
			Transition: Transition{Monitor: Monitor{ID: 7}, Previous: StatusDown, Current: StatusDown, Reminder: true},
		})
		if notifier.calls != 0 {
			t.Fatalf("case %d: stale reminder was sent", i)
		}
	}
	if len(store.superseded) != 3 {
		t.Fatalf("superseded = %v, want 3", store.superseded)
	}
}
