package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

type failingNotifier struct {
	countingNotifier
}

func (n *failingNotifier) Notify(context.Context, Transition) error {
	n.mu.Lock()
	n.calls++
	n.mu.Unlock()
	return errors.New("boom")
}

func testDispatcher(store Store, notifiers ...Notifier) *Dispatcher {
	return NewDispatcher(slog.New(slog.NewTextHandler(io.Discard, nil)), store, notifiers...)
}

func TestDispatchRetrySupersededWhenMonitorStatusChanged(t *testing.T) {
	store := &runnerTestStore{snapshots: map[int64]Snapshot{
		1: {Monitor: Monitor{ID: 1}, LastResult: &Result{Status: StatusUp}},
		2: {Monitor: Monitor{ID: 2}, LastResult: &Result{Status: StatusDown}},
	}}
	notifier := &countingNotifier{}
	d := testDispatcher(store, notifier)

	// The queued alert says "down" but the monitor is up again: it must not be sent.
	d.dispatchRetry(context.Background(), NotificationRetry{
		ID: 10, EndpointID: 1, EventType: "status_transition", MaxAttempts: 3,
		Transition: Transition{Monitor: Monitor{ID: 1}, Previous: StatusUp, Current: StatusDown},
	})
	if notifier.calls != 0 || len(store.superseded) != 1 || store.superseded[0] != 10 {
		t.Fatalf("stale retry: calls=%d superseded=%v", notifier.calls, store.superseded)
	}
	if len(store.retryUpdates) != 0 {
		t.Fatalf("superseded retry must not be counted as an attempt: %v", store.retryUpdates)
	}

	// Still down: the retry is sent.
	d.dispatchRetry(context.Background(), NotificationRetry{
		ID: 11, EndpointID: 1, EventType: "status_transition", MaxAttempts: 3,
		Transition: Transition{Monitor: Monitor{ID: 2}, Previous: StatusUp, Current: StatusDown},
	})
	if notifier.calls != 1 || len(store.superseded) != 1 {
		t.Fatalf("current retry: calls=%d superseded=%v", notifier.calls, store.superseded)
	}

	// Deleted monitor: superseded as well.
	d.dispatchRetry(context.Background(), NotificationRetry{
		ID: 12, EndpointID: 1, EventType: "status_transition", MaxAttempts: 3,
		Transition: Transition{Monitor: Monitor{ID: 99}, Previous: StatusUp, Current: StatusDown},
	})
	if notifier.calls != 1 || len(store.superseded) != 2 {
		t.Fatalf("deleted monitor retry: calls=%d superseded=%v", notifier.calls, store.superseded)
	}
}

func TestMutedTransitionIsRecordedAsSuppressed(t *testing.T) {
	store := &runnerTestStore{}
	notifier := &countingNotifier{}
	d := testDispatcher(store, notifier)
	until := time.Now().Add(time.Hour)
	snapshot := Snapshot{
		Monitor:    Monitor{ID: 5, MutedUntil: &until, MuteStartStatus: StatusUp},
		LastResult: &Result{Status: StatusUp},
	}
	d.ProcessResult(context.Background(), snapshot, Result{MonitorID: 5, Status: StatusDown, CheckedAt: time.Now()})
	if notifier.calls != 0 {
		t.Fatalf("muted monitor notified %d times", notifier.calls)
	}
	if len(store.suppressed) != 1 || store.suppressed[0] != 5 {
		t.Fatalf("suppressed events = %v, want one for monitor 5", store.suppressed)
	}
	if len(store.cleared) != 0 {
		t.Fatalf("catch-up marker must survive an active mute")
	}
}

func TestMuteCatchUpNotification(t *testing.T) {
	expired := time.Now().Add(-time.Minute)
	for _, tc := range []struct {
		name      string
		mutedUntl *time.Time
		start     Status
		last      Status
		current   Status
		notifyRec bool
		wantCalls int
		wantClear bool
	}{
		{"down since mute start", &expired, StatusUp, StatusDown, StatusDown, true, 1, true},
		{"unmuted manually", nil, StatusUp, StatusDown, StatusDown, true, 1, true},
		{"unchanged status", &expired, StatusUp, StatusUp, StatusUp, true, 0, true},
		{"recovered during mute", &expired, StatusDown, StatusDown, StatusUp, true, 1, true},
		{"recovered, recovery notices off", &expired, StatusDown, StatusDown, StatusUp, false, 0, true},
		{"no pending marker, no transition", &expired, "", StatusUp, StatusUp, true, 0, false},
		{"regular transition replaced by catch-up", nil, StatusDown, StatusUp, StatusDown, true, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &runnerTestStore{}
			notifier := &countingNotifier{}
			d := testDispatcher(store, notifier)
			snapshot := Snapshot{
				Monitor:    Monitor{ID: 6, MutedUntil: tc.mutedUntl, MuteStartStatus: tc.start, NotifyOnRecovery: tc.notifyRec},
				LastResult: &Result{Status: tc.last},
			}
			d.ProcessResult(context.Background(), snapshot, Result{MonitorID: 6, Status: tc.current, CheckedAt: time.Now()})
			if notifier.calls != tc.wantCalls {
				t.Fatalf("notifier calls = %d, want %d", notifier.calls, tc.wantCalls)
			}
			if got := len(store.cleared) == 1; got != tc.wantClear {
				t.Fatalf("marker cleared = %v, want %v", got, tc.wantClear)
			}
		})
	}
}

func TestMuteCatchUpTransitionContent(t *testing.T) {
	store := &runnerTestStore{}
	var captured Transition
	d := testDispatcher(store, notifierFunc(func(tr Transition) { captured = tr }))
	snapshot := Snapshot{
		Monitor:    Monitor{ID: 6, MuteStartStatus: StatusUp, NotifyOnRecovery: true},
		LastResult: &Result{Status: StatusDown},
	}
	d.ProcessResult(context.Background(), snapshot, Result{MonitorID: 6, Status: StatusDown, CheckedAt: time.Now(), Message: "still down"})
	if !captured.CatchUp || captured.Previous != StatusUp || captured.Current != StatusDown {
		t.Fatalf("unexpected catch-up transition: %+v", captured)
	}
}

type notifierFunc func(Transition)

func (f notifierFunc) Enabled() bool     { return true }
func (f notifierFunc) EndpointID() int64 { return 1 }
func (f notifierFunc) EventType() string { return "status_transition" }
func (f notifierFunc) Notify(_ context.Context, tr Transition) error {
	f(tr)
	return nil
}

func TestBuildConfirmedTransition(t *testing.T) {
	now := time.Now()
	monitor := Monitor{ID: 1, ConfirmAfter: 3, NotifyOnRecovery: true}
	result := func(status Status) Result { return Result{Status: status, CheckedAt: now} }
	snap := func(last Status) Snapshot {
		return Snapshot{Monitor: monitor, LastResult: &Result{Status: last}}
	}

	for _, tc := range []struct {
		name         string
		last         Status
		current      Status
		statuses     []Status // newest first, including current
		wantOK       bool
		wantSettled  bool
		wantPrevious Status
	}{
		{"first failure waits", StatusUp, StatusDown, []Status{StatusDown, StatusUp, StatusUp, StatusUp}, false, false, ""},
		{"second failure waits", StatusDown, StatusDown, []Status{StatusDown, StatusDown, StatusUp, StatusUp}, false, false, ""},
		{"third failure announces", StatusDown, StatusDown, []Status{StatusDown, StatusDown, StatusDown, StatusUp}, true, true, StatusUp},
		{"fourth failure is old news", StatusDown, StatusDown, []Status{StatusDown, StatusDown, StatusDown, StatusDown}, false, true, ""},
		{"mixed failure states count", StatusDown, StatusDegraded, []Status{StatusDegraded, StatusDown, StatusDown, StatusUp}, true, true, StatusUp},
		{"down becomes degraded after announcement", StatusDown, StatusDegraded, []Status{StatusDegraded, StatusDown, StatusDown, StatusDown}, true, true, StatusDown},
		{"recovery after announced failure", StatusDown, StatusUp, []Status{StatusUp, StatusDown, StatusDown, StatusDown}, true, true, StatusDown},
		{"recovery from unannounced failure is silent", StatusDown, StatusUp, []Status{StatusUp, StatusDown, StatusDown, StatusUp}, false, true, ""},
		{"blip never announced", StatusUp, StatusUp, []Status{StatusUp, StatusUp, StatusUp, StatusUp}, false, true, ""},
		{"leaving unknown is announced", StatusUnknown, StatusUp, []Status{StatusUp, StatusUnknown}, true, true, StatusUnknown},
		{"no baseline before streak", StatusDown, StatusDown, []Status{StatusDown, StatusDown, StatusDown}, false, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transition, ok, settled := buildConfirmedTransition(snap(tc.last), result(tc.current), tc.statuses, 3)
			if ok != tc.wantOK || settled != tc.wantSettled {
				t.Fatalf("ok=%v settled=%v, want ok=%v settled=%v", ok, settled, tc.wantOK, tc.wantSettled)
			}
			if ok && (transition.Previous != tc.wantPrevious || transition.Current != tc.current) {
				t.Fatalf("transition %s -> %s, want %s -> %s", transition.Previous, transition.Current, tc.wantPrevious, tc.current)
			}
		})
	}
}

func TestConfirmAfterOneKeepsImmediateBehaviour(t *testing.T) {
	store := &runnerTestStore{}
	notifier := &countingNotifier{}
	d := testDispatcher(store, notifier)
	snapshot := Snapshot{Monitor: Monitor{ID: 2, ConfirmAfter: 1}, LastResult: &Result{Status: StatusUp}}
	d.ProcessResult(context.Background(), snapshot, Result{MonitorID: 2, Status: StatusDown, CheckedAt: time.Now()})
	if notifier.calls != 1 {
		t.Fatalf("notifier calls = %d, want 1", notifier.calls)
	}
}

func TestConfirmAfterDelaysAlertUntilStreakReached(t *testing.T) {
	store := &runnerTestStore{}
	notifier := &countingNotifier{}
	d := testDispatcher(store, notifier)
	monitor := Monitor{ID: 2, ConfirmAfter: 2, NotifyOnRecovery: true}

	// First failure: statuses[0] is the freshly saved result.
	store.recentStatuses = []Status{StatusDown, StatusUp, StatusUp}
	d.ProcessResult(context.Background(), Snapshot{Monitor: monitor, LastResult: &Result{Status: StatusUp}}, Result{MonitorID: 2, Status: StatusDown, CheckedAt: time.Now()})
	if notifier.calls != 0 {
		t.Fatalf("first failure notified")
	}
	// Second consecutive failure reaches the threshold.
	store.recentStatuses = []Status{StatusDown, StatusDown, StatusUp}
	d.ProcessResult(context.Background(), Snapshot{Monitor: monitor, LastResult: &Result{Status: StatusDown}}, Result{MonitorID: 2, Status: StatusDown, CheckedAt: time.Now()})
	if notifier.calls != 1 {
		t.Fatalf("notifier calls = %d, want 1 after threshold", notifier.calls)
	}
}

func TestFailedDeliveryIsQueuedForRetry(t *testing.T) {
	store := &runnerTestStore{}
	notifier := &failingNotifier{}
	d := testDispatcher(store, notifier)
	snapshot := Snapshot{Monitor: Monitor{ID: 3}, LastResult: &Result{Status: StatusUp}}
	d.ProcessResult(context.Background(), snapshot, Result{MonitorID: 3, Status: StatusDown, CheckedAt: time.Now()})
	if len(store.enqueued) != 1 || store.enqueued[0].MonitorID != 3 {
		t.Fatalf("enqueued retries = %+v", store.enqueued)
	}
}
