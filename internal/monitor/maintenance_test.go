package monitor

import (
	"context"
	"testing"
	"time"
)

func utc(y int, m time.Month, d, h, min int) time.Time {
	return time.Date(y, m, d, h, min, 0, 0, time.UTC)
}

func TestMaintenanceWindowOccurrences(t *testing.T) {
	once := MaintenanceWindow{StartsAt: utc(2026, 10, 24, 2, 0), EndsAt: utc(2026, 10, 24, 4, 0), Recurrence: RecurrenceNone, Scope: MaintenanceScopeAll}
	daily := MaintenanceWindow{StartsAt: utc(2026, 10, 1, 23, 30), EndsAt: utc(2026, 10, 2, 0, 30), Recurrence: RecurrenceDaily, Scope: MaintenanceScopeAll}
	weekly := MaintenanceWindow{StartsAt: utc(2026, 10, 3, 1, 0), EndsAt: utc(2026, 10, 3, 3, 0), Recurrence: RecurrenceWeekly, Scope: MaintenanceScopeAll}
	monthly := MaintenanceWindow{StartsAt: utc(2026, 1, 31, 10, 0), EndsAt: utc(2026, 1, 31, 12, 0), Recurrence: RecurrenceMonthly, Scope: MaintenanceScopeAll}

	for _, tc := range []struct {
		name   string
		w      MaintenanceWindow
		now    time.Time
		active bool
		ok     bool
		start  time.Time
	}{
		{"once before", once, utc(2026, 10, 24, 1, 59), false, true, utc(2026, 10, 24, 2, 0)},
		{"once at start", once, utc(2026, 10, 24, 2, 0), true, true, utc(2026, 10, 24, 2, 0)},
		{"once last minute", once, utc(2026, 10, 24, 3, 59), true, true, utc(2026, 10, 24, 2, 0)},
		{"once at end is over", once, utc(2026, 10, 24, 4, 0), false, false, time.Time{}},
		{"daily crossing midnight, second day", daily, utc(2026, 10, 5, 0, 10), true, true, utc(2026, 10, 4, 23, 30)},
		{"daily between", daily, utc(2026, 10, 5, 12, 0), false, true, utc(2026, 10, 5, 23, 30)},
		{"daily before first", daily, utc(2026, 9, 30, 23, 45), false, true, utc(2026, 10, 1, 23, 30)},
		{"weekly next week", weekly, utc(2026, 10, 10, 2, 0), true, true, utc(2026, 10, 10, 1, 0)},
		{"weekly other weekday", weekly, utc(2026, 10, 11, 2, 0), false, true, utc(2026, 10, 17, 1, 0)},
		{"monthly clamps Jan 31 to Feb 28", monthly, utc(2026, 2, 28, 11, 0), true, true, utc(2026, 2, 28, 10, 0)},
		{"monthly next after February", monthly, utc(2026, 3, 1, 0, 0), false, true, utc(2026, 3, 31, 10, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, _, active, ok := tc.w.Occurrence(tc.now)
			if active != tc.active || ok != tc.ok || (ok && !start.Equal(tc.start)) {
				t.Fatalf("got start=%v active=%v ok=%v, want start=%v active=%v ok=%v", start, active, ok, tc.start, tc.active, tc.ok)
			}
			if tc.w.ActiveAt(tc.now) != (tc.active && tc.ok) {
				t.Fatalf("ActiveAt mismatch")
			}
		})
	}
}

// With Timezone=UTC, recurrence stays on fixed UTC intervals across a local DST change.
func TestMaintenanceRecurrenceUTCIsDSTSafe(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	start := time.Date(2026, 10, 24, 2, 0, 0, 0, berlin).UTC()
	w := MaintenanceWindow{StartsAt: start, EndsAt: start.Add(time.Hour), Timezone: "UTC", Recurrence: RecurrenceDaily, Scope: MaintenanceScopeAll}
	for day := 0; day < 5; day++ {
		occ := start.Add(time.Duration(day) * 24 * time.Hour)
		if !w.ActiveAt(occ.Add(30 * time.Minute)) {
			t.Fatalf("day %d: not active mid-window", day)
		}
		if w.ActiveAt(occ.Add(90 * time.Minute)) {
			t.Fatalf("day %d: active after window", day)
		}
	}
}

// With an IANA timezone, daily recurrence keeps the same local wall-clock time across DST.
func TestMaintenanceRecurrenceKeepsWallClockInTimezone(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	start := time.Date(2026, 10, 24, 3, 30, 0, 0, berlin)
	w := MaintenanceWindow{
		StartsAt: start.UTC(), EndsAt: start.Add(time.Hour).UTC(),
		Timezone: "Europe/Berlin", Recurrence: RecurrenceDaily, Scope: MaintenanceScopeAll,
	}
	for _, day := range []int{0, 1, 2} {
		local := time.Date(2026, 10, 24+day, 3, 45, 0, 0, berlin)
		occStart, _, active, ok := w.Occurrence(local)
		if !ok || !active {
			t.Fatalf("day %d: expected active occurrence", day)
		}
		gotLocal := occStart.In(berlin)
		if gotLocal.Hour() != 3 || gotLocal.Minute() != 30 {
			t.Fatalf("day %d: wall clock = %s, want 03:30 Berlin", day, gotLocal.Format("15:04 MST"))
		}
	}
}

func TestMaintenanceMonthlyInTimezone(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	start := time.Date(2026, 1, 15, 9, 0, 0, 0, berlin)
	w := MaintenanceWindow{
		StartsAt: start.UTC(), EndsAt: start.Add(2 * time.Hour).UTC(),
		Timezone: "Europe/Berlin", Recurrence: RecurrenceMonthly, Scope: MaintenanceScopeAll,
	}
	now := time.Date(2026, 3, 15, 9, 30, 0, 0, berlin)
	occStart, occEnd, active, ok := w.Occurrence(now)
	if !ok || !active {
		t.Fatalf("expected active March occurrence, got ok=%v active=%v", ok, active)
	}
	local := occStart.In(berlin)
	if local.Year() != 2026 || local.Month() != time.March || local.Day() != 15 || local.Hour() != 9 {
		t.Fatalf("occurrence start = %v", local)
	}
	if !occEnd.Equal(occStart.Add(2 * time.Hour)) {
		t.Fatalf("occurrence end = %v", occEnd)
	}
}

func TestMaintenanceCovers(t *testing.T) {
	all := MaintenanceWindow{Scope: MaintenanceScopeAll}
	mon := MaintenanceWindow{Scope: MaintenanceScopeMonitors, MonitorIDs: []int64{3, 4}}
	grp := MaintenanceWindow{Scope: MaintenanceScopeGroups, Groups: []string{"Web"}}
	if !all.Covers(1, "") || !mon.Covers(3, "x") || mon.Covers(5, "Web") || !grp.Covers(9, " Web ") || grp.Covers(9, "DB") {
		t.Fatal("scope matching wrong")
	}
}

func TestMaintenanceSetUpcoming(t *testing.T) {
	now := utc(2026, 10, 23, 12, 0)
	set := MaintenanceSet{Windows: []MaintenanceWindow{
		{ID: 1, StartsAt: utc(2026, 10, 23, 11, 0), EndsAt: utc(2026, 10, 23, 13, 0), Scope: MaintenanceScopeAll},
		{ID: 2, StartsAt: utc(2026, 10, 25, 1, 0), EndsAt: utc(2026, 10, 25, 2, 0), Scope: MaintenanceScopeAll},
		{ID: 3, StartsAt: utc(2026, 11, 25, 1, 0), EndsAt: utc(2026, 11, 25, 2, 0), Scope: MaintenanceScopeAll},
		{ID: 4, StartsAt: utc(2026, 10, 1, 1, 0), EndsAt: utc(2026, 10, 1, 2, 0), Scope: MaintenanceScopeAll},
		{ID: 5, StartsAt: utc(2026, 10, 1, 5, 0), EndsAt: utc(2026, 10, 1, 6, 0), Recurrence: RecurrenceDaily, Scope: MaintenanceScopeAll},
	}}
	got := set.Upcoming(now, now.Add(7*24*time.Hour))
	ids := []int64{}
	for _, o := range got {
		ids = append(ids, o.Window.ID)
	}
	want := []int64{1, 5, 2}
	if len(ids) != len(want) {
		t.Fatalf("upcoming = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("upcoming = %v, want %v", ids, want)
		}
	}
}

func TestNoNotificationDuringMaintenanceAndSingleSummaryAfter(t *testing.T) {
	now := time.Now().UTC()
	store := &runnerTestStore{inMaintenance: true}
	var captured []Transition
	d := testDispatcher(store, notifierFunc(func(tr Transition) { captured = append(captured, tr) }))
	d.now = func() time.Time { return now }
	up := &Result{Status: StatusUp}

	snap := Snapshot{Monitor: Monitor{ID: 8, NotifyOnRecovery: true}, LastResult: up}
	d.ProcessResult(context.Background(), snap, Result{MonitorID: 8, Status: StatusDown, CheckedAt: now})
	if len(captured) != 0 {
		t.Fatalf("notified during maintenance: %+v", captured)
	}
	if !store.lastResult().InMaintenance {
		t.Fatal("result not flagged in_maintenance")
	}
	if len(store.states) != 0 {
		t.Fatalf("maintenance downtime recorded as state change: %+v", store.states)
	}
	if store.markers[8] != StatusUp {
		t.Fatalf("catch-up marker = %q, want status before the window", store.markers[8])
	}
	if len(store.suppressed) != 0 {
		if store.suppressed[0] != 8 {
			t.Fatalf("suppressed = %v", store.suppressed)
		}
	}

	snap = Snapshot{Monitor: Monitor{ID: 8, MuteStartStatus: StatusUp, NotifyOnRecovery: true}, LastResult: &Result{Status: StatusDown}}
	d.ProcessResult(context.Background(), snap, Result{MonitorID: 8, Status: StatusDown, CheckedAt: now.Add(time.Minute)})
	if len(captured) != 0 || store.markers[8] != StatusUp {
		t.Fatalf("second maintenance check changed state: %+v %v", captured, store.markers)
	}

	store.inMaintenance = false
	d.ProcessResult(context.Background(), snap, Result{MonitorID: 8, Status: StatusDown, CheckedAt: now.Add(time.Hour)})
	if len(captured) != 1 || !captured[0].CatchUp || captured[0].Previous != StatusUp || captured[0].Current != StatusDown {
		t.Fatalf("summary after maintenance wrong: %+v", captured)
	}
	if len(store.cleared) != 1 {
		t.Fatalf("marker not cleared")
	}
}

func TestNoSummaryWhenStatusUnchangedAfterMaintenance(t *testing.T) {
	now := time.Now().UTC()
	store := &runnerTestStore{}
	notifier := &countingNotifier{}
	d := testDispatcher(store, notifier)
	d.now = func() time.Time { return now }
	snap := Snapshot{Monitor: Monitor{ID: 8, MuteStartStatus: StatusUp, NotifyOnRecovery: true}, LastResult: &Result{Status: StatusDown}}
	d.ProcessResult(context.Background(), snap, Result{MonitorID: 8, Status: StatusUp, CheckedAt: now})
	if notifier.calls != 0 {
		t.Fatalf("calls = %d, want 0", notifier.calls)
	}
	if len(store.cleared) != 1 {
		t.Fatal("marker must be cleared")
	}
}

func TestRecoveryInsideMaintenanceStillResolvesState(t *testing.T) {
	now := time.Now().UTC()
	store := &runnerTestStore{inMaintenance: true}
	d := testDispatcher(store, &countingNotifier{})
	d.now = func() time.Time { return now }
	snap := Snapshot{Monitor: Monitor{ID: 8}, LastResult: &Result{Status: StatusDown}}
	d.ProcessResult(context.Background(), snap, Result{MonitorID: 8, Status: StatusUp, CheckedAt: now})
	if len(store.states) != 1 || store.states[0].Status != StatusUp {
		t.Fatalf("recovery inside maintenance must still be recorded: %+v", store.states)
	}
}
