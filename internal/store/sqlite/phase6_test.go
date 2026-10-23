package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"goup/internal/monitor"
)

func TestMaintenanceChecksStayOutOfUptimeCounts(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	at := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	steps := []struct {
		status      monitor.Status
		maintenance bool
	}{
		{monitor.StatusUp, false},
		{monitor.StatusDown, true},
		{monitor.StatusDown, true},
		{monitor.StatusUp, true},
		{monitor.StatusDown, false},
	}
	for i, step := range steps {
		if err := st.SaveMonitorResult(ctx, monitor.Result{
			MonitorID: monitorID, Status: step.status, CheckedAt: at.Add(time.Duration(i) * time.Minute),
			Latency: 40 * time.Millisecond, InMaintenance: step.maintenance,
		}); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	got := readRollup(t, st, monitorID)
	if got.TotalChecks != 5 || got.MaintenanceChecks != 3 || got.UpChecks != 1 || got.DownChecks != 1 || got.UnknownChecks != 0 {
		t.Fatalf("rollup total/maint/up/down/unknown = %d/%d/%d/%d/%d", got.TotalChecks, got.MaintenanceChecks, got.UpChecks, got.DownChecks, got.UnknownChecks)
	}
	if got.EffectiveChecks() != 2 {
		t.Fatalf("effective checks = %d, want 2", got.EffectiveChecks())
	}
	if got.LatencySumMS != 40 || got.LatencyMaxMS != 40 {
		t.Fatalf("maintenance latency leaked into stats: %+v", got)
	}
	var flagged int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM monitor_results WHERE in_maintenance = 1`).Scan(&flagged); err != nil || flagged != 3 {
		t.Fatalf("in_maintenance rows = %d err=%v", flagged, err)
	}
}

func TestRollupBackfillRespectsMaintenanceFlag(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	at := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	for i, inMaintenance := range []int{0, 1, 1, 0} {
		status := "down"
		if i == 0 {
			status = "up"
		}
		if _, err := st.db.ExecContext(ctx, `INSERT INTO monitor_results (monitor_id, checked_at, status, latency_ms, in_maintenance) VALUES (?, ?, ?, 25, ?)`,
			monitorID, at.Add(time.Duration(i)*time.Minute), status, inMaintenance); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM monitor_hourly_rollups`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM app_settings WHERE key = ?`, hourlyRollupBackfillSettingKey); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ensureHourlyRollupBackfill(ctx, at); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	got := readRollup(t, st, monitorID)
	if got.TotalChecks != 4 || got.MaintenanceChecks != 2 || got.UpChecks != 1 || got.DownChecks != 1 || got.EffectiveChecks() != 2 {
		t.Fatalf("backfilled rollup = %+v", got)
	}
}

func TestMaintenanceWindowCRUDAndTargets(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	start := time.Date(2026, 7, 1, 2, 0, 0, 0, time.UTC)

	id, err := st.CreateMaintenanceWindow(ctx, monitor.MaintenanceWindow{
		Title: "  DB upgrade ", Description: "Postgres 17", StartsAt: start, EndsAt: start.Add(2 * time.Hour),
		Scope: monitor.MaintenanceScopeMonitors, MonitorIDs: []int64{monitorID, monitorID}, Recurrence: monitor.RecurrenceWeekly, CreatedBy: 7,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := st.GetMaintenanceWindow(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "DB upgrade" || got.Recurrence != monitor.RecurrenceWeekly || len(got.MonitorIDs) != 1 || got.MonitorIDs[0] != monitorID || got.CreatedBy != 7 || !got.StartsAt.Equal(start) {
		t.Fatalf("stored window = %+v", got)
	}

	got.Scope = monitor.MaintenanceScopeGroups
	got.Groups = []string{"Web"}
	got.Recurrence = monitor.RecurrenceNone
	if err := st.UpdateMaintenanceWindow(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = st.GetMaintenanceWindow(ctx, id)
	if got.Scope != monitor.MaintenanceScopeGroups || len(got.MonitorIDs) != 0 || len(got.Groups) != 1 || got.Groups[0] != "Web" {
		t.Fatalf("updated window = %+v", got)
	}
	if err := st.UpdateMaintenanceWindow(ctx, monitor.MaintenanceWindow{ID: 999, Title: "x", StartsAt: start, EndsAt: start.Add(time.Hour), Scope: monitor.MaintenanceScopeAll}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("update unknown = %v", err)
	}

	if err := st.DeleteMaintenanceWindow(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := st.DeleteMaintenanceWindow(ctx, id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second delete = %v", err)
	}
	var targets int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM maintenance_window_targets`).Scan(&targets); err != nil || targets != 0 {
		t.Fatalf("orphan targets = %d err=%v", targets, err)
	}
}

func TestMaintenanceWindowValidation(t *testing.T) {
	start := time.Date(2026, 7, 1, 2, 0, 0, 0, time.UTC)
	base := func() monitor.MaintenanceWindow {
		return monitor.MaintenanceWindow{Title: "x", StartsAt: start, EndsAt: start.Add(time.Hour), Recurrence: monitor.RecurrenceNone, Scope: monitor.MaintenanceScopeAll}
	}
	for name, tc := range map[string]struct {
		mutate func(*monitor.MaintenanceWindow)
		want   error
	}{
		"ok":            {func(*monitor.MaintenanceWindow) {}, nil},
		"no title":      {func(w *monitor.MaintenanceWindow) { w.Title = "  " }, ErrMaintenanceTitle},
		"end = start":   {func(w *monitor.MaintenanceWindow) { w.EndsAt = w.StartsAt }, ErrMaintenanceOrder},
		"end < start":   {func(w *monitor.MaintenanceWindow) { w.EndsAt = w.StartsAt.Add(-time.Hour) }, ErrMaintenanceOrder},
		"missing times": {func(w *monitor.MaintenanceWindow) { w.StartsAt = time.Time{} }, ErrMaintenanceTimes},
		"daily > 24h": {func(w *monitor.MaintenanceWindow) {
			w.Recurrence = monitor.RecurrenceDaily
			w.EndsAt = w.StartsAt.Add(25 * time.Hour)
		}, ErrMaintenanceTooLong},
		"monitors none": {func(w *monitor.MaintenanceWindow) { w.Scope = monitor.MaintenanceScopeMonitors }, ErrMaintenanceTargets},
		"groups none":   {func(w *monitor.MaintenanceWindow) { w.Scope = monitor.MaintenanceScopeGroups }, ErrMaintenanceTargets},
	} {
		w := base()
		tc.mutate(&w)
		if err := ValidateMaintenanceWindow(w); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

func TestActiveMaintenanceCacheAndInvalidation(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	now := time.Now().UTC()
	if st.ActiveMaintenance(ctx, monitorID, "", now) {
		t.Fatal("no window yet")
	}
	id, err := st.CreateMaintenanceWindow(ctx, monitor.MaintenanceWindow{
		Title: "now", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), Scope: monitor.MaintenanceScopeMonitors, MonitorIDs: []int64{monitorID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !st.ActiveMaintenance(ctx, monitorID, "", now) {
		t.Fatal("create must invalidate the cache")
	}
	if st.ActiveMaintenance(ctx, monitorID+1, "", now) {
		t.Fatal("other monitor must not be covered")
	}
	if err := st.DeleteMaintenanceWindow(ctx, id); err != nil {
		t.Fatal(err)
	}
	if st.ActiveMaintenance(ctx, monitorID, "", now) {
		t.Fatal("delete must invalidate the cache")
	}
}

func TestReminderPersistence(t *testing.T) {
	ctx := context.Background()
	st, _ := openDataQualityStore(t)
	monitorID, err := st.CreateMonitor(ctx, CreateMonitorParams{Name: "p", Kind: monitor.KindTCP, Target: "127.0.0.1:1", Interval: time.Minute, Timeout: time.Second, Enabled: true, TLSMode: monitor.TLSModeNone, RemindEveryMinutes: 60})
	if err != nil {
		t.Fatal(err)
	}
	alert := time.Now().UTC().Add(-45 * time.Minute).Truncate(time.Second)
	if err := st.SetMonitorLastAlert(ctx, monitorID, &alert); err != nil {
		t.Fatal(err)
	}
	snap, err := st.GetMonitorSnapshot(ctx, monitorID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Monitor.RemindEveryMinutes != 60 || snap.Monitor.LastAlertAt == nil || !snap.Monitor.LastAlertAt.Equal(alert) {
		t.Fatalf("persisted reminder state = %d %v", snap.Monitor.RemindEveryMinutes, snap.Monitor.LastAlertAt)
	}
	if err := st.SetMonitorLastAlert(ctx, monitorID, nil); err != nil {
		t.Fatal(err)
	}
	snap, _ = st.GetMonitorSnapshot(ctx, monitorID)
	if snap.Monitor.LastAlertAt != nil {
		t.Fatal("last alert not cleared")
	}
}

func TestRemindEveryValidationAndOutageStart(t *testing.T) {
	ctx := context.Background()
	st, _ := openDataQualityStore(t)
	params := CreateMonitorParams{Name: "r", Kind: monitor.KindTCP, Target: "127.0.0.1:1", Interval: time.Minute, Timeout: time.Second, Enabled: true, TLSMode: monitor.TLSModeNone}
	params.RemindEveryMinutes = 45
	if _, err := st.CreateMonitor(ctx, params); err == nil {
		t.Fatal("45 minutes must be rejected")
	}
	params.RemindEveryMinutes = 240
	id, err := st.CreateMonitor(ctx, params)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	snap, _ := st.GetMonitorSnapshot(ctx, id)
	if snap.Monitor.RemindEveryMinutes != 240 {
		t.Fatalf("remind every = %d", snap.Monitor.RemindEveryMinutes)
	}

	base := time.Now().Add(-time.Hour) // keeps the monotonic reading, like real check results
	for i, status := range []monitor.Status{monitor.StatusDown, monitor.StatusUp, monitor.StatusDown, monitor.StatusDown} {
		if err := st.SaveMonitorResult(ctx, monitor.Result{MonitorID: id, Status: status, CheckedAt: base.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	start, ok, err := st.CurrentOutageStart(ctx, id)
	if err != nil || !ok || start.Sub(base.Add(2*time.Minute)).Abs() > time.Millisecond {
		t.Fatalf("outage start = %v ok=%v err=%v, want %v", start, ok, err, base.Add(2*time.Minute))
	}
}

func TestReminderRetryRoundTripAndDedupe(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	endpointID := insertMaintenanceNotificationEndpoint(t, ctx, st)
	enqueue := func(d time.Duration) {
		t.Helper()
		if err := st.EnqueueNotificationRetry(ctx, monitor.NotificationRetryParams{
			MonitorID: monitorID, EndpointID: endpointID, EventType: "status_transition", MaxAttempts: 3,
			NextAttemptAt: time.Now().Add(-time.Minute),
			Transition: monitor.Transition{Monitor: monitor.Monitor{ID: monitorID}, Previous: monitor.StatusDown, Current: monitor.StatusDown,
				CheckedAt: time.Now(), Reminder: true, OutageDuration: d},
		}); err != nil {
			t.Fatal(err)
		}
	}
	enqueue(30 * time.Minute)
	enqueue(2*time.Hour + 15*time.Minute)
	due, err := st.ListDueNotificationRetries(ctx, time.Now(), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due = %d err=%v, want only the newest reminder", len(due), err)
	}
	if !due[0].Transition.Reminder || due[0].Transition.OutageDuration != 2*time.Hour+15*time.Minute {
		t.Fatalf("reminder fields lost: %+v", due[0].Transition)
	}
}
