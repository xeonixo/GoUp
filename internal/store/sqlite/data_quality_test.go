package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"goup/internal/monitor"
)

func openDataQualityStore(t *testing.T) (*Store, int64) {
	t.Helper()
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, insertMaintenanceMonitor(t, ctx, st)
}

func readRollup(t *testing.T, st *Store, monitorID int64) MonitorHourlyRollup {
	t.Helper()
	items, err := st.ListMonitorHourlyRollupsForMonitorSince(context.Background(), monitorID, time.Unix(0, 0))
	if err != nil || len(items) != 1 {
		t.Fatalf("list rollups: %v (%d items)", err, len(items))
	}
	return items[0]
}

func TestUpsertHourlyRollupIgnoresDownLatency(t *testing.T) {
	ctx := context.Background()
	hour := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		steps []struct {
			status  monitor.Status
			latency int
		}
		wantMin, wantMax, wantSum int
		wantUp, wantDown          int
	}{
		{
			name: "down first then up",
			steps: []struct {
				status  monitor.Status
				latency int
			}{{monitor.StatusDown, 5000}, {monitor.StatusUp, 120}, {monitor.StatusUp, 80}},
			wantMin: 80, wantMax: 120, wantSum: 200, wantUp: 2, wantDown: 1,
		},
		{
			name: "up first then down",
			steps: []struct {
				status  monitor.Status
				latency int
			}{{monitor.StatusUp, 90}, {monitor.StatusDown, 0}, {monitor.StatusUp, 150}},
			wantMin: 90, wantMax: 150, wantSum: 240, wantUp: 2, wantDown: 1,
		},
		{
			name: "degraded counts for latency",
			steps: []struct {
				status  monitor.Status
				latency int
			}{{monitor.StatusDown, 0}, {monitor.StatusDegraded, 700}, {monitor.StatusUp, 200}},
			wantMin: 200, wantMax: 700, wantSum: 900, wantUp: 1, wantDown: 1,
		},
		{
			name: "only down",
			steps: []struct {
				status  monitor.Status
				latency int
			}{{monitor.StatusDown, 4000}, {monitor.StatusDown, 4100}},
			wantMin: 0, wantMax: 0, wantSum: 0, wantUp: 0, wantDown: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, monitorID := openDataQualityStore(t)
			for i, step := range tc.steps {
				if err := upsertHourlyRollup(ctx, st.db, monitorID, hour.Add(time.Duration(i)*time.Minute), step.status, step.latency); err != nil {
					t.Fatalf("upsert: %v", err)
				}
			}
			got := readRollup(t, st, monitorID)
			if got.LatencyMinMS != tc.wantMin || got.LatencyMaxMS != tc.wantMax || got.LatencySumMS != tc.wantSum {
				t.Fatalf("min/max/sum = %d/%d/%d, want %d/%d/%d", got.LatencyMinMS, got.LatencyMaxMS, got.LatencySumMS, tc.wantMin, tc.wantMax, tc.wantSum)
			}
			if got.UpChecks != tc.wantUp || got.DownChecks != tc.wantDown || got.TotalChecks != len(tc.steps) {
				t.Fatalf("counts up/down/total = %d/%d/%d", got.UpChecks, got.DownChecks, got.TotalChecks)
			}
		})
	}
}

func TestUpsertHourlyRollupCountsUnknownSeparately(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	hour := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	for i, status := range []monitor.Status{monitor.StatusUp, monitor.StatusUnknown, monitor.StatusUnknown, monitor.StatusDown} {
		if err := upsertHourlyRollup(ctx, st.db, monitorID, hour.Add(time.Duration(i)*time.Minute), status, 0); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	got := readRollup(t, st, monitorID)
	if got.TotalChecks != 4 || got.UnknownChecks != 2 || got.MaintenanceChecks != 0 {
		t.Fatalf("total/unknown/maintenance = %d/%d/%d", got.TotalChecks, got.UnknownChecks, got.MaintenanceChecks)
	}
	if got.EffectiveChecks() != 2 {
		t.Fatalf("effective checks = %d, want 2 (up + down)", got.EffectiveChecks())
	}
	got.MaintenanceChecks = 1
	if got.EffectiveChecks() != 1 {
		t.Fatalf("maintenance checks must leave the denominator, got %d", got.EffectiveChecks())
	}
}

func TestSaveMonitorResultFeedsRollupUnknown(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	at := time.Now().UTC()
	for i, status := range []monitor.Status{monitor.StatusUp, monitor.StatusUnknown} {
		if err := st.SaveMonitorResult(ctx, monitor.Result{MonitorID: monitorID, Status: status, CheckedAt: at.Add(time.Duration(i) * time.Second), Latency: 50 * time.Millisecond}); err != nil {
			t.Fatalf("save result: %v", err)
		}
	}
	got := readRollup(t, st, monitorID)
	if got.UnknownChecks != 1 || got.EffectiveChecks() != 1 || got.LatencyMinMS != 50 {
		t.Fatalf("unexpected rollup %+v", got)
	}
}

func TestRollupMigrationBackfillsUnknownAndRepairsMinimum(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tenant.db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	monitorID := insertMaintenanceMonitor(t, ctx, st)
	hour := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)

	// Raw results for the hour: one down, two up (the old bug stored min = 0).
	for i, r := range []struct {
		status  monitor.Status
		latency time.Duration
	}{{monitor.StatusDown, 0}, {monitor.StatusUp, 120 * time.Millisecond}, {monitor.StatusUp, 80 * time.Millisecond}} {
		if _, err := st.db.ExecContext(ctx, `INSERT INTO monitor_results (monitor_id, checked_at, status, latency_ms) VALUES (?, ?, ?, ?)`,
			monitorID, hour.Add(time.Duration(i)*time.Minute), string(r.status), r.latency.Milliseconds()); err != nil {
			t.Fatalf("insert raw: %v", err)
		}
	}
	// A second hour whose raw data is already pruned: must stay untouched.
	prunedHour := hour.Add(-48 * time.Hour)
	if _, err := st.db.ExecContext(ctx, `
INSERT INTO monitor_hourly_rollups (monitor_id, hour_bucket, total_checks, up_checks, down_checks, degraded_checks, latency_sum_ms, latency_min_ms, latency_max_ms, first_checked_at, last_checked_at)
VALUES (?, ?, 3, 2, 1, 0, 200, 0, 120, ?, ?), (?, ?, 3, 2, 1, 0, 200, 0, 120, ?, ?)`,
		monitorID, hour, hour, hour, monitorID, prunedHour, prunedHour, prunedHour); err != nil {
		t.Fatalf("insert rollups: %v", err)
	}
	// Pre-migration unknown checks were only part of total_checks.
	if _, err := st.db.ExecContext(ctx, `
INSERT INTO monitor_hourly_rollups (monitor_id, hour_bucket, total_checks, up_checks, down_checks, degraded_checks, latency_sum_ms, latency_min_ms, latency_max_ms, first_checked_at, last_checked_at)
VALUES (?, ?, 5, 2, 1, 0, 100, 50, 50, ?, ?)`, monitorID, hour.Add(-72*time.Hour), hour, hour); err != nil {
		t.Fatalf("insert legacy rollup: %v", err)
	}
	// Simulate a database from before the unknown/maintenance columns.
	if _, err := st.db.ExecContext(ctx, `ALTER TABLE monitor_hourly_rollups DROP COLUMN unknown_checks`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `ALTER TABLE monitor_hourly_rollups DROP COLUMN maintenance_checks`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	if err := st.initSchema(ctx); err != nil {
		t.Fatalf("re-run schema migration: %v", err)
	}

	// Isolate the repair from the (separate) full backfill.
	if err := st.setSetting(ctx, hourlyRollupBackfillSettingKey, "done"); err != nil {
		t.Fatalf("set backfill marker: %v", err)
	}
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	if _, err := st.RunMaintenance(ctx, now); err != nil {
		t.Fatalf("maintenance: %v", err)
	}
	rollups, err := st.ListMonitorHourlyRollupsForMonitorSince(ctx, monitorID, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("list rollups: %v", err)
	}
	byHour := map[time.Time]MonitorHourlyRollup{}
	for _, item := range rollups {
		byHour[item.HourBucket.UTC()] = item
	}
	if got := byHour[hour].LatencyMinMS; got != 80 {
		t.Fatalf("repaired min = %d, want 80", got)
	}
	if got := byHour[prunedHour].LatencyMinMS; got != 0 {
		t.Fatalf("rollup without raw data must stay unchanged, got min %d", got)
	}
	if got := byHour[hour.Add(-72*time.Hour)].UnknownChecks; got != 2 {
		t.Fatalf("legacy unknown_checks = %d, want 2", got)
	}

	// The repair runs once: a later bogus zero must not be touched again.
	if _, err := st.db.ExecContext(ctx, `UPDATE monitor_hourly_rollups SET latency_min_ms = 0`); err != nil {
		t.Fatalf("reset min: %v", err)
	}
	if _, err := st.RunMaintenance(ctx, now.Add(time.Minute)); err != nil {
		t.Fatalf("second maintenance: %v", err)
	}
	rollups, _ = st.ListMonitorHourlyRollupsForMonitorSince(ctx, monitorID, hour.Add(-time.Minute))
	for _, item := range rollups {
		if item.HourBucket.UTC().Equal(hour) && item.LatencyMinMS != 0 {
			t.Fatalf("repair must be guarded by its marker, min = %d", item.LatencyMinMS)
		}
	}
}

func TestConfirmAfterAndMuteStartStatusPersist(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	params := CreateMonitorParams{
		Name: "Web", Kind: monitor.KindHTTPS, Target: "https://example.com", Interval: time.Minute,
		Timeout: 10 * time.Second, Enabled: true, TLSMode: monitor.TLSModeTLS, ConfirmAfter: 3,
	}
	id, err := st.CreateMonitor(ctx, params)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defaultID, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Other", Kind: monitor.KindHTTPS, Target: "https://example.org", Interval: time.Minute,
		Timeout: 10 * time.Second, Enabled: true, TLSMode: monitor.TLSModeTLS,
	})
	if err != nil {
		t.Fatalf("create default: %v", err)
	}
	huge := params
	huge.Name = "Huge"
	huge.ConfirmAfter = 99
	hugeID, err := st.CreateMonitor(ctx, huge)
	if err != nil {
		t.Fatalf("create huge: %v", err)
	}

	get := func(id int64) monitor.Monitor {
		t.Helper()
		snapshot, err := st.GetMonitorSnapshot(ctx, id)
		if err != nil {
			t.Fatalf("get snapshot: %v", err)
		}
		return snapshot.Monitor
	}
	if got := get(id).ConfirmAfter; got != 3 {
		t.Fatalf("confirm_after = %d, want 3", got)
	}
	if got := get(defaultID).ConfirmAfter; got != 1 {
		t.Fatalf("default confirm_after = %d, want 1", got)
	}
	if got := get(hugeID).ConfirmAfter; got != MaxConfirmAfter {
		t.Fatalf("clamped confirm_after = %d, want %d", got, MaxConfirmAfter)
	}
	params.ConfirmAfter = 5
	if err := st.UpdateMonitor(ctx, UpdateMonitorParams{ID: id, CreateMonitorParams: params}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := get(id).ConfirmAfter; got != 5 {
		t.Fatalf("updated confirm_after = %d, want 5", got)
	}

	// Mute remembers the status at mute start; extending keeps it, unmuting leaves a pending marker.
	if err := st.SaveMonitorResult(ctx, monitor.Result{MonitorID: id, Status: monitor.StatusUp, CheckedAt: time.Now().UTC().Add(-time.Minute)}); err != nil {
		t.Fatalf("save result: %v", err)
	}
	until := time.Now().UTC().Add(time.Hour)
	if _, err := st.SetMonitorsMutedUntil(ctx, []int64{id}, &until); err != nil {
		t.Fatalf("mute: %v", err)
	}
	if got := get(id).MuteStartStatus; got != monitor.StatusUp {
		t.Fatalf("mute start status = %q, want up", got)
	}
	if err := st.SaveMonitorResult(ctx, monitor.Result{MonitorID: id, Status: monitor.StatusDown, CheckedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("save result: %v", err)
	}
	later := until.Add(time.Hour)
	if _, err := st.SetMonitorsMutedUntil(ctx, []int64{id}, &later); err != nil {
		t.Fatalf("extend mute: %v", err)
	}
	if got := get(id).MuteStartStatus; got != monitor.StatusUp {
		t.Fatalf("extending a mute must keep the start status, got %q", got)
	}
	if _, err := st.SetMonitorsMutedUntil(ctx, []int64{id}, nil); err != nil {
		t.Fatalf("unmute: %v", err)
	}
	if got := get(id).MuteStartStatus; got != monitor.StatusUp {
		t.Fatalf("unmute must keep the catch-up marker, got %q", got)
	}
	if err := st.ClearMonitorMuteStartStatus(ctx, id); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := get(id).MuteStartStatus; got != "" {
		t.Fatalf("marker not cleared: %q", got)
	}

	statuses, err := st.RecentMonitorStatuses(ctx, id, 5)
	if err != nil || len(statuses) != 2 || statuses[0] != monitor.StatusDown || statuses[1] != monitor.StatusUp {
		t.Fatalf("recent statuses = %v err=%v", statuses, err)
	}
}

func TestSuppressedEventsAndSupersededRetries(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	endpointID := insertMaintenanceNotificationEndpoint(t, ctx, st)

	if err := st.RecordSuppressedNotificationEvent(ctx, monitorID, endpointID, "status_transition", "muted"); err != nil {
		t.Fatalf("record suppressed: %v", err)
	}
	events, err := st.ListRecentNotificationEvents(ctx, 10)
	if err != nil || len(events) != 1 || !events[0].Suppressed || events[0].DeliveredAt != nil {
		t.Fatalf("events = %+v err=%v", events, err)
	}

	if err := st.EnqueueNotificationRetry(ctx, monitor.NotificationRetryParams{
		MonitorID: monitorID, EndpointID: endpointID, EventType: "status_transition", MaxAttempts: 3,
		NextAttemptAt: time.Now().Add(-time.Minute),
		Transition:    monitor.Transition{Monitor: monitor.Monitor{ID: monitorID}, Previous: monitor.StatusUp, Current: monitor.StatusDown, CheckedAt: time.Now()},
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	due, err := st.ListDueNotificationRetries(ctx, time.Now(), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due retries = %d err=%v", len(due), err)
	}
	if err := st.SupersedeNotificationRetry(ctx, due[0].ID, "superseded"); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	due, _ = st.ListDueNotificationRetries(ctx, time.Now(), 10)
	if len(due) != 0 {
		t.Fatalf("superseded retry still due")
	}
}

func TestPhase2IndexesExist(t *testing.T) {
	ctx := context.Background()
	st, _ := openDataQualityStore(t)
	for _, name := range []string{"idx_notification_events_monitor_created", "idx_incidents_monitor"} {
		var count int
		if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&count); err != nil || count != 1 {
			t.Fatalf("index %s missing (count=%d err=%v)", name, count, err)
		}
	}
}
