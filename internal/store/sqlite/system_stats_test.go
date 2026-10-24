package sqlite

import (
	"context"
	"testing"
	"time"
)

func TestNotificationOutcomeCountsAndFailures(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	endpointID := insertMaintenanceNotificationEndpoint(t, ctx, st)

	delivered := time.Now().UTC()
	if err := st.RecordNotificationEvent(ctx, monitorID, endpointID, "email", &delivered, ""); err != nil {
		t.Fatalf("record delivered: %v", err)
	}
	if err := st.RecordNotificationEvent(ctx, monitorID, endpointID, "email", nil, "decrypt smtp password: cipher: message authentication failed"); err != nil {
		t.Fatalf("record failed: %v", err)
	}
	if err := st.RecordSuppressedNotificationEvent(ctx, monitorID, endpointID, "email", "muted"); err != nil {
		t.Fatalf("record suppressed: %v", err)
	}
	// An old failure must not be counted.
	if _, err := st.db.ExecContext(ctx, `
INSERT INTO notification_events (monitor_id, endpoint_id, event_type, created_at, delivered_at, error_message)
VALUES (?, ?, 'email', ?, NULL, 'old')`, monitorID, endpointID, time.Now().UTC().Add(-48*time.Hour)); err != nil {
		t.Fatalf("insert old: %v", err)
	}

	since := time.Now().UTC().Add(-24 * time.Hour)
	counts, err := st.NotificationOutcomeCountsSince(ctx, since)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if counts.Delivered != 1 || counts.Failed != 1 || counts.Suppressed != 1 {
		t.Fatalf("counts = %+v, want 1/1/1", counts)
	}

	failures, err := st.ListRecentNotificationFailures(ctx, since, 10)
	if err != nil || len(failures) != 1 {
		t.Fatalf("failures = %v err=%v", failures, err)
	}
	if failures[0].MonitorName != "monitor" || failures[0].EndpointKind == "" || failures[0].Error == "" {
		t.Fatalf("unexpected failure row: %+v", failures[0])
	}
}

func TestNotificationEventsCreatedAtIndexExists(t *testing.T) {
	st, _ := openDataQualityStore(t)
	var name string
	err := st.db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_notification_events_created'`).Scan(&name)
	if err != nil {
		t.Fatalf("index missing: %v", err)
	}
}

func TestMaintenanceRunsAndRetryQueueStats(t *testing.T) {
	ctx := context.Background()
	st, monitorID := openDataQualityStore(t)
	endpointID := insertMaintenanceNotificationEndpoint(t, ctx, st)

	runs, err := st.MaintenanceRuns(ctx)
	if err != nil || !runs.RawRetention.IsZero() || !runs.RollupRetention.IsZero() {
		t.Fatalf("fresh runs = %+v err=%v", runs, err)
	}
	stamp := time.Date(2026, 5, 1, 3, 0, 0, 0, time.UTC)
	if err := st.setSetting(ctx, lastRetentionRunSettingKey, stamp.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("set setting: %v", err)
	}
	runs, err = st.MaintenanceRuns(ctx)
	if err != nil || !runs.RawRetention.Equal(stamp) || !runs.RollupRetention.IsZero() {
		t.Fatalf("runs = %+v err=%v", runs, err)
	}

	pending, oldest, err := st.NotificationRetryQueueStats(ctx)
	if err != nil || pending != 0 || oldest != nil {
		t.Fatalf("empty queue = %d %v err=%v", pending, oldest, err)
	}
	next := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	for _, at := range []time.Time{next.Add(time.Hour), next} {
		if _, err := st.db.ExecContext(ctx, `
INSERT INTO notification_retries (monitor_id, endpoint_id, event_type, checked_at, next_attempt_at, status, created_at, updated_at)
VALUES (?, ?, 'email', ?, ?, 'pending', ?, ?)`, monitorID, endpointID, at, at, at, at); err != nil {
			t.Fatalf("insert retry: %v", err)
		}
	}
	pending, oldest, err = st.NotificationRetryQueueStats(ctx)
	if err != nil || pending != 2 || oldest == nil || !oldest.Equal(next) {
		t.Fatalf("queue = %d %v err=%v, want 2 %v", pending, oldest, err, next)
	}
}
