package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunMaintenancePrunesEventHistoryByRetention(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := Open(ctx, filepath.Join(dir, "tenant.db"))
	if err != nil {
		t.Fatalf("open tenant store: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	monitorID := insertMaintenanceMonitor(t, ctx, store)
	endpointID := insertMaintenanceNotificationEndpoint(t, ctx, store)

	insertStateEvent := func(checkedAt time.Time) {
		t.Helper()
		if _, err := store.db.ExecContext(ctx, `
INSERT INTO monitor_state_events (monitor_id, checked_at, from_status, to_status, message)
VALUES (?, ?, 'up', 'down', 'test')
`, monitorID, checkedAt); err != nil {
			t.Fatalf("insert state event: %v", err)
		}
	}
	insertNotificationEvent := func(createdAt time.Time) {
		t.Helper()
		if _, err := store.db.ExecContext(ctx, `
INSERT INTO notification_events (monitor_id, endpoint_id, event_type, created_at, delivered_at, error_message)
VALUES (?, ?, 'incident', ?, ?, '')
`, monitorID, endpointID, createdAt, createdAt); err != nil {
			t.Fatalf("insert notification event: %v", err)
		}
	}

	insertStateEvent(now.AddDate(0, 0, -8))
	insertStateEvent(now.AddDate(0, 0, -2))
	insertNotificationEvent(now.AddDate(0, 0, -8))
	insertNotificationEvent(now.AddDate(0, 0, -2))

	result, err := store.RunMaintenance(ctx, now, MaintenanceOptions{
		StateEventRetentionDays:        7,
		NotificationEventRetentionDays: 7,
	})
	if err != nil {
		t.Fatalf("run maintenance: %v", err)
	}
	if result.DeletedStateEvents != 1 {
		t.Fatalf("unexpected deleted state events: %d", result.DeletedStateEvents)
	}
	if result.DeletedNotificationEvents != 1 {
		t.Fatalf("unexpected deleted notification events: %d", result.DeletedNotificationEvents)
	}

	stateCount, err := store.CountMonitorStateEvents(ctx)
	if err != nil {
		t.Fatalf("count state events: %v", err)
	}
	if stateCount != 1 {
		t.Fatalf("unexpected remaining state events: %d", stateCount)
	}
	notificationCount, err := store.CountNotificationEvents(ctx)
	if err != nil {
		t.Fatalf("count notification events: %v", err)
	}
	if notificationCount != 1 {
		t.Fatalf("unexpected remaining notification events: %d", notificationCount)
	}
}

func insertMaintenanceMonitor(t *testing.T, ctx context.Context, store *Store) int64 {
	t.Helper()
	now := time.Now().UTC()
	result, err := store.db.ExecContext(ctx, `
INSERT INTO monitors (name, kind, target, created_at, updated_at)
VALUES ('monitor', 'https', 'example.com', ?, ?)
`, now, now)
	if err != nil {
		t.Fatalf("insert monitor: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("monitor last insert id: %v", err)
	}
	return id
}

func insertMaintenanceNotificationEndpoint(t *testing.T, ctx context.Context, store *Store) int64 {
	t.Helper()
	now := time.Now().UTC()
	result, err := store.db.ExecContext(ctx, `
INSERT INTO notification_endpoints (kind, name, created_at, updated_at)
VALUES ('email', 'email', ?, ?)
`, now, now)
	if err != nil {
		t.Fatalf("insert notification endpoint: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("endpoint last insert id: %v", err)
	}
	return id
}

func TestControlPlaneMaintenancePrunesRemoteNodeEvents(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	tenant, err := cp.CreateTenant(ctx, "events", "Events", filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	insertEvent := func(eventType, details string, createdAt time.Time) {
		t.Helper()
		if err := cp.InsertRemoteNodeEvent(ctx, tenant.ID, "rn_test", eventType, "127.0.0.1", "test", details, createdAt); err != nil {
			t.Fatalf("insert remote node event: %v", err)
		}
	}
	recent := now.Add(-time.Hour)
	insertEvent("poll", "assigned_monitors=3", recent)
	insertEvent("report", "accepted=12 received=12", recent)
	insertEvent("report", "accepted=1 received=12", recent)
	insertEvent("bootstrap", "", recent)
	insertEvent("status_offline", "", now.AddDate(0, 0, -31))

	result, err := cp.RunMaintenance(ctx, now)
	if err != nil {
		t.Fatalf("run control-plane maintenance: %v", err)
	}
	if result.DeletedRemoteNodeEvents != 3 {
		t.Fatalf("unexpected deleted remote node events: %d", result.DeletedRemoteNodeEvents)
	}
	if !result.Vacuumed {
		t.Fatalf("expected first maintenance run to vacuum")
	}

	events, err := cp.ListRecentRemoteNodeEventsByTenant(ctx, tenant.ID, 10)
	if err != nil {
		t.Fatalf("list remote node events: %v", err)
	}
	kept := make([]string, 0, len(events))
	for _, event := range events {
		kept = append(kept, event.EventType+":"+event.Details)
	}
	if len(kept) != 2 || !strings.Contains(strings.Join(kept, ","), "report:accepted=1 received=12") || !strings.Contains(strings.Join(kept, ","), "bootstrap:") {
		t.Fatalf("unexpected remaining remote node events: %v", kept)
	}

	var autoVacuum int
	if err := cp.db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		t.Fatalf("read auto_vacuum: %v", err)
	}
	if autoVacuum != sqliteAutoVacuumIncremental {
		t.Fatalf("expected incremental auto_vacuum, got %d", autoVacuum)
	}

	again, err := cp.RunMaintenance(ctx, now)
	if err != nil {
		t.Fatalf("rerun control-plane maintenance: %v", err)
	}
	if again.Vacuumed || again.DeletedRemoteNodeEvents != 0 {
		t.Fatalf("expected idempotent second run, got %+v", again)
	}
}

func TestRunMaintenanceUsesRawResultRetentionAndCompacts(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := Open(ctx, filepath.Join(dir, "tenant.db"))
	if err != nil {
		t.Fatalf("open tenant store: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	monitorID := insertMaintenanceMonitor(t, ctx, store)
	for _, checkedAt := range []time.Time{now.AddDate(0, 0, -10), now.AddDate(0, 0, -3)} {
		if _, err := store.db.ExecContext(ctx, `
INSERT INTO monitor_results (monitor_id, checked_at, status, latency_ms, message)
VALUES (?, ?, 'up', 10, '')
`, monitorID, checkedAt); err != nil {
			t.Fatalf("insert monitor result: %v", err)
		}
	}

	result, err := store.RunMaintenance(ctx, now, MaintenanceOptions{RawResultRetentionDays: 7})
	if err != nil {
		t.Fatalf("run maintenance: %v", err)
	}
	if result.DeletedRawResults != 1 {
		t.Fatalf("unexpected deleted raw results: %d", result.DeletedRawResults)
	}
	if !result.Vacuumed {
		t.Fatalf("expected first maintenance run to vacuum")
	}
	var autoVacuum int
	if err := store.db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		t.Fatalf("read auto_vacuum: %v", err)
	}
	if autoVacuum != sqliteAutoVacuumIncremental {
		t.Fatalf("expected incremental auto_vacuum, got %d", autoVacuum)
	}
}
