package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneAuditEventsByRetention(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	insert := func(action string, createdAt time.Time) {
		t.Helper()
		_, err := cp.db.ExecContext(ctx, `
INSERT INTO audit_events (actor, action, target_type, target_id, details, created_at)
VALUES (?, ?, ?, ?, ?, ?)
`, "admin", action, "system", int64(1), "test", createdAt.UTC())
		if err != nil {
			t.Fatalf("insert audit event: %v", err)
		}
	}
	insert("keep.recent", now.Add(-24*time.Hour))
	insert("drop.old", now.AddDate(0, 0, -91))
	insert("drop.older", now.AddDate(0, 0, -120))

	result, err := cp.RunMaintenance(ctx, now, ControlPlaneMaintenanceOptions{AuditRetentionDays: 90})
	if err != nil {
		t.Fatalf("run maintenance: %v", err)
	}
	if result.DeletedAuditEvents != 2 {
		t.Fatalf("deleted audit events = %d, want 2", result.DeletedAuditEvents)
	}

	events, err := cp.ListRecentAuditEvents(ctx, 50)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 || events[0].Action != "keep.recent" {
		t.Fatalf("remaining events = %+v", events)
	}

	again, err := cp.RunMaintenance(ctx, now, ControlPlaneMaintenanceOptions{AuditRetentionDays: 90})
	if err != nil {
		t.Fatalf("rerun maintenance: %v", err)
	}
	if again.DeletedAuditEvents != 0 {
		t.Fatalf("expected idempotent prune, got %+v", again)
	}
}

func TestNormalizeAuditRetentionDays(t *testing.T) {
	if got := NormalizeAuditRetentionDays(0); got != DefaultAuditRetentionDays {
		t.Fatalf("NormalizeAuditRetentionDays(0) = %d", got)
	}
	if got := NormalizeAuditRetentionDays(-3); got != DefaultAuditRetentionDays {
		t.Fatalf("NormalizeAuditRetentionDays(-3) = %d", got)
	}
	if got := NormalizeAuditRetentionDays(30); got != 30 {
		t.Fatalf("NormalizeAuditRetentionDays(30) = %d", got)
	}
}

func TestExportAuditEventsFiltered(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	if err := cp.InsertAuditEvent(ctx, "alice@example.com", "tenant.create", "tenant", 7, "slug=acme"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := cp.InsertAuditEvent(ctx, "bob@example.com", "tenant.update", "tenant", 8, "slug=beta"); err != nil {
		t.Fatalf("insert: %v", err)
	}

	events, err := cp.ExportAuditEventsFiltered(ctx, "tenant.create", "alice", "tenant")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(events) != 1 || events[0].Action != "tenant.create" {
		t.Fatalf("export filtered = %+v", events)
	}
}
