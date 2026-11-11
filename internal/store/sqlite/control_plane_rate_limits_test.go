package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRateLimitAttemptsPersistAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "controlplane.db")

	cp, err := OpenControlPlane(ctx, dbPath)
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	lockedUntil := now.Add(15 * time.Minute)
	if err := cp.UpsertRateLimitAttempt(ctx, RateLimitAttempt{
		Key:         "1|alice|203.0.113.10",
		Kind:        RateLimitKindLocalLogin,
		Failures:    0,
		WindowStart: now,
		LockedUntil: lockedUntil,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := cp.UpsertRateLimitAttempt(ctx, RateLimitAttempt{
		Key:         "admin|203.0.113.11",
		Kind:        RateLimitKindAdminAccess,
		Failures:    3,
		WindowStart: now,
	}); err != nil {
		t.Fatalf("upsert admin: %v", err)
	}
	if err := cp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := OpenControlPlane(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen control plane: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	items, err := reopened.ListRateLimitAttempts(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(items))
	}

	byKey := map[string]RateLimitAttempt{}
	for _, item := range items {
		byKey[item.Key] = item
	}
	local := byKey["1|alice|203.0.113.10"]
	if local.Kind != RateLimitKindLocalLogin || local.Failures != 0 {
		t.Fatalf("unexpected local attempt: %+v", local)
	}
	if local.LockedUntil.Unix() != lockedUntil.Unix() {
		t.Fatalf("locked_until mismatch: got %v want %v", local.LockedUntil, lockedUntil)
	}
	admin := byKey["admin|203.0.113.11"]
	if admin.Kind != RateLimitKindAdminAccess || admin.Failures != 3 {
		t.Fatalf("unexpected admin attempt: %+v", admin)
	}
}

func TestRateLimitAttemptsPruneExpired(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	t.Cleanup(func() { _ = cp.Close() })

	now := time.Now().UTC().Truncate(time.Second)
	if err := cp.UpsertRateLimitAttempt(ctx, RateLimitAttempt{
		Key:         "expired",
		Kind:        RateLimitKindBootstrap,
		Failures:    2,
		WindowStart: now.Add(-20 * time.Minute),
	}); err != nil {
		t.Fatalf("upsert expired: %v", err)
	}
	if err := cp.UpsertRateLimitAttempt(ctx, RateLimitAttempt{
		Key:         "locked",
		Kind:        RateLimitKindBootstrap,
		Failures:    0,
		WindowStart: now.Add(-20 * time.Minute),
		LockedUntil: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("upsert locked: %v", err)
	}
	if err := cp.UpsertRateLimitAttempt(ctx, RateLimitAttempt{
		Key:         "fresh",
		Kind:        RateLimitKindBootstrap,
		Failures:    1,
		WindowStart: now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("upsert fresh: %v", err)
	}

	deleted, err := cp.PruneRateLimitAttempts(ctx, now, map[string]time.Duration{
		RateLimitKindBootstrap: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 pruned row, got %d", deleted)
	}

	items, err := cp.ListRateLimitAttempts(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 remaining, got %d (%+v)", len(items), items)
	}
	byKey := map[string]RateLimitAttempt{}
	for _, item := range items {
		byKey[item.Key] = item
	}
	if _, ok := byKey["expired"]; ok {
		t.Fatal("expired row should be pruned")
	}
	if _, ok := byKey["locked"]; !ok {
		t.Fatal("locked row should remain")
	}
	if _, ok := byKey["fresh"]; !ok {
		t.Fatal("fresh row should remain")
	}
}

func TestRateLimitAttemptsDelete(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = cp.Close() })

	now := time.Now().UTC()
	for _, key := range []string{"a", "b", "c"} {
		if err := cp.UpsertRateLimitAttempt(ctx, RateLimitAttempt{
			Key:         key,
			Kind:        RateLimitKindLocalLogin,
			Failures:    1,
			WindowStart: now,
		}); err != nil {
			t.Fatalf("upsert %s: %v", key, err)
		}
	}
	if err := cp.DeleteRateLimitAttempt(ctx, "a"); err != nil {
		t.Fatalf("delete one: %v", err)
	}
	if err := cp.DeleteRateLimitAttempts(ctx, []string{"b", "c"}); err != nil {
		t.Fatalf("delete many: %v", err)
	}
	items, err := cp.ListRateLimitAttempts(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected empty, got %+v", items)
	}
}
