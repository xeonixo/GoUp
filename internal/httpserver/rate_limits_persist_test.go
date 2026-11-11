package httpserver

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	store "goup/internal/store/sqlite"
)

func newServerWithControlPlane(t *testing.T, cp *store.ControlPlaneStore) *Server {
	t.Helper()
	return &Server{
		logger:              slog.Default(),
		controlStore:        cp,
		localLoginAttempts:  make(map[string]localLoginAttempt),
		adminAccessAttempts: make(map[string]localLoginAttempt),
		bootstrapAttempts:   make(map[string]localLoginAttempt),
	}
}

func TestAuthLockoutsPersistAcrossRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "controlplane.db")

	cp, err := store.OpenControlPlane(ctx, dbPath)
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}

	s1 := newServerWithControlPlane(t, cp)
	now := time.Now().UTC()

	localKey := "42|bob|198.51.100.9"
	for i := 0; i < localLoginMaxFailures; i++ {
		s1.registerLocalLoginFailure(localKey, now)
	}
	adminKey := "admin|198.51.100.10"
	for i := 0; i < adminAccessMaxFailures; i++ {
		s1.registerAdminAccessFailure(adminKey, now)
	}
	bootstrapKey := "node-bootstrap|edge-1|198.51.100.11"
	for i := 0; i < bootstrapMaxFailures; i++ {
		s1.registerBootstrapFailure(bootstrapKey, now)
	}

	if ok, _ := s1.localLoginAllowed(localKey, now); ok {
		t.Fatal("local login should be locked before restart")
	}
	if ok, _ := s1.adminAccessAllowed(adminKey, now); ok {
		t.Fatal("admin access should be locked before restart")
	}
	if ok, _ := s1.bootstrapAllowed(bootstrapKey, now); ok {
		t.Fatal("bootstrap should be locked before restart")
	}

	if err := cp.Close(); err != nil {
		t.Fatalf("close control plane: %v", err)
	}

	reopened, err := store.OpenControlPlane(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen control plane: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	s2 := newServerWithControlPlane(t, reopened)
	s2.loadPersistedRateLimitAttempts(ctx)

	if ok, remaining := s2.localLoginAllowed(localKey, now); ok || remaining <= 0 {
		t.Fatalf("local login lockout should survive restart: ok=%v remaining=%v", ok, remaining)
	}
	if ok, remaining := s2.adminAccessAllowed(adminKey, now); ok || remaining <= 0 {
		t.Fatalf("admin lockout should survive restart: ok=%v remaining=%v", ok, remaining)
	}
	if ok, remaining := s2.bootstrapAllowed(bootstrapKey, now); ok || remaining <= 0 {
		t.Fatalf("bootstrap lockout should survive restart: ok=%v remaining=%v", ok, remaining)
	}
}

func TestClearAuthLockoutRemovesPersistedRow(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = cp.Close() })

	s := newServerWithControlPlane(t, cp)
	now := time.Now().UTC()
	key := "7|carol|203.0.113.50"
	s.registerLocalLoginFailure(key, now)
	s.clearLocalLoginAttempts(key)

	items, err := cp.ListRateLimitAttempts(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("cleared attempt should be removed from db, got %+v", items)
	}
}

func TestSweepRemovesExpiredPersistedLockouts(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = cp.Close() })

	s := newServerWithControlPlane(t, cp)
	now := time.Now().UTC()
	expiredKey := "9|dave|203.0.113.60"
	s.localLoginAttempts[expiredKey] = localLoginAttempt{
		Failures:    2,
		WindowStart: now.Add(-localLoginWindow - time.Minute),
	}
	if err := cp.UpsertRateLimitAttempt(ctx, store.RateLimitAttempt{
		Key:         expiredKey,
		Kind:        store.RateLimitKindLocalLogin,
		Failures:    2,
		WindowStart: now.Add(-localLoginWindow - time.Minute),
	}); err != nil {
		t.Fatalf("seed expired: %v", err)
	}
	lockedKey := "admin|203.0.113.61"
	s.adminAccessAttempts[lockedKey] = localLoginAttempt{
		Failures:    0,
		WindowStart: now,
		LockedUntil: now.Add(adminAccessLockout),
	}
	if err := cp.UpsertRateLimitAttempt(ctx, store.RateLimitAttempt{
		Key:         lockedKey,
		Kind:        store.RateLimitKindAdminAccess,
		WindowStart: now,
		LockedUntil: now.Add(adminAccessLockout),
	}); err != nil {
		t.Fatalf("seed locked: %v", err)
	}

	s.sweepLocalLoginAttempts(now)
	s.sweepAdminAccessAttempts(now)
	s.prunePersistedRateLimitAttempts(now)

	if _, ok := s.localLoginAttempts[expiredKey]; ok {
		t.Fatal("expired local attempt should be swept from memory")
	}
	if _, ok := s.adminAccessAttempts[lockedKey]; !ok {
		t.Fatal("active lockout should remain in memory")
	}

	items, err := cp.ListRateLimitAttempts(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 1 || items[0].Key != lockedKey {
		t.Fatalf("expected only locked row in db, got %+v", items)
	}
}
