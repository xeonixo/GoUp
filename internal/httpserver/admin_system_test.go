package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/config"
	store "goup/internal/store/sqlite"
)

func TestStatDBFilesSizesAndMissing(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tenants", "a.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath+"-wal", make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}

	got := statDBFiles(dir, "A", dbPath)
	if got.Missing || got.Size != "2.0 KB" || got.WAL != "1.0 KB" || got.SHM != "0 B" {
		t.Fatalf("unexpected view: %+v", got)
	}
	if got.RelPath != filepath.Join("tenants", "a.db") || got.TotalBytes != 3072 {
		t.Fatalf("rel/total = %q / %d", got.RelPath, got.TotalBytes)
	}
	if got.LargeDB || got.LargeWAL {
		t.Fatalf("small files must not be highlighted")
	}

	missing := statDBFiles(dir, "B", filepath.Join(dir, "nope.db"))
	if !missing.Missing {
		t.Fatalf("missing file not flagged: %+v", missing)
	}
}

func TestFormatHelpers(t *testing.T) {
	if got := formatByteSize(5 << 30); got != "5.0 GB" {
		t.Fatalf("formatByteSize = %q", got)
	}
	if got := formatSystemDuration(26*time.Hour + 10*time.Minute); got != "1d 2h" {
		t.Fatalf("formatSystemDuration = %q", got)
	}
	if got := truncateRunes("äöüäöü", 3); got != "äöü…" {
		t.Fatalf("truncateRunes = %q", got)
	}
}

func TestCollectSystemViewIsolatesTenantErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	// Active tenant without a database file: reported in its row, page still renders.
	tenant, err := cp.CreateTenant(ctx, "ghost", "Ghost", filepath.Join(dir, "ghost.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	_ = os.Remove(tenant.DBPath)

	s := &Server{
		cfg:          config.Config{DataDir: dir, ControlPlaneDBPath: filepath.Join(dir, "controlplane.db")},
		controlStore: cp,
		tenantStores: store.NewTenantStoreManager(cp, store.Tenant{}, nil),
		startedAt:    time.Now().Add(-90 * time.Second),
	}
	view, err := s.collectSystemView(ctx)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(view.Tenants) != 1 || view.Tenants[0].Err == "" {
		t.Fatalf("tenant error not isolated: %+v", view.Tenants)
	}
	if len(view.Storage.Files) != 2 || view.Storage.Files[0].Missing || !view.Storage.Files[1].Missing {
		t.Fatalf("storage files = %+v", view.Storage.Files)
	}
	if view.Process.Goroutines <= 0 || view.Process.GoVersion == "" || view.Process.Uptime != "1m 30s" {
		t.Fatalf("process = %+v", view.Process)
	}
}

func TestAdminSystemRequiresAdmin(t *testing.T) {
	s := &Server{adminCookieKey: strings.Repeat("a", 32)}
	handler := s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminSystem))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/system", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/access" {
		t.Fatalf("unauthenticated: code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}

	unconfigured := &Server{}
	rec = httptest.NewRecorder()
	unconfigured.requireControlPlaneAdmin(http.HandlerFunc(unconfigured.handleAdminSystem)).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/system", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unconfigured admin: code=%d", rec.Code)
	}
}

func TestAdminSystemPageRenders(t *testing.T) {
	s := renderTestServer(t)
	view := systemPageView{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Storage:     systemStorageView{Files: []systemDBFileView{{Label: "Control plane", RelPath: "controlplane.db", Size: "1 KB", WAL: "0 B", SHM: "0 B", LargeWAL: true}}},
		Tenants:     []systemTenantView{{Name: "T", Slug: "t", Active: true, HasRunner: true, Backlog: 2}},
		Failures:    []systemFailureView{{TimeRaw: "2026-01-01T00:00:00Z", Tenant: "T", Error: "decrypt smtp password: cipher: message authentication failed"}},
	}
	rec := httptest.NewRecorder()
	s.render(rec, "admin_system", pageData{Title: "System", ControlPlaneAdmin: true, SystemView: &view})
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "message authentication failed") || !strings.Contains(body, `href="/admin/system" class="admin-nav-link is-active"`) {
		t.Fatalf("render failed: code=%d body=%.300s", rec.Code, body)
	}
	if !strings.Contains(body, `/admin/system/backup`) || !strings.Contains(body, `/admin/system/rekey-secrets`) || !strings.Contains(body, `/admin/system/rotate-vapid`) {
		t.Fatalf("backup/rekey/vapid actions missing: %.400s", body)
	}
}

func TestAdminSystemBackupAndRekey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "controlplane.db")
	cp, err := store.OpenControlPlane(ctx, controlPath)
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()
	oldKey := "old-admin-rekey-key-1234567890abcd"
	newKey := "new-admin-rekey-key-1234567890abcd"
	if err := cp.ConfigureSecretKeys(oldKey); err != nil {
		t.Fatalf("old key: %v", err)
	}
	if err := cp.CreateControlPlaneAdmin(ctx, "root", "hash"); err != nil {
		t.Fatalf("admin: %v", err)
	}
	if err := cp.SetControlPlaneAdminTOTP(ctx, "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatalf("totp: %v", err)
	}
	if err := cp.ConfigureSecretKeys(newKey, oldKey); err != nil {
		t.Fatalf("new+old: %v", err)
	}

	s := &Server{
		cfg:          config.Config{DataDir: dir, ControlPlaneDBPath: controlPath},
		controlStore: cp,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/system/backup", nil)
	s.handleAdminSystemBackup(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=") {
		t.Fatalf("backup redirect: code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/system/rekey-secrets", strings.NewReader("confirm=yes"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleAdminSystemRekeySecrets(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=") {
		t.Fatalf("rekey redirect: code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}

	if err := cp.ConfigureSecretKeys(newKey); err != nil {
		t.Fatalf("new only: %v", err)
	}
	admin, err := cp.GetControlPlaneAdmin(ctx)
	if err != nil || admin.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("totp after rekey: %+v err=%v", admin, err)
	}
}

func TestAdminSystemRotateVAPID(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "controlplane.db")
	cp, err := store.OpenControlPlane(ctx, controlPath)
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()
	if err := cp.ConfigureSecretKey("test-secret-key-for-vapid-rotate"); err != nil {
		t.Fatal(err)
	}
	tenant, err := cp.CreateTenant(ctx, "vapid", "Vapid", filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	user, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "alice", "a-long-password-123", "a@example.com", "Alice", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	_, pub1, err := cp.GetOrCreateVAPIDKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.UpsertPushSubscription(ctx, store.PushSubscription{
		TenantID: tenant.ID, UserID: user.UserID, Endpoint: "https://web.push.apple.com/x",
		P256dh: "p256", Auth: "auth", NotifyDown: true, NotifyRecovery: true, NotifyDegraded: true, NotifyReminder: true,
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		cfg:          config.Config{DataDir: dir, ControlPlaneDBPath: controlPath, BaseURL: "https://goup.example"},
		controlStore: cp,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/system/rotate-vapid", strings.NewReader("confirm=yes"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleAdminSystemRotateVAPID(rec, req)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.Contains(loc, "notice=") || !strings.Contains(loc, "re-enable") {
		t.Fatalf("rotate redirect: code=%d location=%q", rec.Code, loc)
	}

	_, pub2, err := cp.GetOrCreateVAPIDKeys(ctx)
	if err != nil || pub2 == "" || pub2 == pub1 {
		t.Fatalf("keys after rotate: pub=%q old=%q err=%v", pub2, pub1, err)
	}
	subs, _ := cp.ListUserPushSubscriptions(ctx, tenant.ID, user.UserID)
	if len(subs) != 0 {
		t.Fatalf("subscriptions not cleared: %#v", subs)
	}
	// Cached sender keys must reload the rotated pair.
	cached, err := s.pushSender().PublicKey(ctx)
	if err != nil || cached != pub2 {
		t.Fatalf("sender cache = %q want %q (%v)", cached, pub2, err)
	}
}
