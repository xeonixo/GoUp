package httpserver

import (
	"context"
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
}
