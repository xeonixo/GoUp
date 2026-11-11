package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"goup/internal/config"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

func TestHandleHealthzRemainsShallow(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	s := &Server{controlStore: cp}
	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

func TestHandleReadyzOKAndUnavailable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	tenantDB := filepath.Join(dir, "acme.db")
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme", tenantDB)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenantStore, err := store.Open(ctx, tenantDB)
	if err != nil {
		t.Fatalf("open tenant store: %v", err)
	}
	defer tenantStore.Close()

	manager := store.NewTenantStoreManager(cp, tenant, tenantStore)
	runners := map[int64]*monitor.Runner{tenant.ID: {}}

	s := &Server{
		cfg:          config.Config{DataDir: dir},
		controlStore: cp,
		store:        tenantStore,
		tenantStores: manager,
		runnerFor: func(tenantID int64) *monitor.Runner {
			return runners[tenantID]
		},
	}

	rec := httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz ok = %d %s", rec.Code, rec.Body.String())
	}
	var okBody readyzResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &okBody); err != nil {
		t.Fatalf("decode ok body: %v", err)
	}
	if okBody.Status != "ok" || len(okBody.Reasons) != 0 {
		t.Fatalf("ok body = %+v", okBody)
	}

	delete(runners, tenant.ID)
	rec = httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz missing runner = %d %s", rec.Code, rec.Body.String())
	}
	var failBody readyzResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &failBody); err != nil {
		t.Fatalf("decode fail body: %v", err)
	}
	if failBody.Status != "unavailable" || len(failBody.Reasons) == 0 {
		t.Fatalf("fail body = %+v", failBody)
	}
	joined := strings.Join(failBody.Reasons, ",")
	if !strings.Contains(joined, "runner:acme: missing") {
		t.Fatalf("expected runner reason, got %v", failBody.Reasons)
	}
}

func TestHandleReadyzUsesReadyCheckHook(t *testing.T) {
	s := &Server{
		readyCheck: func(context.Context) []string {
			return []string{"control_plane: down"}
		},
	}
	rec := httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "control_plane: down") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
