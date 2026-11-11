package app

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"goup/internal/config"
	monitorrunner "goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

func TestAppReadyReportsMissingRunner(t *testing.T) {
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
		t.Fatalf("open tenant: %v", err)
	}
	defer tenantStore.Close()

	a := &App{
		config:       config.Config{DataDir: dir, AuditRetentionDays: 90},
		logger:       slog.Default(),
		controlStore: cp,
		store:        tenantStore,
		tenantStores: store.NewTenantStoreManager(cp, tenant, tenantStore),
		runners:      map[int64]*tenantRunner{},
	}
	reasons := a.Ready(ctx)
	joined := strings.Join(reasons, ",")
	if !strings.Contains(joined, "runner:acme: missing") {
		t.Fatalf("expected missing runner, got %v", reasons)
	}

	a.runners[tenant.ID] = &tenantRunner{tenant: tenant, runner: &monitorrunner.Runner{}}
	reasons = a.Ready(ctx)
	if len(reasons) != 0 {
		t.Fatalf("expected ready, got %v", reasons)
	}
}
