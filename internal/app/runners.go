package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"goup/internal/config"
	monitorrunner "goup/internal/monitor"
	"goup/internal/notify"
	store "goup/internal/store/sqlite"
)

type tenantRunner struct {
	tenant store.Tenant
	runner *monitorrunner.Runner
	cancel context.CancelFunc
}

func (a *App) startConfiguredRunners(ctx context.Context) {
	a.runnerMu.Lock()
	defer a.runnerMu.Unlock()
	for _, item := range a.runners {
		if item == nil || item.runner == nil || item.cancel != nil {
			continue
		}
		runnerCtx, cancel := context.WithCancel(ctx)
		item.cancel = cancel
		go item.runner.Run(runnerCtx)
		a.logger.Info("runner started for tenant", "tenant", item.tenant.Slug)
	}
}

func (a *App) runRunnerReconcile(ctx context.Context) {
	a.reconcileRunners(ctx)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.reconcileRunners(ctx)
		}
	}
}

func (a *App) reconcileRunners(ctx context.Context) {
	tenants, err := a.controlStore.GetAllTenants(ctx)
	if err != nil {
		a.logger.Warn("load tenants for runner reconcile failed", "error", err)
		return
	}

	desired := make(map[int64]store.Tenant, len(tenants))
	for _, tenant := range tenants {
		if !tenant.Active || !tenantHasAppDatabase(tenant.DBPath) {
			continue
		}
		desired[tenant.ID] = tenant
	}

	toStart := make([]store.Tenant, 0)

	a.runnerMu.Lock()
	for tenantID, item := range a.runners {
		desiredTenant, ok := desired[tenantID]
		if !ok {
			if item != nil && item.cancel != nil {
				item.cancel()
			}
			delete(a.runners, tenantID)
			if item != nil {
				a.logger.Info("runner stopped for tenant", "tenant", item.tenant.Slug, "reason", "tenant inactive or missing")
			}
			continue
		}

		if item == nil {
			delete(a.runners, tenantID)
			toStart = append(toStart, desiredTenant)
			continue
		}

		existingDBPath := strings.TrimSpace(item.tenant.DBPath)
		desiredDBPath := strings.TrimSpace(desiredTenant.DBPath)
		if existingDBPath != desiredDBPath || strings.TrimSpace(item.tenant.Slug) != strings.TrimSpace(desiredTenant.Slug) {
			if item.cancel != nil {
				item.cancel()
			}
			delete(a.runners, tenantID)
			toStart = append(toStart, desiredTenant)
			a.logger.Info("runner restarted for tenant", "tenant", desiredTenant.Slug, "reason", "tenant configuration changed")
		}
	}
	for tenantID, tenant := range desired {
		if _, ok := a.runners[tenantID]; !ok {
			toStart = append(toStart, tenant)
		}
	}
	a.runnerMu.Unlock()

	for _, tenant := range toStart {
		runner, err := buildTenantRunner(ctx, a.logger, a.controlStore, a.tenantStores, a.config, tenant)
		if err != nil {
			a.logger.Warn("failed to initialize runner during reconcile", "tenant", tenant.Slug, "error", err)
			continue
		}

		runnerCtx, cancel := context.WithCancel(ctx)
		a.runnerMu.Lock()
		if existing, ok := a.runners[tenant.ID]; ok {
			a.runnerMu.Unlock()
			cancel()
			if existing != nil && existing.cancel == nil && existing.runner != nil {
				existingCtx, existingCancel := context.WithCancel(ctx)
				existing.cancel = existingCancel
				go existing.runner.Run(existingCtx)
			}
			continue
		}
		a.runners[tenant.ID] = &tenantRunner{tenant: tenant, runner: runner, cancel: cancel}
		a.runnerMu.Unlock()

		go runner.Run(runnerCtx)
		a.logger.Info("runner started for tenant", "tenant", tenant.Slug)
	}
}

func (a *App) stopRunners() {
	a.runnerMu.Lock()
	defer a.runnerMu.Unlock()
	for _, item := range a.runners {
		if item == nil || item.cancel == nil {
			continue
		}
		item.cancel()
		item.cancel = nil
	}
}

func buildTenantRunner(ctx context.Context, logger *slog.Logger, controlStore *store.ControlPlaneStore, tenantStores *store.TenantStoreManager, cfg config.Config, tenant store.Tenant) (*monitorrunner.Runner, error) {
	ts, err := tenantStores.StoreForTenant(ctx, tenant.ID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant db: %w", err)
	}
	notifiers, err := notify.Build(ctx, controlStore, ts, notify.Options{
		TenantID:   tenant.ID,
		TenantSlug: tenant.Slug,
		BaseURL:    cfg.BaseURL,
	})
	if err != nil {
		return nil, err
	}
	runner := monitorrunner.NewRunner(logger, ts, notifiers...)
	runner.SetWorkers(cfg.MonitorWorkers)
	return runner, nil
}

func tenantHasAppDatabase(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// runnerForTenant returns the runner of a tenant, or nil when none is registered.
func (a *App) runnerForTenant(tenantID int64) *monitorrunner.Runner {
	a.runnerMu.Lock()
	defer a.runnerMu.Unlock()
	if item := a.runners[tenantID]; item != nil {
		return item.runner
	}
	return nil
}
