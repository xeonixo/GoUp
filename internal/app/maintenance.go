package app

import (
	"context"
	"time"

	store "goup/internal/store/sqlite"
)

func (a *App) runMaintenance(ctx context.Context) {
	a.runMaintenanceOnce(ctx)

	ticker := time.NewTicker(store.MaintenanceInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runMaintenanceOnce(ctx)
		}
	}
}

func (a *App) runMaintenanceOnce(ctx context.Context) {
	tenants, err := a.controlStore.GetAllTenants(ctx)
	if err != nil {
		a.logger.Error("load tenants for maintenance failed", "error", err)
		return
	}
	now := time.Now().UTC()

	controlResult, err := a.controlStore.RunMaintenance(ctx, now)
	if err != nil {
		a.logger.Error("control-plane maintenance failed", "error", err)
	} else {
		if controlResult.CompactionSkipped != "" {
			a.logger.Warn("control-plane compaction skipped", "reason", controlResult.CompactionSkipped)
		}
		if controlResult.DeletedRemoteNodeEvents > 0 || controlResult.Vacuumed {
			a.logger.Info(
				"control-plane maintenance completed",
				"remote_node_events_deleted", controlResult.DeletedRemoteNodeEvents,
				"vacuumed", controlResult.Vacuumed,
			)
		}
	}

	for _, tenant := range tenants {
		if !tenant.Active || !tenantHasAppDatabase(tenant.DBPath) {
			continue
		}
		tenantStore, err := a.tenantStores.StoreForTenant(ctx, tenant.ID)
		if err != nil {
			a.logger.Warn("resolve tenant store for maintenance failed", "tenant", tenant.Slug, "error", err)
			continue
		}
		result, err := tenantStore.RunMaintenance(ctx, now, store.MaintenanceOptions{
			StateEventRetentionDays:        tenant.StateEventRetentionDays,
			NotificationEventRetentionDays: tenant.NotificationEventRetentionDays,
			RawResultRetentionDays:         tenant.RawResultRetentionDays,
		})
		if err != nil {
			a.logger.Error("database maintenance failed", "tenant", tenant.Slug, "error", err)
			continue
		}
		if result.CompactionSkipped != "" {
			a.logger.Warn("database compaction skipped", "tenant", tenant.Slug, "reason", result.CompactionSkipped)
		}

		if !result.BackfilledHourlyRollups &&
			!result.Optimized &&
			!result.Vacuumed &&
			result.DeletedRawResults == 0 &&
			result.DeletedHourlyRollups == 0 &&
			result.DeletedStateEvents == 0 &&
			result.DeletedNotificationEvents == 0 {
			continue
		}

		a.logger.Info(
			"database maintenance completed",
			"tenant", tenant.Slug,
			"hourly_rollups_backfilled", result.BackfilledHourlyRollups,
			"raw_results_deleted", result.DeletedRawResults,
			"hourly_rollups_deleted", result.DeletedHourlyRollups,
			"state_events_deleted", result.DeletedStateEvents,
			"notification_events_deleted", result.DeletedNotificationEvents,
			"optimized", result.Optimized,
			"vacuumed", result.Vacuumed,
		)
	}
}
