package app

import (
	"context"
	"fmt"
)

// Ready returns failure reasons when the process is not ready to serve traffic.
// An empty slice means ready.
func (a *App) Ready(ctx context.Context) []string {
	reasons := make([]string, 0, 4)

	if a.controlStore == nil {
		reasons = append(reasons, "control_plane: unavailable")
	} else if err := a.controlStore.Healthcheck(ctx); err != nil {
		reasons = append(reasons, "control_plane: "+err.Error())
	}

	tenantsChecked := 0
	if a.controlStore != nil && a.tenantStores != nil {
		tenants, err := a.controlStore.GetAllTenants(ctx)
		if err != nil {
			reasons = append(reasons, "tenants: "+err.Error())
		} else {
			for _, tenant := range tenants {
				if !tenant.Active || !tenantHasAppDatabase(tenant.DBPath) {
					continue
				}
				tenantsChecked++
				tenantStore, storeErr := a.tenantStores.StoreForTenant(ctx, tenant.ID)
				if storeErr != nil {
					reasons = append(reasons, fmt.Sprintf("tenant_store:%s: %v", tenant.Slug, storeErr))
					continue
				}
				if pingErr := tenantStore.Healthcheck(ctx); pingErr != nil {
					reasons = append(reasons, fmt.Sprintf("tenant_store:%s: %v", tenant.Slug, pingErr))
					continue
				}
				if runner := a.runnerForTenant(tenant.ID); runner == nil {
					reasons = append(reasons, fmt.Sprintf("runner:%s: missing", tenant.Slug))
				}
			}
		}
	}

	// When no active tenant databases exist yet, ping the default store if present.
	if tenantsChecked == 0 && a.store != nil {
		if err := a.store.Healthcheck(ctx); err != nil {
			reasons = append(reasons, "tenant_store:default: "+err.Error())
		}
	}

	return reasons
}
