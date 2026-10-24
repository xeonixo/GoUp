package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	monitorrunner "goup/internal/monitor"
	"goup/internal/notify"
	store "goup/internal/store/sqlite"
)

func (a *App) runRemoteNodeHeartbeatWatch(ctx context.Context) {
	a.checkRemoteNodesHeartbeat(ctx)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.checkRemoteNodesHeartbeat(ctx)
		}
	}
}

func (a *App) checkRemoteNodesHeartbeat(ctx context.Context) {
	nodes, err := a.controlStore.ListAllEnabledRemoteNodes(ctx)
	if err != nil {
		a.logger.Warn("list remote nodes for heartbeat watch failed", "error", err)
		return
	}
	now := time.Now().UTC()
	for _, node := range nodes {
		currentUp := node.IsOnline(now)
		previousUp, seen := a.remoteNodeUp[node.NodeID]
		a.remoteNodeUp[node.NodeID] = currentUp
		if !seen && currentUp {
			continue
		}
		if seen && previousUp == currentUp {
			continue
		}

		appStore, storeErr := a.tenantStores.StoreForTenant(ctx, node.TenantID)
		if storeErr != nil {
			a.logger.Warn("resolve tenant store for remote node heartbeat failed", "tenant_id", node.TenantID, "node_id", node.NodeID, "error", storeErr)
			continue
		}
		tenant, tenantErr := a.controlStore.GetTenantByID(ctx, node.TenantID)
		if tenantErr != nil {
			continue
		}
		transition := monitorrunner.Transition{
			Monitor: monitorrunner.Monitor{
				Name:   "Remote Node " + strings.TrimSpace(node.Name),
				Kind:   monitorrunner.Kind("remote-node"),
				Target: node.NodeID,
			},
			CheckedAt:    now,
			ResultDetail: fmt.Sprintf("last_seen=%v timeout=%ds", node.LastSeenAt, node.HeartbeatTimeoutSeconds),
		}
		if !currentUp {
			transition.Previous = monitorrunner.StatusUp
			transition.Current = monitorrunner.StatusDown
			a.markRemoteNodeMonitorsUnknown(ctx, appStore, node, now)
		} else {
			transition.Previous = monitorrunner.StatusDown
			transition.Current = monitorrunner.StatusUp
		}
		eventType := "status_online"
		if transition.Current == monitorrunner.StatusDown {
			eventType = "status_offline"
		}
		if err := a.controlStore.InsertRemoteNodeEvent(ctx, node.TenantID, node.NodeID, eventType, "control-plane", "GoUp", transition.ResultDetail, now); err != nil {
			a.logger.Warn("record remote node heartbeat status event failed", "node_id", node.NodeID, "event_type", eventType, "error", err)
		}
		notifiers, buildErr := notify.Build(ctx, a.controlStore, appStore, notify.Options{
			TenantID:   node.TenantID,
			TenantSlug: tenant.Slug,
			BaseURL:    a.config.BaseURL,
			AdminOnly:  true,
		})
		if buildErr != nil {
			a.logger.Warn("build notifiers for remote node heartbeat failed", "tenant_id", node.TenantID, "error", buildErr)
			continue
		}
		for _, notifier := range notifiers {
			if notifier == nil || !notifier.Enabled() {
				continue
			}
			notifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := notifier.Notify(notifyCtx, transition)
			cancel()
			if err != nil && err != monitorrunner.ErrNoRecipients {
				a.logger.Warn("remote node heartbeat notification failed", "node_id", node.NodeID, "endpoint_id", notifier.EndpointID(), "error", err)
			}
		}
	}
}

func (a *App) markRemoteNodeMonitorsUnknown(ctx context.Context, appStore *store.Store, node store.RemoteNode, checkedAt time.Time) {
	if appStore == nil {
		return
	}
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}
	assigned, err := appStore.ListMonitorsByExecutor(ctx, "remote", node.NodeID)
	if err != nil {
		a.logger.Warn("list monitors for offline remote node failed", "tenant_id", node.TenantID, "node_id", node.NodeID, "error", err)
		return
	}
	if len(assigned) == 0 {
		return
	}
	snapshots, err := appStore.ListMonitorSnapshots(ctx)
	if err != nil {
		a.logger.Warn("load monitor snapshots for offline remote node failed", "tenant_id", node.TenantID, "node_id", node.NodeID, "error", err)
		return
	}
	previousByID := make(map[int64]*monitorrunner.Result, len(snapshots))
	for i := range snapshots {
		if snapshots[i].LastResult == nil {
			continue
		}
		result := *snapshots[i].LastResult
		previousByID[snapshots[i].Monitor.ID] = &result
	}

	var notifiers []monitorrunner.Notifier
	if a.controlStore != nil {
		tenant, tenantErr := a.controlStore.GetTenantByID(ctx, node.TenantID)
		if tenantErr != nil {
			a.logger.Warn("load tenant for offline remote monitors failed", "tenant_id", node.TenantID, "error", tenantErr)
		} else {
			var buildErr error
			notifiers, buildErr = notify.Build(ctx, a.controlStore, appStore, notify.Options{
				TenantID:   node.TenantID,
				TenantSlug: tenant.Slug,
				BaseURL:    a.config.BaseURL,
			})
			if buildErr != nil {
				a.logger.Warn("build notifiers for offline remote monitors failed", "tenant_id", node.TenantID, "error", buildErr)
			}
		}
	}
	dispatcher := monitorrunner.NewDispatcher(a.logger, appStore, notifiers...)

	nodeName := strings.TrimSpace(node.Name)
	if nodeName == "" {
		nodeName = strings.TrimSpace(node.NodeID)
	}
	message := fmt.Sprintf("remote node %s is offline; monitor state is unknown", nodeName)
	for _, item := range assigned {
		previous := previousByID[item.ID]
		if previous != nil && previous.Status == monitorrunner.StatusUnknown {
			continue
		}
		result := monitorrunner.Result{
			MonitorID: item.ID,
			CheckedAt: checkedAt.UTC(),
			Status:    monitorrunner.StatusUnknown,
			Message:   message,
		}
		// The shared dispatcher saves the result and announces the change with the same
		// notifier set, mute handling and retry queue as the local runner.
		dispatcher.ProcessResult(ctx, monitorrunner.Snapshot{Monitor: item, LastResult: previous}, result)
	}
}
