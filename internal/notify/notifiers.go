// Package notify assembles the notifier set used for a tenant. Every code path that announces
// monitor transitions (local runner, remote node reports, offline handling) builds its
// notifiers here, so a new channel only has to be added in one place.
package notify

import (
	"context"
	"fmt"

	"goup/internal/monitor"
	emailnotify "goup/internal/notify/email"
	matrixnotify "goup/internal/notify/matrix"
	webhooknotify "goup/internal/notify/webhook"
	store "goup/internal/store/sqlite"
)

// Options selects how the notifier set is built.
type Options struct {
	TenantID   int64
	TenantSlug string
	BaseURL    string
	// AdminOnly restricts Matrix and e-mail recipients to tenant admins (infrastructure alerts
	// such as a remote node going offline). Webhooks are unaffected.
	AdminOnly bool
}

// EnsureSystemEndpoints makes sure the per-tenant Matrix and e-mail endpoint rows exist.
func EnsureSystemEndpoints(ctx context.Context, appStore *store.Store) (matrixID, emailID int64, err error) {
	matrixID, err = appStore.EnsureSystemNotificationEndpoint(ctx, "matrix", "user-matrix", `{}`, true)
	if err != nil {
		return 0, 0, fmt.Errorf("matrix: %w", err)
	}
	emailID, err = appStore.EnsureSystemNotificationEndpoint(ctx, "email", "user-email", `{}`, true)
	if err != nil {
		return 0, 0, fmt.Errorf("email: %w", err)
	}
	return matrixID, emailID, nil
}

// Build returns the full notifier set for a tenant: Matrix, e-mail and webhooks.
func Build(ctx context.Context, controlStore *store.ControlPlaneStore, appStore *store.Store, opts Options) ([]monitor.Notifier, error) {
	matrixID, emailID, err := EnsureSystemEndpoints(ctx, appStore)
	if err != nil {
		return nil, err
	}
	var matrix, email monitor.Notifier
	if opts.AdminOnly {
		matrix = matrixnotify.NewTenantAdminNotifier(controlStore, matrixID, opts.TenantID)
		email = emailnotify.NewTenantAdminNotifier(controlStore, emailID, opts.TenantID, opts.BaseURL, opts.TenantSlug)
	} else {
		matrix = matrixnotify.NewTenantNotifier(controlStore, matrixID, opts.TenantID)
		email = emailnotify.NewNotifier(controlStore, emailID, opts.TenantID, opts.BaseURL, opts.TenantSlug)
	}
	return []monitor.Notifier{
		matrix,
		email,
		webhooknotify.NewNotifier(appStore, controlStore, opts.TenantID),
	}, nil
}
