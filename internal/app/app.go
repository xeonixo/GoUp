package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"goup/internal/auth"
	"goup/internal/config"
	"goup/internal/httpserver"
	monitorrunner "goup/internal/monitor"
	emailnotify "goup/internal/notify/email"
	matrixnotify "goup/internal/notify/matrix"
	store "goup/internal/store/sqlite"
)

type App struct {
	config       config.Config
	logger       *slog.Logger
	store        *store.Store
	controlStore *store.ControlPlaneStore
	tenantStores *store.TenantStoreManager
	server       *httpserver.Server
	runnerMu     sync.Mutex
	runners      map[int64]*tenantRunner
	remoteNodeUp map[string]bool
}

type tenantRunner struct {
	tenant store.Tenant
	runner *monitorrunner.Runner
	cancel context.CancelFunc
}

func New(ctx context.Context) (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)}))

	controlStore, err := store.OpenControlPlane(ctx, cfg.ControlPlaneDBPath)
	if err != nil {
		return nil, err
	}
	sessionKey := strings.TrimSpace(cfg.SessionKey)
	if sessionKey == "" {
		dbSessionKey, keyErr := controlStore.GetOrCreateSessionKey(ctx)
		if keyErr != nil {
			controlStore.Close()
			return nil, fmt.Errorf("load generated session key: %w", keyErr)
		}
		sessionKey = dbSessionKey
	}
	cfg.SessionKey = sessionKey

	secretKey := strings.TrimSpace(cfg.SSOSecretKey)
	if secretKey == "" {
		secretKey = sessionKey
	}
	if err := controlStore.ConfigureSecretKey(secretKey); err != nil {
		controlStore.Close()
		return nil, fmt.Errorf("configure control-plane secret key: %w", err)
	}
	adminCookieKey := strings.TrimSpace(cfg.ControlPlaneAdminKey)
	if adminCookieKey == "" {
		adminCookieKey = secretKey
	}
	// Load all active tenants and start a runner for each one that has a database.
	allTenants, tenantsErr := controlStore.GetAllTenants(ctx)
	if tenantsErr != nil {
		controlStore.Close()
		return nil, fmt.Errorf("load tenants: %w", tenantsErr)
	}

	// Determine the "primary" tenant used for legacy single-tenant OIDC setup and
	// as the TenantStoreManager default: prefer slug=="default", else first active.
	var defaultTenant store.Tenant
	for _, t := range allTenants {
		if t.Slug == "default" && t.Active {
			defaultTenant = t
			break
		}
	}
	if defaultTenant.ID == 0 {
		for _, t := range allTenants {
			if t.Active {
				defaultTenant = t
				break
			}
		}
	}

	hasGlobalOIDC := strings.TrimSpace(cfg.Auth.OIDC.IssuerURL) != "" && strings.TrimSpace(cfg.Auth.OIDC.ClientID) != "" && strings.TrimSpace(cfg.Auth.OIDC.ClientSecret) != ""

	// If OIDC is enabled, ensure default provider for primary tenant.
	if cfg.Auth.Mode == config.AuthModeOIDC && hasGlobalOIDC && defaultTenant.ID > 0 {
		if _, err := controlStore.EnsureDefaultOIDCProvider(ctx, defaultTenant.ID, cfg.Auth.OIDC.IssuerURL, cfg.Auth.OIDC.ClientID, cfg.Auth.OIDC.ClientSecret); err != nil {
			controlStore.Close()
			return nil, fmt.Errorf("ensure default oidc provider: %w", err)
		}
	}

	// Open a store for the primary tenant (used by TenantStoreManager as default).
	var sqliteStore *store.Store
	if defaultTenant.ID > 0 && tenantHasAppDatabase(defaultTenant.DBPath) {
		sqliteStore, err = store.Open(ctx, defaultTenant.DBPath)
		if err != nil {
			controlStore.Close()
			return nil, err
		}
	}

	sessions := auth.NewSessionManager([]byte(sessionKey), cfg.SecureCookies())

	var oidcManager *auth.OIDCManager
	if cfg.Auth.Mode == config.AuthModeOIDC && hasGlobalOIDC {
		oidcManager, err = auth.NewOIDCManager(ctx, cfg)
		if err != nil {
			if sqliteStore != nil {
				sqliteStore.Close()
			}
			controlStore.Close()
			return nil, fmt.Errorf("initialize oidc: %w", err)
		}
	}

	tenantStores := store.NewTenantStoreManager(controlStore, defaultTenant, sqliteStore)

	// Build one runner per active tenant that has a database.
	runners := make(map[int64]*tenantRunner, len(allTenants))
	for _, t := range allTenants {
		if !t.Active || !tenantHasAppDatabase(t.DBPath) {
			continue
		}
		runner, err := buildTenantRunner(ctx, logger, controlStore, tenantStores, cfg, t)
		if err != nil {
			logger.Warn("failed to initialize runner for tenant", "tenant", t.Slug, "error", err)
			continue
		}
		runners[t.ID] = &tenantRunner{tenant: t, runner: runner}
		logger.Info("runner initialized for tenant", "tenant", t.Slug)
	}

	server, err := httpserver.New(httpserver.Dependencies{
		Config:         cfg,
		Logger:         logger,
		Store:          sqliteStore,
		ControlStore:   controlStore,
		AdminCookieKey: adminCookieKey,
		TenantStores:   tenantStores,
		DefaultTenant:  defaultTenant,
		Sessions:       sessions,
		OIDC:           oidcManager,
	})
	if err != nil {
		if sqliteStore != nil {
			sqliteStore.Close()
		}
		controlStore.Close()
		return nil, err
	}

	logger.Info("initialized application", "control_db_path", filepath.Clean(cfg.ControlPlaneDBPath), "auth_mode", cfg.Auth.Mode)

	return &App{
		config:       cfg,
		logger:       logger,
		store:        sqliteStore,
		controlStore: controlStore,
		tenantStores: tenantStores,
		server:       server,
		runners:      runners,
		remoteNodeUp: make(map[string]bool),
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	a.startConfiguredRunners(ctx)
	if a.controlStore != nil {
		go a.runRemoteNodeHeartbeatWatch(ctx)
	}
	if a.controlStore != nil && a.tenantStores != nil {
		go a.runMaintenance(ctx)
		go a.runRunnerReconcile(ctx)
	}
	a.logger.Info("starting server", "addr", a.config.Addr)
	return a.server.Run(ctx)
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
		if !seen || previousUp == currentUp {
			continue
		}

		appStore, storeErr := a.tenantStores.StoreForTenant(ctx, node.TenantID)
		if storeErr != nil {
			a.logger.Warn("resolve tenant store for remote node heartbeat failed", "tenant_id", node.TenantID, "node_id", node.NodeID, "error", storeErr)
			continue
		}
		matrixEndpointID, emailEndpointID, endpointErr := ensureNotifierEndpoints(ctx, appStore)
		if endpointErr != nil {
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
		if previousUp {
			transition.Previous = monitorrunner.StatusUp
			transition.Current = monitorrunner.StatusDown
		} else {
			transition.Previous = monitorrunner.StatusDown
			transition.Current = monitorrunner.StatusUp
		}
		notifiers := []monitorrunner.Notifier{
			matrixnotify.NewTenantNotifier(a.controlStore, matrixEndpointID, node.TenantID),
			emailnotify.NewNotifier(a.controlStore, emailEndpointID, node.TenantID, a.config.BaseURL, tenant.Slug),
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
	for _, tenant := range tenants {
		if !tenant.Active || !tenantHasAppDatabase(tenant.DBPath) {
			continue
		}
		tenantStore, err := a.tenantStores.StoreForTenant(ctx, tenant.ID)
		if err != nil {
			a.logger.Warn("resolve tenant store for maintenance failed", "tenant", tenant.Slug, "error", err)
			continue
		}
		result, err := tenantStore.RunMaintenance(ctx, now)
		if err != nil {
			a.logger.Error("database maintenance failed", "tenant", tenant.Slug, "error", err)
			continue
		}

		if !result.BackfilledHourlyRollups && !result.Optimized && result.DeletedRawResults == 0 && result.DeletedHourlyRollups == 0 {
			continue
		}

		a.logger.Info(
			"database maintenance completed",
			"tenant", tenant.Slug,
			"hourly_rollups_backfilled", result.BackfilledHourlyRollups,
			"raw_results_deleted", result.DeletedRawResults,
			"hourly_rollups_deleted", result.DeletedHourlyRollups,
			"optimized", result.Optimized,
		)
	}
}

func (a *App) Close() error {
	var firstErr error
	a.stopRunners()
	if a.tenantStores != nil {
		if err := a.tenantStores.Close(); err != nil {
			firstErr = err
		}
	}
	if a.store != nil {
		if err := a.store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if a.controlStore != nil {
		if err := a.controlStore.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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

func parseLogLevel(value string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func ensureNotifierEndpoints(ctx context.Context, s *store.Store) (matrixID, emailID int64, err error) {
	matrixID, err = s.EnsureSystemNotificationEndpoint(ctx, "matrix", "user-matrix", `{}`, true)
	if err != nil {
		return 0, 0, fmt.Errorf("matrix: %w", err)
	}
	emailID, err = s.EnsureSystemNotificationEndpoint(ctx, "email", "user-email", `{}`, true)
	if err != nil {
		return 0, 0, fmt.Errorf("email: %w", err)
	}
	return matrixID, emailID, nil
}

func buildTenantRunner(ctx context.Context, logger *slog.Logger, controlStore *store.ControlPlaneStore, tenantStores *store.TenantStoreManager, cfg config.Config, tenant store.Tenant) (*monitorrunner.Runner, error) {
	ts, err := tenantStores.StoreForTenant(ctx, tenant.ID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant db: %w", err)
	}
	matrixEndpointID, emailEndpointID, endpointErr := ensureNotifierEndpoints(ctx, ts)
	if endpointErr != nil {
		return nil, endpointErr
	}
	return monitorrunner.NewRunner(
		logger,
		ts,
		matrixnotify.NewTenantNotifier(controlStore, matrixEndpointID, tenant.ID),
		emailnotify.NewNotifier(controlStore, emailEndpointID, tenant.ID, cfg.BaseURL, tenant.Slug),
	), nil
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
