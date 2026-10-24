package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"goup/internal/auth"
	"goup/internal/config"
	"goup/internal/httpserver"
	monitorrunner "goup/internal/monitor"
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

func New(ctx context.Context) (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)}))
	store.HardenDataDir(cfg.DataDir)
	monitorrunner.SetAllowPrivateTargets(cfg.MonitorAllowPrivate)

	controlStore, err := store.OpenControlPlane(ctx, cfg.ControlPlaneDBPath)
	if err != nil {
		return nil, err
	}
	sessionKey := strings.TrimSpace(cfg.SessionKey)
	cfg.SessionKey = sessionKey

	secretKey := strings.TrimSpace(cfg.SSOSecretKey)
	sessionSecretFallback := strings.TrimSpace(cfg.SessionKey)
	if err := controlStore.ConfigureSecretKeys(secretKey, sessionSecretFallback); err != nil {
		controlStore.Close()
		return nil, fmt.Errorf("configure control-plane secret key: %w", err)
	}
	adminCookieKey := strings.TrimSpace(cfg.ControlPlaneAdminKey)
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

	var app *App
	runnerLookup := func(tenantID int64) *monitorrunner.Runner {
		if app == nil {
			return nil
		}
		return app.runnerForTenant(tenantID)
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
		RunnerLookup:   runnerLookup,
	})
	if err != nil {
		if sqliteStore != nil {
			sqliteStore.Close()
		}
		controlStore.Close()
		return nil, err
	}

	logger.Info("initialized application", "control_db_path", filepath.Clean(cfg.ControlPlaneDBPath), "auth_mode", cfg.Auth.Mode)

	app = &App{
		config:       cfg,
		logger:       logger,
		store:        sqliteStore,
		controlStore: controlStore,
		tenantStores: tenantStores,
		server:       server,
		runners:      runners,
		remoteNodeUp: make(map[string]bool),
	}
	return app, nil
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
