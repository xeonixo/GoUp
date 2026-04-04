package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	runner       *monitorrunner.Runner
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
	secretKey := strings.TrimSpace(cfg.SSOSecretKey)
	if secretKey == "" {
		secretKey = cfg.SessionKey
	}
	if err := controlStore.ConfigureSecretKey(secretKey); err != nil {
		controlStore.Close()
		return nil, fmt.Errorf("configure control-plane secret key: %w", err)
	}
	defaultTenant, err := controlStore.EnsureDefaultTenant(ctx, "Default", "default", cfg.DBPath)
	if err != nil {
		controlStore.Close()
		return nil, fmt.Errorf("ensure default tenant: %w", err)
	}
	hasGlobalOIDC := strings.TrimSpace(cfg.Auth.OIDC.IssuerURL) != "" && strings.TrimSpace(cfg.Auth.OIDC.ClientID) != "" && strings.TrimSpace(cfg.Auth.OIDC.ClientSecret) != ""

	// If OIDC is enabled, ensure default provider for default tenant
	if cfg.Auth.Mode == config.AuthModeOIDC && hasGlobalOIDC {
		if _, err := controlStore.EnsureDefaultOIDCProvider(ctx, defaultTenant.ID, cfg.Auth.OIDC.IssuerURL, cfg.Auth.OIDC.ClientID, cfg.Auth.OIDC.ClientSecret); err != nil {
			controlStore.Close()
			return nil, fmt.Errorf("ensure default oidc provider: %w", err)
		}
	}

	sqliteStore, err := store.Open(ctx, defaultTenant.DBPath)
	if err != nil {
		controlStore.Close()
		return nil, err
	}

	sessions := auth.NewSessionManager([]byte(cfg.SessionKey), cfg.SecureCookies())

	var oidcManager *auth.OIDCManager
	if cfg.Auth.Mode == config.AuthModeOIDC && hasGlobalOIDC {
		oidcManager, err = auth.NewOIDCManager(ctx, cfg)
		if err != nil {
			sqliteStore.Close()
			controlStore.Close()
			return nil, fmt.Errorf("initialize oidc: %w", err)
		}
	}

	matrixClient := matrixnotify.New(cfg.Matrix)
	matrixConfigJSON, marshalErr := json.Marshal(map[string]string{
		"homeserver_url": cfg.Matrix.HomeserverURL,
		"room_id":        cfg.Matrix.RoomID,
	})
	if marshalErr != nil {
		sqliteStore.Close()
		controlStore.Close()
		return nil, fmt.Errorf("marshal matrix endpoint config: %w", marshalErr)
	}

	matrixEndpointID, err := sqliteStore.EnsureSystemNotificationEndpoint(ctx, "matrix", "system-matrix", string(matrixConfigJSON), matrixClient.Enabled())
	if err != nil {
		sqliteStore.Close()
		controlStore.Close()
		return nil, fmt.Errorf("ensure matrix endpoint: %w", err)
	}

	emailEnabled := len(cfg.Notify.EmailRecipients) > 0
	emailConfigJSON, marshalErr := json.Marshal(map[string]any{
		"recipients": cfg.Notify.EmailRecipients,
	})
	if marshalErr != nil {
		sqliteStore.Close()
		controlStore.Close()
		return nil, fmt.Errorf("marshal email endpoint config: %w", marshalErr)
	}

	emailEndpointID, err := sqliteStore.EnsureSystemNotificationEndpoint(ctx, "email", "system-email", string(emailConfigJSON), emailEnabled)
	if err != nil {
		sqliteStore.Close()
		controlStore.Close()
		return nil, fmt.Errorf("ensure email endpoint: %w", err)
	}

	tenantStores := store.NewTenantStoreManager(controlStore, defaultTenant, sqliteStore)
	runner := monitorrunner.NewRunner(
		logger,
		sqliteStore,
		matrixnotify.NewNotifier(matrixClient, matrixEndpointID),
		emailnotify.NewNotifier(controlStore, emailEndpointID, defaultTenant.ID, cfg.Notify.EmailRecipients, cfg.Notify.EmailSubjectPrefix),
	)

	server, err := httpserver.New(httpserver.Dependencies{
		Config:        cfg,
		Logger:        logger,
		Store:         sqliteStore,
		ControlStore:  controlStore,
		TenantStores:  tenantStores,
		DefaultTenant: defaultTenant,
		Sessions:      sessions,
		OIDC:          oidcManager,
	})
	if err != nil {
		sqliteStore.Close()
		controlStore.Close()
		return nil, err
	}

	logger.Info("initialized application", "db_path", filepath.Clean(cfg.DBPath), "control_db_path", filepath.Clean(cfg.ControlPlaneDBPath), "auth_mode", cfg.Auth.Mode)

	return &App{
		config:       cfg,
		logger:       logger,
		store:        sqliteStore,
		controlStore: controlStore,
		tenantStores: tenantStores,
		server:       server,
		runner:       runner,
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	if a.runner != nil {
		go a.runner.Run(ctx)
	}
	if a.store != nil {
		go a.runMaintenance(ctx)
	}
	a.logger.Info("starting server", "addr", a.config.Addr)
	return a.server.Run(ctx)
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
	result, err := a.store.RunMaintenance(ctx, time.Now().UTC())
	if err != nil {
		a.logger.Error("database maintenance failed", "error", err)
		return
	}

	if !result.BackfilledHourlyRollups && !result.Optimized && result.DeletedRawResults == 0 {
		return
	}

	a.logger.Info(
		"database maintenance completed",
		"hourly_rollups_backfilled", result.BackfilledHourlyRollups,
		"raw_results_deleted", result.DeletedRawResults,
		"optimized", result.Optimized,
	)
}

func (a *App) Close() error {
	var firstErr error
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
