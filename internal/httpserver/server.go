package httpserver

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"goup/internal/auth"
	"goup/internal/config"
	store "goup/internal/store/sqlite"
	"goup/web"
)

type Dependencies struct {
	Config         config.Config
	Logger         *slog.Logger
	Store          *store.Store
	ControlStore   *store.ControlPlaneStore
	AdminCookieKey string
	TenantStores   *store.TenantStoreManager
	DefaultTenant  store.Tenant
	Sessions       *auth.SessionManager
	OIDC           *auth.OIDCManager
}

type Server struct {
	cfg                 config.Config
	logger              *slog.Logger
	store               *store.Store
	controlStore        *store.ControlPlaneStore
	i18n                translationCatalog
	adminCookieKey      string
	tenantStores        *store.TenantStoreManager
	defaultTenant       store.Tenant
	sessions            *auth.SessionManager
	oidc                *auth.OIDCManager
	dynamicOIDC         *auth.DynamicOIDCManager
	templates           map[string]*template.Template
	appMux              http.Handler
	handler             http.Handler
	iconIndexMu         sync.RWMutex
	iconIndex           []dashboardIconEntry
	iconAssetMu         sync.RWMutex
	iconAssets          map[string]dashboardIconAsset
	localLoginMu        sync.Mutex
	localLoginAttempts  map[string]localLoginAttempt
	adminAccessMu       sync.Mutex
	adminAccessAttempts map[string]localLoginAttempt
	bootstrapMu         sync.Mutex
	bootstrapAttempts   map[string]localLoginAttempt
	passwordResetMu     sync.Mutex
	usedResetTokens     map[string]time.Time
}

func New(deps Dependencies) (*Server, error) {
	templates, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	i18n, err := loadTranslationCatalog(web.FS, "i18n")
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:                 deps.Config,
		logger:              deps.Logger,
		store:               deps.Store,
		controlStore:        deps.ControlStore,
		i18n:                i18n,
		adminCookieKey:      strings.TrimSpace(deps.AdminCookieKey),
		tenantStores:        deps.TenantStores,
		defaultTenant:       deps.DefaultTenant,
		sessions:            deps.Sessions,
		oidc:                deps.OIDC,
		dynamicOIDC:         auth.NewDynamicOIDCManager(),
		templates:           templates,
		iconAssets:          make(map[string]dashboardIconAsset),
		localLoginAttempts:  make(map[string]localLoginAttempt),
		adminAccessAttempts: make(map[string]localLoginAttempt),
		bootstrapAttempts:   make(map[string]localLoginAttempt),
		usedResetTokens:     make(map[string]time.Time),
	}
	s.appMux = s.buildAppMux()
	s.handler, err = s.routes()
	if err != nil {
		return nil, fmt.Errorf("build routes: %w", err)
	}

	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go s.runSecurityStateSweeper(ctx)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-errCh
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}
