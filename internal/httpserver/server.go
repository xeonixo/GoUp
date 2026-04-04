package httpserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	webassets "goup/assets"
	"goup/internal/auth"
	"goup/internal/config"
	"goup/internal/monitor"
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
	iconIndexFetchedAt  time.Time
	localLoginMu        sync.Mutex
	localLoginAttempts  map[string]localLoginAttempt
	adminAccessMu       sync.Mutex
	adminAccessAttempts map[string]localLoginAttempt
}

type localLoginAttempt struct {
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
}

type pageData struct {
	Title               string
	HideTopbar          bool
	User                *auth.UserSession
	IsAdmin             bool
	Stats               store.DashboardStats
	Error               string
	Notice              string
	FormAction          string
	BackURL             string
	IsEdit              bool
	SettingsMode        bool
	AuthEnabled         bool
	AuthDisabled        bool
	OIDCTenantOnly      bool
	TrendValue          string
	TrendLabel          string
	TrendRanges         []trendRangeOptionView
	Monitors            []monitorView
	MonitorGroups       []monitorGroupView
	AvailableGroups     []string
	Events              []notificationEventView
	StateEvents         []monitorStateEventView
	AdminTenants        []store.Tenant
	AdminTenant         store.Tenant
	AdminProviders      []store.AuthProvider
	AdminProvider       store.AuthProvider
	AdminLocalUsers     []store.LocalUser
	AdminTenantUsers    []store.TenantUser
	AdminLocalUser      store.LocalUser
	ProfileUser         store.TenantUser
	ProfileNotify       store.UserNotificationSettings
	AdminAuditEvents    []store.AuditEvent
	AuditAction         string
	AuditActor          string
	AuditTargetType     string
	AuditActions        []string
	AuditTargetTypes    []string
	GlobalSMTP          store.GlobalSMTPSettings
	ControlPlaneAdmin   bool
	AutoDBPath          string
	TenantSlug          string
	TenantName          string
	AppBase             string
	LoginProviders      []store.AuthProvider
	HasLocalLogin       bool
	HasOIDCLogin        bool
	ResetEnabled        bool
	ResetToken          string
	AdminSetup          bool
	AdminUsername       string
	TOTPRequired        bool
	TOTPEnabled         bool
	TOTPSecret          string
	TOTPProvisioningURI string
}

const (
	localLoginMaxFailures  = 5
	localLoginWindow       = 10 * time.Minute
	localLoginLockout      = 15 * time.Minute
	adminAccessMaxFailures = 10
	adminAccessWindow      = 5 * time.Minute
	adminAccessLockout     = 30 * time.Minute
	passwordResetTTL       = 30 * time.Minute
	controlPlaneAdminTTL   = 12 * time.Hour
	controlPlaneCookie     = "goup_cp_admin"
)

type monitorGroupView struct {
	Title       string
	Subtitle    string
	EmptyText   string
	AccentClass string
	Monitors    []monitorView
	Services    []monitorServiceGroupView
	Count       int
	ServiceHint string
}

type monitorServiceGroupView struct {
	Title       string
	Subtitle    string
	StatusLabel string
	StatusClass string
	StatusInfo  string
	TrendLabel  string
	UptimeLabel string
	TrendPoints []trendPointView
	IconSlug    string
	IconURL     string
	Monitors    []monitorView
	Open        bool
	CanMoveUp   bool
	CanMoveDown bool
}

type trendRangeOptionView struct {
	Value    string
	Label    string
	Selected bool
}

type dashboardIconMetadata struct {
	Aliases    []string `json:"aliases"`
	Categories []string `json:"categories"`
}

type dashboardIconEntry struct {
	Slug       string
	Label      string
	SearchText string
}

type dashboardIconSearchResult struct {
	Slug  string `json:"slug"`
	Label string `json:"label"`
	URL   string `json:"url"`
}

type trendPointView struct {
	BucketRaw string
	Percent   int
	Class     string
	Label     string
	Format    string
	Checks    int
	AvgMS     int
	MinMS     int
	MaxMS     int
}

type monitorView struct {
	ID               int64
	Name             string
	Group            string
	SortOrder        int
	CanMoveUp        bool
	CanMoveDown      bool
	KindValue        string
	Kind             string
	TLSMode          string
	TLSModeValue     string
	Target           string
	TargetLabel      string
	Interval         string
	IntervalSeconds  int
	Timeout          string
	TimeoutSeconds   int
	Enabled          bool
	NotifyOnRecovery bool
	ExpectedStatus   string
	ExpectedText     string
	TrendLabel       string
	StatusLabel      string
	StatusClass      string
	StatusSummary    string
	LastCheckedAt    string
	LastCheckedAtRaw string
	LastStatus       string
	LastMessage      string
	LastLatency      string
	TrendPoints      []trendPointView
	UptimeLabel      string
	HTTPStatusCode   string
	TLSDaysRemaining string
	TLSNotAfter      string
	TLSNotAfterRaw   string
}

type notificationEventView struct {
	ID             int64
	When           string
	WhenRaw        string
	Monitor        string
	EventType      string
	Endpoint       string
	Result         string
	Error          string
	DeliveredAt    string
	DeliveredAtRaw string
}

type monitorStateEventView struct {
	ID        int64
	When      string
	WhenRaw   string
	Monitor   string
	From      string
	FromClass string
	To        string
	ToClass   string
	Message   string
}

type trendRange struct {
	Value      string
	Label      string
	BucketSize time.Duration
	Buckets    int
	Step       string
}

var supportedTrendRanges = []trendRange{
	{Value: "24h", Label: "24h", BucketSize: time.Hour, Buckets: 24, Step: "hour"},
	{Value: "7d", Label: "7d", BucketSize: 24 * time.Hour, Buckets: 7, Step: "day"},
	{Value: "30d", Label: "30d", BucketSize: 24 * time.Hour, Buckets: 30, Step: "day"},
	{Value: "12m", Label: "12M", BucketSize: 24 * time.Hour, Buckets: 12, Step: "month"},
}

const (
	dashboardIconsBaseURL     = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons"
	dashboardIconsMetadataURL = "https://raw.githubusercontent.com/homarr-labs/dashboard-icons/refs/heads/main/metadata.json"
	dashboardIconCacheTTL     = 6 * time.Hour
	dashboardIconSearchLimit  = 24
)

func New(deps Dependencies) (*Server, error) {
	templates, err := parseTemplates()
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:                 deps.Config,
		logger:              deps.Logger,
		store:               deps.Store,
		controlStore:        deps.ControlStore,
		adminCookieKey:      strings.TrimSpace(deps.AdminCookieKey),
		tenantStores:        deps.TenantStores,
		defaultTenant:       deps.DefaultTenant,
		sessions:            deps.Sessions,
		oidc:                deps.OIDC,
		dynamicOIDC:         auth.NewDynamicOIDCManager(),
		templates:           templates,
		localLoginAttempts:  make(map[string]localLoginAttempt),
		adminAccessAttempts: make(map[string]localLoginAttempt),
	}
	s.appMux = s.buildAppMux()
	s.handler = s.routes()

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

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	staticFS, err := fs.Sub(web.FS, "static")
	if err != nil {
		panic(err)
	}
	assetsFS, err := fs.Sub(webassets.FS, ".")
	if err != nil {
		panic(err)
	}
	faviconFS, err := fs.Sub(webassets.FS, "favicon")
	if err != nil {
		panic(err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assetsFS))))
	mux.Handle("/favicon/", http.StripPrefix("/favicon/", http.FileServer(http.FS(faviconFS))))
	mux.HandleFunc("/favicon.ico", serveEmbeddedFile(faviconFS, "favicon.ico"))
	mux.HandleFunc("/favicon-16x16.png", serveEmbeddedFile(faviconFS, "favicon-16x16.png"))
	mux.HandleFunc("/favicon-32x32.png", serveEmbeddedFile(faviconFS, "favicon-32x32.png"))
	mux.HandleFunc("/apple-touch-icon.png", serveEmbeddedFile(faviconFS, "apple-touch-icon.png"))
	mux.HandleFunc("/android-chrome-192x192.png", serveEmbeddedFile(faviconFS, "android-chrome-192x192.png"))
	mux.HandleFunc("/android-chrome-512x512.png", serveEmbeddedFile(faviconFS, "android-chrome-512x512.png"))
	mux.HandleFunc("/site.webmanifest", serveEmbeddedFile(faviconFS, "site.webmanifest"))
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/auth/login", s.handleGlobalAuthDisabled)
	mux.HandleFunc("/auth/callback", s.handleGlobalAuthDisabled)
	mux.HandleFunc("/auth/logout", s.handleLogout)

	// Control-plane admin routes (separate access mechanism, no tenant session required)
	mux.HandleFunc("/admin/setup", s.handleAdminSetup)
	mux.HandleFunc("/admin/access", s.handleAdminAccess)
	mux.Handle("/admin/security", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminSecuritySettings)))
	mux.Handle("/admin/security/totp/disable", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTOTPDisable)))
	mux.Handle("/admin/", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminDashboard)))
	mux.Handle("/admin/tenants", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTenantsList)))
	mux.Handle("/admin/tenants/new", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTenantForm)))
	mux.Handle("/admin/tenants/{id}/edit", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTenantForm)))
	mux.Handle("/admin/tenants/save", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTenantSave)))
	mux.Handle("/admin/tenants/{id}/delete", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTenantDelete)))
	mux.Handle("/admin/tenants/{id}/purge", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTenantPurge)))
	mux.Handle("/admin/tenants/{id}/providers", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminProvidersList)))
	mux.Handle("/admin/tenants/{id}/providers/new", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminProviderForm)))
	mux.Handle("/admin/tenants/{id}/providers/{providerKey}/edit", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminProviderForm)))
	mux.Handle("/admin/tenants/{id}/providers/save", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminProviderSave)))
	mux.Handle("/admin/tenants/{id}/providers/{providerKey}/delete", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminProviderDelete)))
	mux.Handle("/admin/tenants/{id}/local-users", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminLocalUsersList)))
	mux.Handle("/admin/tenants/{id}/local-users/new", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminLocalUserForm)))
	mux.Handle("/admin/tenants/{id}/local-users/{userID}/edit", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminLocalUserForm)))
	mux.Handle("/admin/tenants/{id}/local-users/save", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminLocalUserSave)))
	mux.Handle("/admin/tenants/{id}/local-users/{userID}/delete", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminLocalUserDelete)))
	mux.Handle("/admin/tenants/{id}/users/{userID}/remove", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTenantUserRemove)))
	mux.Handle("/admin/settings/smtp/save", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminSMTPSettingsSave)))

	return s.logging(s.securityHeaders(s.requireSameOrigin(mux)))
}

func serveEmbeddedFile(fsys fs.FS, fileName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		payload, err := fs.ReadFile(fsys, fileName)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		contentType := mime.TypeByExtension(path.Ext(fileName))
		if contentType == "" {
			contentType = http.DetectContentType(payload)
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")

		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(payload)
	}
}

func (s *Server) handleGlobalAuthDisabled(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "tenant slug required (use /{tenant}/auth/login)", http.StatusNotFound)
}

func (s *Server) requireSameOrigin(next http.Handler) http.Handler {
	expected, err := url.Parse(s.cfg.BaseURL)
	if err != nil || expected.Scheme == "" || expected.Host == "" {
		return next
	}
	expectedScheme := strings.ToLower(strings.TrimSpace(expected.Scheme))
	expectedHost := strings.ToLower(strings.TrimSpace(expected.Hostname()))
	expectedPort := strings.TrimSpace(expected.Port())

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			next.ServeHTTP(w, r)
			return
		}

		allowedOrigins := make(map[string]struct{})
		for _, origin := range buildAllowedOrigins(expectedScheme, expectedHost, expectedPort, r) {
			allowedOrigins[origin] = struct{}{}
		}

		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			normalizedOrigin := normalizeOrigin(origin)
			if normalizedOrigin == "" {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
			if _, ok := allowedOrigins[normalizedOrigin]; !ok {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
			normalizedRefererOrigin := normalizeRefererOrigin(referer)
			if normalizedRefererOrigin == "" {
				http.Error(w, "invalid referer", http.StatusForbidden)
				return
			}
			if _, ok := allowedOrigins[normalizedRefererOrigin]; !ok {
				http.Error(w, "invalid referer", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Neither Origin nor Referer present on a mutating request: reject.
		// Legitimate browser-initiated form submissions always include at least one.
		// Non-browser API clients should supply Origin.
		http.Error(w, "origin or referer required", http.StatusForbidden)
	})
}

func buildAllowedOrigins(expectedScheme, expectedHost, expectedPort string, r *http.Request) []string {
	origins := make(map[string]struct{})
	addOriginCandidate(origins, expectedScheme, expectedHost, expectedPort)

	requestScheme := expectedScheme
	if strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")) != "" {
		requestScheme = strings.ToLower(strings.TrimSpace(strings.Split(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), ",")[0]))
	}
	requestHost := strings.ToLower(strings.TrimSpace(r.Host))
	if requestHost != "" {
		hostname := requestHost
		port := ""
		if strings.Contains(requestHost, ":") {
			if parsedHost, parsedPort, err := net.SplitHostPort(requestHost); err == nil {
				hostname = strings.ToLower(strings.TrimSpace(parsedHost))
				port = strings.TrimSpace(parsedPort)
			}
		}
		addOriginCandidate(origins, requestScheme, hostname, port)
	}

	for _, host := range []string{expectedHost, strings.ToLower(strings.TrimSpace(r.URL.Hostname()))} {
		if host == "" {
			continue
		}
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			for _, alt := range []string{"localhost", "127.0.0.1", "[::1]"} {
				addOriginCandidate(origins, expectedScheme, alt, expectedPort)
			}
		}
	}

	result := make([]string, 0, len(origins))
	for value := range origins {
		result = append(result, value)
	}
	return result
}

func addOriginCandidate(set map[string]struct{}, scheme, host, port string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		scheme = "http"
	}
	port = strings.TrimSpace(port)
	if port != "" {
		set[scheme+"://"+strings.ToLower(host)+":"+port] = struct{}{}
		return
	}
	set[scheme+"://"+strings.ToLower(host)] = struct{}{}
}

func normalizeOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return ""
	}
	if port := strings.TrimSpace(parsed.Port()); port != "" {
		return strings.ToLower(parsed.Scheme) + "://" + host + ":" + port
	}
	return strings.ToLower(parsed.Scheme) + "://" + host
}

func normalizeRefererOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return ""
	}
	if port := strings.TrimSpace(parsed.Port()); port != "" {
		return strings.ToLower(parsed.Scheme) + "://" + host + ":" + port
	}
	return strings.ToLower(parsed.Scheme) + "://" + host
}

type tenantSlugContextKey struct{}
type tenantIDContextKey struct{}

func requestWithTenantSlug(r *http.Request, slug string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), tenantSlugContextKey{}, strings.TrimSpace(slug)))
}

func requestWithTenantID(r *http.Request, tenantID int64) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), tenantIDContextKey{}, tenantID))
}

func tenantIDFromRequest(r *http.Request) int64 {
	if id, ok := r.Context().Value(tenantIDContextKey{}).(int64); ok {
		return id
	}
	return 0
}

func tenantSlugFromRequest(r *http.Request) string {
	if slug := strings.TrimSpace(r.PathValue("tenantSlug")); slug != "" {
		return slug
	}
	if value, ok := r.Context().Value(tenantSlugContextKey{}).(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func (s *Server) handlePrettyTenantPath(w http.ResponseWriter, r *http.Request) bool {
	trimmed := strings.Trim(strings.TrimSpace(r.URL.Path), "/")
	if trimmed == "" {
		return false
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return false
	}

	slug := strings.TrimSpace(parts[0])

	// Reserve built-in top-level paths for the main mux.
	if slug == "admin" || slug == "static" || slug == "healthz" || slug == "auth" {
		return false
	}

	// Validate the slug against an actual active tenant – prevents arbitrary
	// paths like /app/ from accidentally being served as tenant app routes.
	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), slug)
	if err != nil || !tenant.Active {
		return false
	}

	r = requestWithTenantSlug(r, slug)
	r = requestWithTenantID(r, tenant.ID)

	switch {
	case len(parts) == 1:
		if strings.HasSuffix(r.URL.Path, "/") {
			// /{slug}/ — forward to appMux as /
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			r2.URL.RawPath = ""
			s.appMux.ServeHTTP(w, r2)
		} else {
			// /{slug} — canonical URL is /{slug}/
			http.Redirect(w, r, "/"+slug+"/", http.StatusMovedPermanently)
		}
		return true
	case len(parts) == 2 && parts[1] == "login":
		s.handleTenantLoginPage(w, r)
		return true
	case len(parts) == 2 && parts[1] == "password-reset":
		s.handleTenantPasswordResetRequestPage(w, r)
		return true
	case len(parts) == 3 && parts[1] == "auth" && parts[2] == "login":
		s.handleTenantAuthLogin(w, r)
		return true
	case len(parts) == 3 && parts[1] == "auth" && parts[2] == "callback":
		s.handleTenantAuthCallback(w, r)
		return true
	case len(parts) == 3 && parts[1] == "auth" && parts[2] == "local":
		s.handleTenantLocalLogin(w, r)
		return true
	case len(parts) == 3 && parts[1] == "password-reset" && parts[2] == "request":
		s.handleTenantPasswordResetRequest(w, r)
		return true
	case len(parts) == 3 && parts[1] == "password-reset" && parts[2] == "confirm":
		s.handleTenantPasswordResetConfirm(w, r)
		return true
	default:
		// /{slug}/X — rewrite to /X and forward to appMux.
		rewrittenPath := "/" + strings.Join(parts[1:], "/")
		if strings.HasSuffix(r.URL.Path, "/") && !strings.HasSuffix(rewrittenPath, "/") {
			rewrittenPath += "/"
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = rewrittenPath
		r2.URL.RawPath = ""
		s.appMux.ServeHTTP(w, r2)
		return true
	}
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		if s.handlePrettyTenantPath(w, r) {
			return
		}
	}
	s.handleNoTenant(w, r)
}

// buildAppMux returns a handler that services all tenant-scoped app routes.
// Requests are dispatched here from handlePrettyTenantPath after the tenant slug
// has been injected into the request context and the URL has been rewritten from
// /{slug}/X to /X.
func (s *Server) buildAppMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("/monitors", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSaveMonitor))))
	mux.Handle("/monitors/save", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSaveMonitor))))
	mux.Handle("/monitors/update-target", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleUpdateMonitorTarget))))
	mux.Handle("/monitors/reorder", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleReorderMonitor))))
	mux.Handle("/groups/save", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSaveGroup))))
	mux.Handle("/groups/delete", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleDeleteGroup))))
	mux.Handle("/groups/reorder", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleReorderGroup))))
	mux.Handle("/icons/search", s.requireAuth(http.HandlerFunc(s.handleSearchDashboardIcons)))
	mux.Handle("/monitors/delete", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleDeleteMonitor))))
	mux.Handle("/monitors/enabled", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSetMonitorEnabled))))
	mux.Handle("/settings/profile", s.requireAuth(http.HandlerFunc(s.handleSettingsProfile)))
	mux.Handle("/settings/profile/save", s.requireAuth(http.HandlerFunc(s.handleSettingsProfileSave)))
	mux.Handle("/settings/profile/notifiers/delete", s.requireAuth(http.HandlerFunc(s.handleSettingsProfileNotifierDelete)))
	mux.Handle("/settings/profile/password", s.requireAuth(http.HandlerFunc(s.handleSettingsProfilePassword)))
	mux.Handle("/settings/users", s.requireUserManagement(http.HandlerFunc(s.handleSettingsUsers)))
	mux.Handle("/settings/local-users/new", s.requireUserManagement(http.HandlerFunc(s.handleSettingsLocalUserForm)))
	mux.Handle("/settings/local-users/{userID}/edit", s.requireUserManagement(http.HandlerFunc(s.handleSettingsLocalUserForm)))
	mux.Handle("/settings/local-users/save", s.requireUserManagement(http.HandlerFunc(s.handleSettingsLocalUserSave)))
	mux.Handle("/settings/local-users/{userID}/delete", s.requireUserManagement(http.HandlerFunc(s.handleSettingsLocalUserDelete)))
	mux.Handle("/settings/users/{userID}/role", s.requireUserManagement(http.HandlerFunc(s.handleSettingsUserRoleSave)))
	mux.Handle("/settings/users/{userID}/remove", s.requireUserManagement(http.HandlerFunc(s.handleSettingsUserRemove)))
	return mux
}

// handleNoTenant is the landing page for / and any unknown path that could not
// be matched to a tenant. When exactly one active tenant exists the request is
// silently redirected there. Otherwise a hint is rendered asking the user to
// supply the tenant slug in the URL. The list of available tenants is never
// exposed to unauthenticated callers.
func (s *Server) handleNoTenant(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.controlStore.GetAllTenants(r.Context())
	if err == nil {
		active := make([]store.Tenant, 0, len(tenants))
		ready := make([]store.Tenant, 0, len(tenants))
		for _, t := range tenants {
			if t.Active {
				active = append(active, t)
				if tenantHasAppDatabase(t.DBPath) {
					ready = append(ready, t)
				}
			}
		}
		if len(ready) == 1 {
			http.Redirect(w, r, "/"+ready[0].Slug+"/", http.StatusSeeOther)
			return
		}
		if len(ready) == 0 {
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			return
		}
	}
	s.render(w, "no_tenant", pageData{
		Title: "Tenant auswählen · GoUp",
	})
}

// tenantAppBase returns the canonical base URL for the tenant app portion of the
// current request, e.g. "/default/app/". It reads the tenant slug from the
// request context (set by the pretty-URL dispatcher) and falls back to the
// session when called from within the appMux (where the context slug is always
// present).
func (s *Server) tenantAppBase(r *http.Request) string {
	slug := tenantSlugFromRequest(r)
	if slug == "" {
		if user := s.currentUser(r); user != nil && user.TenantSlug != "" {
			slug = user.TenantSlug
		}
	}
	if slug != "" {
		return "/" + slug + "/"
	}
	return "/"
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.render(w, "login", pageData{
		Title:          "Login · GoUp",
		Error:          strings.TrimSpace(r.URL.Query().Get("error")),
		Notice:         strings.TrimSpace(r.URL.Query().Get("notice")),
		AuthEnabled:    s.cfg.Auth.Mode == config.AuthModeOIDC && s.oidc != nil,
		AuthDisabled:   s.cfg.Auth.Mode == config.AuthModeDisabled,
		OIDCTenantOnly: s.cfg.Auth.Mode == config.AuthModeOIDC && s.oidc == nil,
		User:           s.currentUser(r),
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Auth.Mode != config.AuthModeOIDC || s.oidc == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	redirectURL, err := s.oidc.BeginAuth(w, r)
	if err != nil {
		http.Error(w, "unable to start authentication", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Auth.Mode != config.AuthModeOIDC || s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	defer s.oidc.ClearEphemeralCookies(w)

	identity, err := s.oidc.CompleteAuth(r.Context(), r)
	if err != nil {
		s.logger.Warn("oidc callback failed", "error", err)
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Anmeldung fehlgeschlagen"), http.StatusSeeOther)
		return
	}

	resolvedUser, err := s.controlStore.UpsertOIDCUserIdentity(r.Context(), "oidc-primary", identity.Subject, identity.Email, identity.Name, s.defaultTenant.ID)
	if err != nil {
		s.logger.Error("persist control-plane user failed", "error", err)
		http.Error(w, "unable to persist user", http.StatusInternalServerError)
		return
	}

	session := auth.UserSession{
		UserID:       resolvedUser.UserID,
		Subject:      identity.Subject,
		Email:        resolvedUser.Email,
		Name:         resolvedUser.DisplayName,
		TenantID:     resolvedUser.TenantID,
		TenantSlug:   resolvedUser.TenantSlug,
		TenantName:   resolvedUser.TenantName,
		Role:         resolvedUser.Role,
		AuthProvider: "oidc-primary",
		ExpiresAt:    time.Now().Add(12 * time.Hour),
	}
	if err := s.sessions.Set(w, session); err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/"+resolvedUser.TenantSlug+"/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := s.sessions.Get(r)
	s.sessions.Clear(w)
	if session != nil && strings.TrimSpace(session.TenantSlug) != "" {
		http.Redirect(w, r, "/"+session.TenantSlug+"/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	stats, err := appStore.DashboardStats(r.Context())
	if err != nil {
		http.Error(w, "unable to load dashboard", http.StatusInternalServerError)
		return
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Error(w, "unable to load monitors", http.StatusInternalServerError)
		return
	}

	events, err := appStore.ListRecentNotificationEvents(r.Context(), 20)
	if err != nil {
		s.logger.Warn("load notification events failed", "error", err)
		events = nil
	}

	stateEvents, err := appStore.ListRecentMonitorStateEvents(r.Context(), 40)
	if err != nil {
		s.logger.Warn("load monitor state events failed", "error", err)
		stateEvents = nil
	}

	groupMetadata, err := appStore.ListMonitorGroupMetadata(r.Context())
	if err != nil {
		http.Error(w, "unable to load monitor groups", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	selectedTrend := parseTrendRange(strings.TrimSpace(r.URL.Query().Get("trend")))
	trendSince := trendRangeStart(now, selectedTrend)
	rollups, err := appStore.ListMonitorHourlyRollupsSince(r.Context(), trendSince)
	if err != nil {
		s.logger.Warn("load monitor trends failed", "error", err)
		rollups = nil
	}

	monitorViews := buildMonitorViews(snapshots, rollups, now, selectedTrend)
	availableGroups := buildAvailableGroups(groupMetadata)
	availableGroups = mergeAvailableGroups(availableGroups, monitorViews)

	curUser := s.currentUser(r)
	s.render(w, "dashboard", pageData{
		Title:           "Dashboard · GoUp",
		User:            curUser,
		IsAdmin:         curUser == nil || strings.EqualFold(strings.TrimSpace(curUser.Role), "admin"),
		Stats:           stats,
		Notice:          strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:           strings.TrimSpace(r.URL.Query().Get("error")),
		AuthEnabled:     s.cfg.Auth.Mode == config.AuthModeOIDC,
		AuthDisabled:    s.cfg.Auth.Mode != config.AuthModeOIDC,
		TrendValue:      selectedTrend.Value,
		TrendLabel:      selectedTrend.Label,
		TrendRanges:     buildTrendRangeOptions(selectedTrend),
		Monitors:        monitorViews,
		MonitorGroups:   buildMonitorGroups(monitorViews, groupMetadata),
		AvailableGroups: availableGroups,
		Events:          buildNotificationEventViews(events),
		StateEvents:     buildMonitorStateEventViews(stateEvents),
		AppBase:         s.tenantAppBase(r),
	})
}

func (s *Server) handleSearchDashboardIcons(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	results, err := s.searchDashboardIcons(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), dashboardIconSearchLimit)
	if err != nil {
		http.Error(w, "unable to search dashboard icons", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(struct {
		Results []dashboardIconSearchResult `json:"results"`
	}{Results: results}); err != nil {
		http.Error(w, "unable to encode dashboard icons", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleReorderMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	if draggedIDRaw := strings.TrimSpace(r.FormValue("dragged_id")); draggedIDRaw != "" {
		draggedID, parseErr := strconv.ParseInt(draggedIDRaw, 10, 64)
		targetID, targetErr := strconv.ParseInt(strings.TrimSpace(r.FormValue("target_id")), 10, 64)
		if parseErr != nil || targetErr != nil || draggedID <= 0 || targetID <= 0 {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Drag&Drop-Monitor-ID"), http.StatusSeeOther)
			return
		}
		snapshots, err := appStore.ListMonitorSnapshots(r.Context())
		if err != nil {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitore konnten nicht geladen werden"), http.StatusSeeOther)
			return
		}
		monitorViews := buildMonitorViews(snapshots, nil, time.Now().UTC(), supportedTrendRanges[0])
		groupName := strings.TrimSpace(r.FormValue("group"))
		draggedGroupName := ""
		targetGroupName := ""
		orderedIDs := make([]int64, 0)
		for _, item := range monitorViews {
			trimmedGroup := monitorServiceLabel(item)
			if item.ID == draggedID {
				draggedGroupName = trimmedGroup
			}
			if item.ID == targetID {
				targetGroupName = trimmedGroup
			}
		}
		if draggedGroupName == "" || targetGroupName == "" {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		if groupName == "" {
			groupName = draggedGroupName
		}
		if draggedGroupName != groupName || targetGroupName != groupName {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitore müssen in derselben Gruppe liegen"), http.StatusSeeOther)
			return
		}
		for _, item := range monitorViews {
			if monitorServiceLabel(item) == groupName {
				orderedIDs = append(orderedIDs, item.ID)
			}
		}
		reorderedIDs, ok := reorderMonitorIDs(orderedIDs, draggedID, targetID)
		if !ok {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor konnte nicht neu einsortiert werden"), http.StatusSeeOther)
			return
		}
		if err := appStore.ReorderMonitors(r.Context(), reorderedIDs); err != nil {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Monitor sortiert", ""), http.StatusSeeOther)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	direction := strings.TrimSpace(r.FormValue("direction"))
	if direction != "up" && direction != "down" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Sortierrichtung"), http.StatusSeeOther)
		return
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitore konnten nicht geladen werden"), http.StatusSeeOther)
		return
	}
	monitorViews := buildMonitorViews(snapshots, nil, time.Now().UTC(), supportedTrendRanges[0])
	groupItems := make([]monitorView, 0)
	for _, item := range monitorViews {
		if monitorServiceLabel(item) == groupName {
			groupItems = append(groupItems, item)
		}
	}
	sort.Slice(groupItems, func(i, j int) bool {
		if groupItems[i].SortOrder != groupItems[j].SortOrder {
			return groupItems[i].SortOrder < groupItems[j].SortOrder
		}
		return groupItems[i].ID < groupItems[j].ID
	})
	currentIndex := -1
	for idx, item := range groupItems {
		if item.ID == id {
			currentIndex = idx
			break
		}
	}
	if currentIndex == -1 {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor wurde nicht gefunden"), http.StatusSeeOther)
		return
	}
	targetIndex := currentIndex - 1
	if direction == "down" {
		targetIndex = currentIndex + 1
	}
	if targetIndex < 0 || targetIndex >= len(groupItems) {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", ""), http.StatusSeeOther)
		return
	}
	if err := appStore.SwapMonitors(r.Context(), id, groupItems[targetIndex].ID); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Monitor sortiert", ""), http.StatusSeeOther)
}

func (s *Server) handleSaveGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	iconSlug := normalizeDashboardIconSlug(strings.TrimSpace(r.FormValue("icon_slug")))
	if err := appStore.UpdateMonitorGroupIcon(r.Context(), groupName, iconSlug); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppen-Icon gespeichert", ""), http.StatusSeeOther)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	if err := appStore.DeleteMonitorGroup(r.Context(), groupName); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe konnte nicht gelöscht werden"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe inkl. Monitore gelöscht", ""), http.StatusSeeOther)
}

func (s *Server) handleReorderGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if draggedGroup := strings.TrimSpace(r.FormValue("dragged_group")); draggedGroup != "" {
		targetGroup := strings.TrimSpace(r.FormValue("target_group"))
		if err := appStore.ReorderMonitorGroups(r.Context(), draggedGroup, targetGroup); err != nil {
			if err == sql.ErrNoRows {
				http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe sortiert", ""), http.StatusSeeOther)
		return
	}
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	direction := strings.TrimSpace(r.FormValue("direction"))
	if err := appStore.MoveMonitorGroup(r.Context(), groupName, direction); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe sortiert", ""), http.StatusSeeOther)
}

func (s *Server) handleSaveMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}

	monitorIDRaw := strings.TrimSpace(r.FormValue("id"))
	var monitorID int64
	if monitorIDRaw != "" {
		parsedID, parseErr := strconv.ParseInt(monitorIDRaw, 10, 64)
		if parseErr != nil || parsedID <= 0 {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
			return
		}
		monitorID = parsedID
	}

	intervalSeconds, err := strconv.Atoi(strings.TrimSpace(r.FormValue("interval_seconds")))
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültiges Intervall"), http.StatusSeeOther)
		return
	}
	timeoutSeconds, err := strconv.Atoi(strings.TrimSpace(r.FormValue("timeout_seconds")))
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültiges Timeout"), http.StatusSeeOther)
		return
	}

	var expectedStatusCode *int
	expectedText := ""
	kind := monitor.Kind(strings.ToLower(strings.TrimSpace(r.FormValue("kind"))))
	if kind == "" {
		kind = monitor.KindHTTPS
	}
	tlsMode := normalizeTLSMode(kind, monitor.TLSMode(strings.ToLower(strings.TrimSpace(r.FormValue("tls_mode")))))
	if raw := strings.TrimSpace(r.FormValue("expected_status_code")); raw != "" && kind == monitor.KindHTTPS {
		value, err := strconv.Atoi(raw)
		if err != nil {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültiger erwarteter HTTP-Status"), http.StatusSeeOther)
			return
		}
		expectedStatusCode = &value
	}
	if kind == monitor.KindHTTPS || kind == monitor.KindDNS {
		expectedText = strings.TrimSpace(r.FormValue("expected_text"))
	}

	target := strings.TrimSpace(r.FormValue("target"))
	if kind == monitor.KindHTTPS {
		target = normalizeHTTPMonitorTarget(target, tlsMode)
	}

	params := store.CreateMonitorParams{
		Name:               strings.TrimSpace(r.FormValue("name")),
		Group:              strings.TrimSpace(r.FormValue("group")),
		Kind:               kind,
		Target:             target,
		Interval:           time.Duration(intervalSeconds) * time.Second,
		Timeout:            time.Duration(timeoutSeconds) * time.Second,
		Enabled:            r.FormValue("enabled") == "on",
		TLSMode:            tlsMode,
		ExpectedStatusCode: expectedStatusCode,
		ExpectedText:       expectedText,
		NotifyOnRecovery:   r.FormValue("notify_on_recovery") == "on",
	}

	if monitorID > 0 {
		err = appStore.UpdateMonitor(r.Context(), store.UpdateMonitorParams{
			ID:                  monitorID,
			CreateMonitorParams: params,
		})
		if err != nil {
			if err == sql.ErrNoRows {
				http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape("Monitor aktualisiert"), http.StatusSeeOther)
		return
	}

	_, err = appStore.CreateMonitor(r.Context(), params)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape(strings.ToUpper(string(kind))+"-Monitor angelegt"), http.StatusSeeOther)
}

func (s *Server) handleDeleteMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}

	err = appStore.DeleteMonitor(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor konnte nicht gelöscht werden"), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape("Monitor gelöscht"), http.StatusSeeOther)
}

func (s *Server) handleSetMonitorEnabled(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}

	enabledRaw := strings.ToLower(strings.TrimSpace(r.FormValue("enabled")))
	enabled := enabledRaw == "1" || enabledRaw == "true" || enabledRaw == "on" || enabledRaw == "yes"

	if err := appStore.SetMonitorEnabled(r.Context(), id, enabled); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor konnte nicht aktualisiert werden"), http.StatusSeeOther)
		return
	}

	message := "Monitor pausiert"
	if enabled {
		message = "Monitor aktiviert"
	}
	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape(message), http.StatusSeeOther)
}

func (s *Server) handleUpdateMonitorTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}

	target := strings.TrimSpace(r.FormValue("target"))
	if target == "" {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ziel darf nicht leer sein"), http.StatusSeeOther)
		return
	}

	err = appStore.UpdateMonitorTarget(r.Context(), id, target)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape("Monitor-Ziel aktualisiert"), http.StatusSeeOther)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if s.store != nil {
		if err := s.store.Healthcheck(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
	} else if s.controlStore != nil {
		if err := s.controlStore.Healthcheck(r.Context()); err != nil {
			http.Error(w, "control plane unavailable", http.StatusServiceUnavailable)
			return
		}
	} else {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Determine whether this tenant requires authentication.
		// A tenant is protected as soon as it has at least one enabled auth
		// provider (local user list or OIDC), regardless of the global
		// GOUP_AUTH_MODE setting.  Tenants with no providers are public
		// (backwards-compatible default for fresh instances).
		needsAuth := false
		if tenantID := tenantIDFromRequest(r); tenantID > 0 {
			hasProviders, err := s.controlStore.TenantHasProviders(r.Context(), tenantID)
			if err != nil {
				s.logger.Error("check tenant providers", "tenant_id", tenantID, "error", err)
				// Fail safe: treat as protected.
				hasProviders = true
			}
			needsAuth = hasProviders
		} else {
			// No tenant in context – fall back to global auth mode.
			needsAuth = s.cfg.Auth.Mode == config.AuthModeOIDC || s.cfg.Auth.Mode == config.AuthModeLocal
		}

		if !needsAuth {
			next.ServeHTTP(w, r)
			return
		}

		if _, err := s.sessions.Get(r); err != nil {
			slug := tenantSlugFromRequest(r)
			if slug != "" {
				http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireUserManagement(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessions.Get(r)
		if err != nil {
			slug := tenantSlugFromRequest(r)
			if slug != "" {
				http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
			return
		}
		if !strings.EqualFold(strings.TrimSpace(session.Role), "admin") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAdminWhenAuth blocks write operations for authenticated non-admin users.
// When no session exists (auth-disabled tenant) the request is passed through.
func (s *Server) requireAdminWhenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessions.Get(r)
		if err == nil && !strings.EqualFold(strings.TrimSpace(session.Role), "admin") {
			http.Error(w, "forbidden: admin role required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireControlPlaneAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(s.adminCookieKey) == "" {
			http.Error(w, "control-plane admin access is not configured", http.StatusForbidden)
			return
		}
		if !s.hasControlPlaneAdminCookie(r) {
			http.Redirect(w, r, "/admin/access", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) isControlPlaneAdminRequest(r *http.Request) bool {
	if r == nil || !strings.HasPrefix(r.URL.Path, "/admin") {
		return false
	}
	if strings.TrimSpace(s.adminCookieKey) == "" {
		return false
	}
	return s.hasControlPlaneAdminCookie(r)
}

func (s *Server) hasControlPlaneAdminCookie(r *http.Request) bool {
	cookie, err := r.Cookie(controlPlaneCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, []byte(s.adminCookieKey))
	_, _ = h.Write(payload)
	if subtle.ConstantTimeCompare(providedSig, h.Sum(nil)) != 1 {
		return false
	}
	expiresUnix, err := strconv.ParseInt(string(payload), 10, 64)
	if err != nil {
		return false
	}
	return time.Now().UTC().Before(time.Unix(expiresUnix, 0))
}

func (s *Server) setControlPlaneAdminCookie(w http.ResponseWriter) {
	expiresAt := time.Now().UTC().Add(controlPlaneAdminTTL)
	payload := []byte(strconv.FormatInt(expiresAt.Unix(), 10))
	h := hmac.New(sha256.New, []byte(s.adminCookieKey))
	_, _ = h.Write(payload)
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     controlPlaneCookie,
		Value:    token,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(controlPlaneAdminTTL.Seconds()),
	})
}

func (s *Server) clearControlPlaneAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     controlPlaneCookie,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (s *Server) clientIP(r *http.Request) string {
	// Only use RemoteAddr. X-Forwarded-For is trivially spoofable by clients
	// and must not be trusted for security decisions unless the server is behind
	// a trusted reverse proxy that strips/overwrites the header.
	clientIP := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(clientIP); err == nil && host != "" {
		clientIP = host
	}
	if clientIP == "" {
		clientIP = "unknown"
	}
	return clientIP
}

func (s *Server) localLoginKey(r *http.Request, tenantID int64, loginName string) string {
	return fmt.Sprintf("%d|%s|%s", tenantID, strings.ToLower(strings.TrimSpace(loginName)), s.clientIP(r))
}

func (s *Server) localLoginAllowed(key string, now time.Time) (bool, time.Duration) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()

	attempt, ok := s.localLoginAttempts[key]
	if !ok {
		return true, 0
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return false, time.Until(attempt.LockedUntil)
	}
	if !attempt.WindowStart.IsZero() && now.Sub(attempt.WindowStart) > localLoginWindow {
		delete(s.localLoginAttempts, key)
	}
	return true, 0
}

func (s *Server) registerLocalLoginFailure(key string, now time.Time) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()

	attempt := s.localLoginAttempts[key]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > localLoginWindow {
		attempt = localLoginAttempt{Failures: 1, WindowStart: now}
		s.localLoginAttempts[key] = attempt
		return
	}

	attempt.Failures++
	if attempt.Failures >= localLoginMaxFailures {
		attempt.Failures = 0
		attempt.WindowStart = now
		attempt.LockedUntil = now.Add(localLoginLockout)
	}
	s.localLoginAttempts[key] = attempt
}

func (s *Server) clearLocalLoginAttempts(key string) {
	s.localLoginMu.Lock()
	defer s.localLoginMu.Unlock()
	delete(s.localLoginAttempts, key)
}

func (s *Server) adminAccessKey(r *http.Request) string {
	return "admin|" + s.clientIP(r)
}

func (s *Server) adminAccessAllowed(key string, now time.Time) (bool, time.Duration) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	attempt, ok := s.adminAccessAttempts[key]
	if !ok {
		return true, 0
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return false, time.Until(attempt.LockedUntil)
	}
	if !attempt.WindowStart.IsZero() && now.Sub(attempt.WindowStart) > adminAccessWindow {
		delete(s.adminAccessAttempts, key)
	}
	return true, 0
}

func (s *Server) registerAdminAccessFailure(key string, now time.Time) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	attempt := s.adminAccessAttempts[key]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > adminAccessWindow {
		attempt = localLoginAttempt{Failures: 1, WindowStart: now}
		s.adminAccessAttempts[key] = attempt
		return
	}
	attempt.Failures++
	if attempt.Failures >= adminAccessMaxFailures {
		attempt.Failures = 0
		attempt.WindowStart = now
		attempt.LockedUntil = now.Add(adminAccessLockout)
	}
	s.adminAccessAttempts[key] = attempt
}

func (s *Server) clearAdminAccessAttempts(key string) {
	s.adminAccessMu.Lock()
	defer s.adminAccessMu.Unlock()
	delete(s.adminAccessAttempts, key)
}

func (s *Server) currentUser(r *http.Request) *auth.UserSession {
	session, err := s.sessions.Get(r)
	if err != nil {
		return nil
	}
	return session
}

func (s *Server) appStore(r *http.Request) (*store.Store, error) {
	if s.tenantStores == nil {
		return s.store, nil
	}
	currentUser := s.currentUser(r)
	if currentUser == nil || currentUser.TenantID <= 0 {
		return s.store, nil
	}
	return s.tenantStores.StoreForTenant(r.Context(), currentUser.TenantID)
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

func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	switch name {
	case "login", "admin_access", "admin_setup":
		data.HideTopbar = true
	}

	tmpl, ok := s.templates[name]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("render template failed", "template", name, "error", err)
		http.Error(w, fmt.Sprintf("render %s failed", name), http.StatusInternalServerError)
	}
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("http request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start).String())
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Clickjacking protection
		h.Set("X-Frame-Options", "DENY")
		// MIME-type sniffing protection
		h.Set("X-Content-Type-Options", "nosniff")
		// Referrer leakage: only send origin on cross-origin requests
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Disable browser features not needed
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		// Content Security Policy: allow own origin + CDN for dashboard icons
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self' https://cdn.jsdelivr.net data:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")
		// HSTS: only set when using HTTPS
		if s.cfg.SecureCookies() {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func parseTemplates() (map[string]*template.Template, error) {
	pages := []string{"dashboard", "login", "password_reset_request", "password_reset_confirm", "admin_dashboard", "admin_tenants", "admin_tenant_form", "admin_providers", "admin_provider_form", "admin_local_users", "admin_local_user_form", "settings_users", "settings_profile", "admin_access", "admin_setup", "admin_security", "no_tenant"}
	parsed := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		tmpl, err := template.ParseFS(web.FS, "templates/layout.tmpl", "templates/"+page+".tmpl")
		if err != nil {
			return nil, err
		}
		parsed[page] = tmpl
	}
	return parsed, nil
}

func (s *Server) passwordResetEnabled(ctx context.Context) bool {
	smtpCfg, err := s.controlStore.GetGlobalSMTPSettings(ctx)
	if err != nil {
		return false
	}
	return strings.TrimSpace(smtpCfg.Host) != "" && strings.TrimSpace(smtpCfg.FromEmail) != "" && smtpCfg.PasswordConfigured
}

func (s *Server) signPasswordResetToken(tenantID, userID int64, expiresAt time.Time) (string, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := fmt.Sprintf("%d:%d:%d:%s", tenantID, userID, expiresAt.UTC().Unix(), hex.EncodeToString(nonce))
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))

	h := hmac.New(sha256.New, []byte(s.cfg.SessionKey))
	_, _ = h.Write([]byte(payloadEncoded))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return payloadEncoded + "." + signature, nil
}

func (s *Server) parsePasswordResetToken(token string) (tenantID, userID int64, expiresAt time.Time, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token")
	}
	payloadEncoded := parts[0]
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token signature")
	}

	h := hmac.New(sha256.New, []byte(s.cfg.SessionKey))
	_, _ = h.Write([]byte(payloadEncoded))
	expectedSig := h.Sum(nil)
	if !hmac.Equal(providedSig, expectedSig) {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token payload")
	}
	fields := strings.Split(string(payloadBytes), ":")
	if len(fields) < 3 {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token payload")
	}

	tenantID, err = strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token tenant")
	}
	userID, err = strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token user")
	}
	expUnix, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return 0, 0, time.Time{}, fmt.Errorf("invalid token expiration")
	}
	expiresAt = time.Unix(expUnix, 0).UTC()
	if time.Now().UTC().After(expiresAt) {
		return 0, 0, time.Time{}, fmt.Errorf("token expired")
	}

	return tenantID, userID, expiresAt, nil
}

func sendSMTPMail(cfg store.GlobalSMTPDeliveryConfig, to, subject, body string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("recipient is required")
	}
	host := strings.TrimSpace(cfg.Settings.Host)
	port := cfg.Settings.Port
	if host == "" || port <= 0 {
		return fmt.Errorf("smtp host/port not configured")
	}

	fromHeader := cfg.Settings.FromEmail
	if strings.TrimSpace(cfg.Settings.FromName) != "" {
		fromHeader = fmt.Sprintf("%s <%s>", cfg.Settings.FromName, cfg.Settings.FromEmail)
	}
	msg := strings.Join([]string{
		"From: " + fromHeader,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	addr := fmt.Sprintf("%s:%d", host, port)
	auth := smtp.PlainAuth("", cfg.Settings.Username, cfg.Password, host)

	switch strings.ToLower(strings.TrimSpace(cfg.Settings.TLSMode)) {
	case "tls":
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
		if err != nil {
			return err
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return err
		}
		defer client.Close()

		if cfg.Settings.Username != "" || cfg.Password != "" {
			if ok, _ := client.Extension("AUTH"); ok {
				if err := client.Auth(auth); err != nil {
					return err
				}
			}
		}
		if err := client.Mail(cfg.Settings.FromEmail); err != nil {
			return err
		}
		if err := client.Rcpt(to); err != nil {
			return err
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil {
			_ = wc.Close()
			return err
		}
		if err := wc.Close(); err != nil {
			return err
		}
		return client.Quit()
	case "none", "starttls":
		client, err := smtp.Dial(addr)
		if err != nil {
			return err
		}
		defer client.Close()

		if strings.ToLower(strings.TrimSpace(cfg.Settings.TLSMode)) == "starttls" {
			if ok, _ := client.Extension("STARTTLS"); ok {
				if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
					return err
				}
			}
		}

		if cfg.Settings.Username != "" || cfg.Password != "" {
			if ok, _ := client.Extension("AUTH"); ok {
				if err := client.Auth(auth); err != nil {
					return err
				}
			}
		}
		if err := client.Mail(cfg.Settings.FromEmail); err != nil {
			return err
		}
		if err := client.Rcpt(to); err != nil {
			return err
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil {
			_ = wc.Close()
			return err
		}
		if err := wc.Close(); err != nil {
			return err
		}
		return client.Quit()
	default:
		return fmt.Errorf("unsupported smtp tls mode")
	}
}

func buildMonitorViews(items []monitor.Snapshot, rollups []store.MonitorHourlyRollup, now time.Time, selectedTrend trendRange) []monitorView {
	rollupsByMonitor := groupRollupsByMonitor(rollups)
	views := make([]monitorView, 0, len(items))
	for _, item := range items {
		kindLabel := monitorKindLabel(item.Monitor.Kind)
		tlsLabel := monitorTLSModeLabel(item.Monitor)
		if item.Monitor.Kind == monitor.KindHTTPS {
			kindLabel = monitorHTTPKindLabel(item.Monitor.TLSMode)
			tlsLabel = ""
		}

		view := monitorView{
			ID:               item.Monitor.ID,
			Name:             item.Monitor.Name,
			Group:            effectiveMonitorGroup(strings.TrimSpace(item.Monitor.Group), item.Monitor.Name, item.Monitor.Target),
			SortOrder:        item.Monitor.SortOrder,
			KindValue:        string(item.Monitor.Kind),
			Kind:             kindLabel,
			TLSMode:          tlsLabel,
			TLSModeValue:     string(item.Monitor.TLSMode),
			Target:           item.Monitor.Target,
			TargetLabel:      monitorTargetLabel(item.Monitor),
			Interval:         item.Monitor.Interval.String(),
			IntervalSeconds:  int(item.Monitor.Interval / time.Second),
			Timeout:          item.Monitor.Timeout.String(),
			TimeoutSeconds:   int(item.Monitor.Timeout / time.Second),
			Enabled:          item.Monitor.Enabled,
			NotifyOnRecovery: item.Monitor.NotifyOnRecovery,
			TrendLabel:       selectedTrend.Label,
			TrendPoints:      buildTrendPoints(rollupsByMonitor[item.Monitor.ID], now, selectedTrend),
		}
		view.UptimeLabel = summarizeTrend(view.TrendPoints, selectedTrend)
		view.StatusLabel = "UNKNOWN"
		view.StatusClass = "status-UNKNOWN"
		view.StatusSummary = "No successful check yet"
		if item.Monitor.ExpectedStatusCode != nil {
			view.ExpectedStatus = strconv.Itoa(*item.Monitor.ExpectedStatusCode)
		}
		view.ExpectedText = strings.TrimSpace(item.Monitor.ExpectedText)
		if item.LastResult != nil {
			view.LastCheckedAt = item.LastResult.CheckedAt.UTC().Format(time.RFC3339)
			view.LastCheckedAtRaw = item.LastResult.CheckedAt.UTC().Format(time.RFC3339)
			view.LastStatus = strings.ToUpper(string(item.LastResult.Status))
			view.StatusLabel = view.LastStatus
			view.StatusClass = "status-" + view.LastStatus
			view.StatusSummary = item.LastResult.Message
			view.LastMessage = item.LastResult.Message
			view.LastLatency = item.LastResult.Latency.String()
			if item.LastResult.HTTPStatusCode != nil {
				view.HTTPStatusCode = strconv.Itoa(*item.LastResult.HTTPStatusCode)
			}
			if item.LastResult.TLSDaysRemaining != nil {
				view.TLSDaysRemaining = strconv.Itoa(*item.LastResult.TLSDaysRemaining) + " Tage"
			}
			if item.LastResult.TLSNotAfter != nil {
				view.TLSNotAfter = item.LastResult.TLSNotAfter.UTC().Format(time.RFC3339)
				view.TLSNotAfterRaw = item.LastResult.TLSNotAfter.UTC().Format(time.RFC3339)
			}
		}
		if !item.Monitor.Enabled {
			view.StatusLabel = "PAUSED"
			view.StatusClass = "status-PAUSED"
			view.StatusSummary = "Monitor is paused"
		}
		views = append(views, view)
	}
	return views
}

func buildAvailableGroups(items []store.MonitorGroup) []string {
	groups := make([]string, 0, len(items))
	for _, item := range items {
		groups = append(groups, item.Name)
	}
	return groups
}

func mergeAvailableGroups(existing []string, monitors []monitorView) []string {
	seen := make(map[string]struct{}, len(existing)+len(monitors))
	groups := make([]string, 0, len(existing)+len(monitors))
	for _, item := range existing {
		group := strings.TrimSpace(item)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	for _, item := range monitors {
		group := strings.TrimSpace(item.Group)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	return groups
}

func buildMonitorGroups(monitors []monitorView, metadata []store.MonitorGroup) []monitorGroupView {
	groupSortOrder := make(map[string]int, len(metadata))
	groupIcons := make(map[string]string, len(metadata))
	for idx, item := range metadata {
		name := strings.TrimSpace(item.Name)
		groupSortOrder[name] = idx
		groupIcons[name] = normalizeDashboardIconSlug(item.IconSlug)
	}

	services := buildMonitorServiceGroups(monitors, groupSortOrder, groupIcons, len(metadata))
	serviceHint := "Keine Dienstgruppen"
	if len(services) == 1 {
		serviceHint = "1 Dienstgruppe"
	} else if len(services) > 1 {
		serviceHint = strconv.Itoa(len(services)) + " Dienstgruppen"
	}

	return []monitorGroupView{
		{
			Title:       "Dienste",
			Subtitle:    "Gesamtsicht aller Monitore",
			EmptyText:   "Noch keine Monitore vorhanden.",
			AccentClass: "group-healthy",
			Monitors:    monitors,
			Services:    services,
			Count:       len(monitors),
			ServiceHint: serviceHint,
		},
	}
}

func buildMonitorStatusGroup(title string, subtitle string, emptyText string, accentClass string, monitors []monitorView, groupSortOrder map[string]int, groupIcons map[string]string, totalGroups int) monitorGroupView {
	services := buildMonitorServiceGroups(monitors, groupSortOrder, groupIcons, totalGroups)
	serviceHint := "Einzelne Dienste"
	if len(services) > 1 {
		serviceHint = strconv.Itoa(len(services)) + " Dienstgruppen"
	}
	if len(services) == 1 {
		serviceHint = "1 Dienstgruppe"
	}
	return monitorGroupView{
		Title:       title,
		Subtitle:    subtitle,
		EmptyText:   emptyText,
		AccentClass: accentClass,
		Monitors:    monitors,
		Services:    services,
		Count:       len(monitors),
		ServiceHint: serviceHint,
	}
}

func buildMonitorServiceGroups(monitors []monitorView, groupSortOrder map[string]int, groupIcons map[string]string, totalGroups int) []monitorServiceGroupView {
	if len(monitors) == 0 && len(groupSortOrder) == 0 {
		return nil
	}

	grouped := make(map[string][]monitorView)
	for _, item := range monitors {
		label := monitorServiceLabel(item)
		grouped[label] = append(grouped[label], item)
	}
	for label := range groupSortOrder {
		if _, ok := grouped[label]; !ok {
			grouped[label] = nil
		}
	}

	labels := make([]string, 0, len(grouped))
	for label := range grouped {
		labels = append(labels, label)
	}
	sort.Slice(labels, func(i, j int) bool {
		leftOrder, leftKnown := groupSortOrder[labels[i]]
		rightOrder, rightKnown := groupSortOrder[labels[j]]
		if leftKnown && rightKnown && leftOrder != rightOrder {
			return leftOrder < rightOrder
		}
		if leftKnown != rightKnown {
			return leftKnown
		}
		left := grouped[labels[i]]
		right := grouped[labels[j]]
		if len(left) == len(right) {
			return labels[i] < labels[j]
		}
		return len(left) > len(right)
	})

	services := make([]monitorServiceGroupView, 0, len(labels))
	for _, label := range labels {
		items := grouped[label]
		sort.Slice(items, func(i, j int) bool {
			if items[i].SortOrder != items[j].SortOrder {
				return items[i].SortOrder < items[j].SortOrder
			}
			if items[i].Name == items[j].Name {
				return items[i].Kind < items[j].Kind
			}
			return items[i].Name < items[j].Name
		})
		for idx := range items {
			items[idx].CanMoveUp = idx > 0
			items[idx].CanMoveDown = idx < len(items)-1
		}
		subtitle := strconv.Itoa(len(items)) + " Monitor"
		if len(items) != 1 {
			subtitle += "e"
		}
		statusLabel, statusClass, statusInfo := aggregateServiceStatus(items)
		aggregatePoints := aggregateServiceTrendPoints(items)
		uptimeLabel := summarizeTrendPoints(aggregatePoints)
		trendLabel := ""
		if len(items) > 0 {
			trendLabel = items[0].TrendLabel
		}
		orderIndex := len(groupSortOrder)
		if knownIndex, ok := groupSortOrder[label]; ok {
			orderIndex = knownIndex
		}
		iconSlug := effectiveDashboardIconSlug(label, groupIcons[label])
		services = append(services, monitorServiceGroupView{
			Title:       label,
			Subtitle:    subtitle,
			StatusLabel: statusLabel,
			StatusClass: statusClass,
			StatusInfo:  statusInfo,
			TrendLabel:  trendLabel,
			UptimeLabel: uptimeLabel,
			TrendPoints: aggregatePoints,
			IconSlug:    iconSlug,
			IconURL:     dashboardIconURL(iconSlug),
			Monitors:    items,
			Open:        false,
			CanMoveUp:   orderIndex > 0,
			CanMoveDown: orderIndex >= 0 && orderIndex < totalGroups-1,
		})
	}

	return services
}

func aggregateServiceStatus(items []monitorView) (label string, class string, info string) {
	if len(items) == 0 {
		return "UNKNOWN", "status-UNKNOWN", "No monitors"
	}
	hasDown := false
	hasDegraded := false
	hasUnknown := false
	hasPaused := false
	hasUp := false
	for _, item := range items {
		switch item.StatusLabel {
		case "DOWN":
			hasDown = true
		case "DEGRADED":
			hasDegraded = true
		case "UP":
			hasUp = true
		case "PAUSED":
			hasPaused = true
		default:
			hasUnknown = true
		}
	}
	hasOnlyDown := hasDown && !hasUp && !hasDegraded && !hasUnknown && !hasPaused
	switch {
	case hasOnlyDown:
		return "DOWN", "status-DOWN", "Mindestens ein Dienst ist ausgefallen"
	case hasDown:
		return "DEGRADED", "status-DEGRADED", "Mindestens ein Dienst ist ausgefallen"
	case hasDegraded:
		return "DEGRADED", "status-DEGRADED", "Mindestens ein Dienst ist degradiert"
	case hasUp && !hasUnknown && !hasPaused:
		return "UP", "status-UP", "Alle Dienste sind erreichbar"
	case hasPaused && !hasUp && !hasUnknown:
		return "PAUSED", "status-PAUSED", "All monitors in this service are paused"
	default:
		return "DEGRADED", "status-DEGRADED", "Mixed state"
	}
}

func aggregateServiceTrendPoints(items []monitorView) []trendPointView {
	if len(items) == 0 {
		return nil
	}
	buckets := make([]trendPointView, len(items[0].TrendPoints))
	type aggregate struct {
		totalChecks int
		upChecks    int
		latencySum  int
		minMS       int
		maxMS       int
	}
	agg := make([]aggregate, len(items[0].TrendPoints))
	for i, point := range items[0].TrendPoints {
		buckets[i] = trendPointView{
			BucketRaw: point.BucketRaw,
			Format:    point.Format,
			Class:     "trend-none",
			Label:     "Keine Daten",
		}
	}
	for _, item := range items {
		for i, point := range item.TrendPoints {
			if i >= len(agg) || point.Checks <= 0 {
				continue
			}
			agg[i].totalChecks += point.Checks
			agg[i].upChecks += int(float64(point.Percent) / 100.0 * float64(point.Checks))
			agg[i].latencySum += point.AvgMS * point.Checks
			if agg[i].minMS == 0 || (point.MinMS > 0 && point.MinMS < agg[i].minMS) {
				agg[i].minMS = point.MinMS
			}
			if point.MaxMS > agg[i].maxMS {
				agg[i].maxMS = point.MaxMS
			}
		}
	}
	for i := range buckets {
		if agg[i].totalChecks <= 0 {
			continue
		}
		percent := int(float64(agg[i].upChecks) / float64(agg[i].totalChecks) * 100)
		buckets[i].Percent = percent
		buckets[i].Checks = agg[i].totalChecks
		buckets[i].AvgMS = agg[i].latencySum / agg[i].totalChecks
		buckets[i].MinMS = agg[i].minMS
		buckets[i].MaxMS = agg[i].maxMS
		buckets[i].Label = strconv.Itoa(percent) + "% Uptime · " + strconv.Itoa(agg[i].totalChecks) + " Checks"
		switch {
		case percent == 100:
			buckets[i].Class = "trend-up"
		case percent == 0:
			buckets[i].Class = "trend-down"
		default:
			buckets[i].Class = "trend-degraded"
		}
	}
	return buckets
}

func summarizeTrendPoints(points []trendPointView) string {
	totalPercent := 0
	counted := 0
	for _, point := range points {
		if point.Checks <= 0 {
			continue
		}
		totalPercent += point.Percent
		counted++
	}
	if counted == 0 {
		return "Keine Daten"
	}
	return strconv.Itoa(totalPercent/counted) + "% Uptime"
}

func (s *Server) redirectDashboardPath(r *http.Request, trend string, notice string, errText string) string {
	base := s.tenantAppBase(r)
	values := url.Values{}
	if strings.TrimSpace(trend) != "" {
		values.Set("trend", strings.TrimSpace(trend))
	}
	if strings.TrimSpace(notice) != "" {
		values.Set("notice", strings.TrimSpace(notice))
	}
	if strings.TrimSpace(errText) != "" {
		values.Set("error", strings.TrimSpace(errText))
	}
	encoded := values.Encode()
	if encoded == "" {
		return base
	}
	return base + "?" + encoded
}

func monitorServiceLabel(item monitorView) string {
	if group := strings.TrimSpace(item.Group); group != "" {
		return group
	}
	return effectiveMonitorGroup("", item.Name, item.Target)

}

func effectiveMonitorGroup(group string, name string, target string) string {
	if group = strings.TrimSpace(group); group != "" {
		return group
	}

	name = strings.TrimSpace(name)
	for _, token := range monitorGroupingTokens(name) {
		if token == "" {
			continue
		}
		return strings.ToUpper(token[:1]) + token[1:]
	}

	host := monitorTargetHost(target)
	for _, token := range monitorGroupingTokens(host) {
		if token == "" {
			continue
		}
		return strings.ToUpper(token[:1]) + token[1:]
	}

	return "Sonstige"
}

func dashboardIconURL(slug string) string {
	slug = normalizeDashboardIconSlug(slug)
	if slug == "" {
		return ""
	}
	return dashboardIconsBaseURL + "/svg/" + slug + ".svg"
}

func normalizeDashboardIconSlug(slug string) string {
	slug = strings.ToLower(strings.TrimSpace(slug))
	slug = strings.ReplaceAll(slug, " ", "-")
	return slug
}

func effectiveDashboardIconSlug(groupName string, storedSlug string) string {
	storedSlug = normalizeDashboardIconSlug(storedSlug)
	if storedSlug != "" {
		return storedSlug
	}
	return normalizeDashboardIconSlug(groupName)
}

func (s *Server) searchDashboardIcons(ctx context.Context, query string, limit int) ([]dashboardIconSearchResult, error) {
	entries, err := s.loadDashboardIconIndex(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = dashboardIconSearchLimit
	}
	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	type scoredIcon struct {
		entry dashboardIconEntry
		score int
	}
	scored := make([]scoredIcon, 0, len(entries))
	for _, entry := range entries {
		score := 99
		switch {
		case normalizedQuery == "":
			score = 0
		case entry.Slug == normalizedQuery:
			score = 0
		case strings.HasPrefix(entry.Slug, normalizedQuery):
			score = 1
		case strings.HasPrefix(strings.ToLower(entry.Label), normalizedQuery):
			score = 2
		case strings.Contains(entry.Slug, normalizedQuery):
			score = 3
		case strings.Contains(entry.SearchText, normalizedQuery):
			score = 4
		default:
			continue
		}
		scored = append(scored, scoredIcon{entry: entry, score: score})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score < scored[j].score
		}
		return scored[i].entry.Slug < scored[j].entry.Slug
	})
	if len(scored) > limit {
		scored = scored[:limit]
	}
	results := make([]dashboardIconSearchResult, 0, len(scored))
	for _, item := range scored {
		results = append(results, dashboardIconSearchResult{
			Slug:  item.entry.Slug,
			Label: item.entry.Label,
			URL:   dashboardIconURL(item.entry.Slug),
		})
	}
	return results, nil
}

func (s *Server) loadDashboardIconIndex(ctx context.Context) ([]dashboardIconEntry, error) {
	s.iconIndexMu.RLock()
	if len(s.iconIndex) > 0 && time.Since(s.iconIndexFetchedAt) < dashboardIconCacheTTL {
		cached := append([]dashboardIconEntry(nil), s.iconIndex...)
		s.iconIndexMu.RUnlock()
		return cached, nil
	}
	stale := append([]dashboardIconEntry(nil), s.iconIndex...)
	s.iconIndexMu.RUnlock()

	s.iconIndexMu.Lock()
	defer s.iconIndexMu.Unlock()
	if len(s.iconIndex) > 0 && time.Since(s.iconIndexFetchedAt) < dashboardIconCacheTTL {
		return append([]dashboardIconEntry(nil), s.iconIndex...), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dashboardIconsMetadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build dashboard icons metadata request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if len(stale) > 0 {
			return stale, nil
		}
		return nil, fmt.Errorf("fetch dashboard icons metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if len(stale) > 0 {
			return stale, nil
		}
		return nil, fmt.Errorf("dashboard icons metadata returned %s", resp.Status)
	}
	metadata := make(map[string]dashboardIconMetadata)
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		if len(stale) > 0 {
			return stale, nil
		}
		return nil, fmt.Errorf("decode dashboard icons metadata: %w", err)
	}
	entries := make([]dashboardIconEntry, 0, len(metadata))
	for slug, meta := range metadata {
		normalizedSlug := normalizeDashboardIconSlug(slug)
		if normalizedSlug == "" {
			continue
		}
		entries = append(entries, dashboardIconEntry{
			Slug:       normalizedSlug,
			Label:      formatDashboardIconLabel(normalizedSlug),
			SearchText: buildDashboardIconSearchText(normalizedSlug, meta),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Slug < entries[j].Slug
	})
	s.iconIndex = entries
	s.iconIndexFetchedAt = time.Now()
	return append([]dashboardIconEntry(nil), entries...), nil
}

func buildDashboardIconSearchText(slug string, meta dashboardIconMetadata) string {
	parts := []string{strings.ToLower(strings.TrimSpace(slug)), strings.ToLower(formatDashboardIconLabel(slug))}
	for _, alias := range meta.Aliases {
		if value := strings.ToLower(strings.TrimSpace(alias)); value != "" {
			parts = append(parts, value)
		}
	}
	for _, category := range meta.Categories {
		if value := strings.ToLower(strings.TrimSpace(category)); value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, " ")
}

func formatDashboardIconLabel(slug string) string {
	parts := strings.Fields(strings.ReplaceAll(normalizeDashboardIconSlug(slug), "-", " "))
	for idx, part := range parts {
		if part == "" {
			continue
		}
		parts[idx] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func reorderMonitorIDs(items []int64, draggedID int64, targetID int64) ([]int64, bool) {
	if draggedID == targetID {
		return items, true
	}
	draggedIndex := -1
	targetIndex := -1
	for idx, item := range items {
		if item == draggedID {
			draggedIndex = idx
		}
		if item == targetID {
			targetIndex = idx
		}
	}
	if draggedIndex == -1 || targetIndex == -1 {
		return nil, false
	}
	reordered := make([]int64, 0, len(items))
	for idx, item := range items {
		if idx == draggedIndex {
			continue
		}
		reordered = append(reordered, item)
	}
	if draggedIndex < targetIndex {
		targetIndex--
	}
	updated := make([]int64, 0, len(items))
	updated = append(updated, reordered[:targetIndex]...)
	updated = append(updated, draggedID)
	updated = append(updated, reordered[targetIndex:]...)
	return updated, true
}

func monitorGroupingTokens(value string) []string {
	replacer := strings.NewReplacer("-", " ", "_", " ", "/", " ", ".", " ", "(", " ", ")", " ", ":", " ")
	normalized := strings.ToLower(strings.TrimSpace(replacer.Replace(value)))
	if normalized == "" {
		return nil
	}

	stopWords := map[string]struct{}{
		"https":      {},
		"http":       {},
		"tcp":        {},
		"icmp":       {},
		"smtp":       {},
		"imap":       {},
		"dns":        {},
		"udp":        {},
		"whois":      {},
		"tls":        {},
		"starttls":   {},
		"monitor":    {},
		"check":      {},
		"health":     {},
		"status":     {},
		"server":     {},
		"service":    {},
		"prod":       {},
		"production": {},
		"staging":    {},
		"stage":      {},
		"test":       {},
		"validation": {},
	}

	parts := strings.Fields(normalized)
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if _, blocked := stopWords[part]; blocked {
			continue
		}
		filtered = append(filtered, part)
	}
	return filtered
}

func monitorTargetHost(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		parsed, err := url.Parse(trimmed)
		if err == nil {
			return parsed.Hostname()
		}
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		return host
	}
	return trimmed
}

func monitorKindLabel(kind monitor.Kind) string {
	switch kind {
	case monitor.KindHTTPS:
		return "HTTP(S)"
	case monitor.KindTCP:
		return "TCP"
	case monitor.KindICMP:
		return "ICMP"
	case monitor.KindSMTP:
		return "SMTP"
	case monitor.KindIMAP:
		return "IMAP"
	case monitor.KindDNS:
		return "DNS"
	case monitor.KindUDP:
		return "UDP"
	case monitor.KindWhois:
		return "WHOIS"
	default:
		return strings.ToUpper(string(kind))
	}
}

func buildNotificationEventViews(items []store.NotificationEvent) []notificationEventView {
	views := make([]notificationEventView, 0, len(items))
	for _, item := range items {
		view := notificationEventView{
			ID:        item.ID,
			When:      item.CreatedAt.UTC().Format(time.RFC3339),
			WhenRaw:   item.CreatedAt.UTC().Format(time.RFC3339),
			Monitor:   item.MonitorName,
			EventType: strings.ToUpper(strings.TrimSpace(item.EventType)),
			Endpoint:  item.Endpoint,
			Result:    "FAILED",
			Error:     item.Error,
		}
		if view.Monitor == "" {
			view.Monitor = strconv.FormatInt(item.MonitorID, 10)
		}
		if view.Endpoint == "" {
			view.Endpoint = strconv.FormatInt(item.EndpointID, 10)
		}
		if item.DeliveredAt != nil {
			view.Result = "DELIVERED"
			view.DeliveredAt = item.DeliveredAt.UTC().Format(time.RFC3339)
			view.DeliveredAtRaw = item.DeliveredAt.UTC().Format(time.RFC3339)
		}
		if strings.TrimSpace(view.Error) == "" {
			view.Error = "—"
		}
		views = append(views, view)
	}
	return views
}

func buildMonitorStateEventViews(items []store.MonitorStateEvent) []monitorStateEventView {
	views := make([]monitorStateEventView, 0, len(items))
	for _, item := range items {
		view := monitorStateEventView{
			ID:      item.ID,
			When:    item.CheckedAt.UTC().Format(time.RFC3339),
			WhenRaw: item.CheckedAt.UTC().Format(time.RFC3339),
			Monitor: item.MonitorName,
			From:    strings.ToUpper(strings.TrimSpace(item.FromStatus)),
			To:      strings.ToUpper(strings.TrimSpace(item.ToStatus)),
			Message: strings.TrimSpace(item.Message),
		}
		if view.Monitor == "" {
			view.Monitor = strconv.FormatInt(item.MonitorID, 10)
		}
		if view.Message == "" {
			view.Message = "—"
		}
		if view.From == "" {
			view.From = "UNKNOWN"
		}
		if view.To == "" {
			view.To = "UNKNOWN"
		}
		view.FromClass = "status-" + view.From
		view.ToClass = "status-" + view.To
		views = append(views, view)
	}
	return views
}

func groupRollupsByMonitor(items []store.MonitorHourlyRollup) map[int64][]store.MonitorHourlyRollup {
	grouped := make(map[int64][]store.MonitorHourlyRollup)
	for _, item := range items {
		grouped[item.MonitorID] = append(grouped[item.MonitorID], item)
	}
	return grouped
}

func buildTrendPoints(items []store.MonitorHourlyRollup, now time.Time, selectedTrend trendRange) []trendPointView {
	type aggregate struct {
		totalChecks    int
		upChecks       int
		downChecks     int
		degradedChecks int
		latencySumMS   int
		latencyMinMS   int
		latencyMaxMS   int
	}

	start := trendRangeStart(now, selectedTrend)
	buckets := make(map[string]*aggregate, selectedTrend.Buckets)
	for idx := 0; idx < selectedTrend.Buckets; idx++ {
		bucketStart := trendBucketAt(start, selectedTrend, idx)
		buckets[bucketStart.Format(time.RFC3339)] = &aggregate{}
	}

	for _, item := range items {
		bucketStart := bucketStartFor(item.HourBucket.UTC(), start, selectedTrend)
		if bucketStart.IsZero() {
			continue
		}
		entry := buckets[bucketStart.Format(time.RFC3339)]
		if entry == nil {
			continue
		}
		entry.totalChecks += item.TotalChecks
		entry.upChecks += item.UpChecks
		entry.downChecks += item.DownChecks
		entry.degradedChecks += item.DegradedChecks
		entry.latencySumMS += item.LatencySumMS
		if entry.latencyMinMS == 0 || (item.LatencyMinMS > 0 && item.LatencyMinMS < entry.latencyMinMS) {
			entry.latencyMinMS = item.LatencyMinMS
		}
		if item.LatencyMaxMS > entry.latencyMaxMS {
			entry.latencyMaxMS = item.LatencyMaxMS
		}
	}

	points := make([]trendPointView, 0, selectedTrend.Buckets)
	for idx := 0; idx < selectedTrend.Buckets; idx++ {
		bucket := trendBucketAt(start, selectedTrend, idx)
		key := bucket.Format(time.RFC3339)
		agg := buckets[key]
		point := trendPointView{
			BucketRaw: key,
			Class:     "trend-none",
			Label:     "Keine Daten",
			Format:    trendPointFormat(selectedTrend),
		}
		if agg != nil && agg.totalChecks > 0 {
			percent := int(float64(agg.upChecks) / float64(agg.totalChecks) * 100)
			point.Percent = percent
			point.Checks = agg.totalChecks
			point.AvgMS = agg.latencySumMS / agg.totalChecks
			point.MinMS = agg.latencyMinMS
			point.MaxMS = agg.latencyMaxMS
			point.Label = strconv.Itoa(percent) + "% Uptime · " + strconv.Itoa(agg.totalChecks) + " Checks"
			switch {
			case agg.downChecks > 0 && agg.upChecks == 0 && agg.degradedChecks == 0:
				point.Class = "trend-down"
			case agg.downChecks > 0 || agg.degradedChecks > 0 || percent < 100:
				point.Class = "trend-degraded"
			default:
				point.Class = "trend-up"
			}
		}
		points = append(points, point)
	}
	return points
}

func trendPointFormat(selected trendRange) string {
	if selected.Step == "hour" {
		return "hour"
	}
	if selected.Step == "month" {
		return "month"
	}
	return "date"
}

func summarizeTrend(points []trendPointView, selectedTrend trendRange) string {
	if len(points) == 0 {
		return "Keine Daten"
	}
	counted := 0
	total := 0
	for _, point := range points {
		if point.Class == "trend-none" {
			continue
		}
		counted++
		total += point.Percent
	}
	if counted == 0 {
		return "Keine Daten"
	}
	return strconv.Itoa(total/counted) + "% Uptime / " + selectedTrend.Label
}

func parseTrendRange(value string) trendRange {
	for _, item := range supportedTrendRanges {
		if item.Value == value {
			return item
		}
	}
	return supportedTrendRanges[0]
}

func buildTrendRangeOptions(selected trendRange) []trendRangeOptionView {
	items := make([]trendRangeOptionView, 0, len(supportedTrendRanges))
	for _, item := range supportedTrendRanges {
		items = append(items, trendRangeOptionView{
			Value:    item.Value,
			Label:    item.Label,
			Selected: item.Value == selected.Value,
		})
	}
	return items
}

func trendRangeStart(now time.Time, selected trendRange) time.Time {
	if selected.Step == "hour" {
		return now.UTC().Truncate(time.Hour).Add(-time.Duration(selected.Buckets-1) * time.Hour)
	}
	if selected.Step == "month" {
		startOfMonth := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
		return startOfMonth.AddDate(0, -(selected.Buckets - 1), 0)
	}
	startOfDay := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return startOfDay.AddDate(0, 0, -(selected.Buckets - 1))
}

func bucketStartFor(checkedAt time.Time, rangeStart time.Time, selected trendRange) time.Time {
	if checkedAt.Before(rangeStart) {
		return time.Time{}
	}
	if selected.Step == "hour" {
		return checkedAt.Truncate(time.Hour)
	}
	if selected.Step == "month" {
		return time.Date(checkedAt.Year(), checkedAt.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return time.Date(checkedAt.Year(), checkedAt.Month(), checkedAt.Day(), 0, 0, 0, 0, time.UTC)
}

func trendBucketAt(start time.Time, selected trendRange, idx int) time.Time {
	if selected.Step == "month" {
		return start.AddDate(0, idx, 0)
	}
	return start.Add(time.Duration(idx) * selected.BucketSize)
}

func defaultTLSMode(kind monitor.Kind) monitor.TLSMode {
	switch kind {
	case monitor.KindHTTPS, monitor.KindIMAP:
		return monitor.TLSModeTLS
	case monitor.KindSMTP:
		return monitor.TLSModeSTARTTLS
	default:
		return monitor.TLSModeNone
	}
}

func normalizeTLSMode(kind monitor.Kind, requested monitor.TLSMode) monitor.TLSMode {
	switch kind {
	case monitor.KindHTTPS:
		if requested == monitor.TLSModeNone || requested == monitor.TLSModeTLS || requested == monitor.TLSModeSTARTTLS {
			return requested
		}
		return monitor.TLSModeTLS
	case monitor.KindTCP, monitor.KindICMP:
		if kind == monitor.KindTCP {
			if requested == monitor.TLSModeNone || requested == monitor.TLSModeTLS || requested == monitor.TLSModeSTARTTLS {
				return requested
			}
		}
		return monitor.TLSModeNone
	case monitor.KindSMTP:
		if requested == monitor.TLSModeTLS || requested == monitor.TLSModeSTARTTLS {
			return requested
		}
		return monitor.TLSModeSTARTTLS
	case monitor.KindIMAP:
		if requested == monitor.TLSModeTLS || requested == monitor.TLSModeSTARTTLS {
			return requested
		}
		return monitor.TLSModeTLS
	case monitor.KindDNS, monitor.KindUDP, monitor.KindWhois:
		return monitor.TLSModeNone
	default:
		return requested
	}
}

func monitorTargetLabel(item monitor.Monitor) string {
	if item.Kind != monitor.KindTCP {
		return item.Target
	}
	host, port, err := net.SplitHostPort(item.Target)
	if err != nil {
		return item.Target
	}
	if host == "" {
		host = "localhost"
	}
	return host + ":" + port
}

func monitorTLSModeLabel(item monitor.Monitor) string {
	switch item.Kind {
	case monitor.KindHTTPS:
		return ""
	case monitor.KindSMTP, monitor.KindIMAP:
		if item.TLSMode == monitor.TLSModeSTARTTLS {
			return "STARTTLS"
		}
		return "TLS"
	case monitor.KindTCP:
		switch item.TLSMode {
		case monitor.TLSModeTLS:
			return "TLS"
		case monitor.TLSModeSTARTTLS:
			return "TLS (selfsigned)"
		default:
			return ""
		}
	default:
		return ""
	}
}

func normalizeHTTPMonitorTarget(raw string, mode monitor.TLSMode) string {
	target := strings.TrimSpace(raw)
	if target == "" {
		return target
	}
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasPrefix(target, "//") {
		target = strings.TrimPrefix(target, "//")
	}
	if mode == monitor.TLSModeNone {
		return "http://" + target
	}
	return "https://" + target
}

func monitorHTTPKindLabel(mode monitor.TLSMode) string {
	switch mode {
	case monitor.TLSModeNone:
		return "HTTP"
	case monitor.TLSModeSTARTTLS:
		return "HTTPS (selfsigned)"
	default:
		return "HTTPS"
	}
}

// ========== Tenant-Specific Login Handlers (Multi-Tenant SSO) ==========

func (s *Server) handleTenantEntry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantSlug := tenantSlugFromRequest(r)
	if tenantSlug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), tenantSlug)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if session, err := s.sessions.Get(r); err == nil && session != nil && session.TenantID == tenant.ID {
		http.Redirect(w, r, "/"+tenantSlug+"/", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/"+tenantSlug+"/login", http.StatusSeeOther)
}

func (s *Server) handleTenantLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantSlug := tenantSlugFromRequest(r)
	if tenantSlug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), tenantSlug)
	if err != nil {
		s.logger.Warn("tenant not found for login", "slug", tenantSlug, "error", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	providers, err := s.controlStore.GetAuthProvidersByTenant(r.Context(), tenant.ID)
	if err != nil {
		s.logger.Error("get auth providers for tenant", "tenant_id", tenant.ID, "error", err)
		providers = []store.AuthProvider{} // continue with empty providers
	}

	hasLocal := false
	hasOIDC := false
	for _, provider := range providers {
		switch provider.Kind {
		case "local":
			hasLocal = true
		case "oidc":
			hasOIDC = true
		}
	}
	resetEnabled := hasLocal && s.passwordResetEnabled(r.Context())

	s.render(w, "login", pageData{
		Title:          "Login · " + tenant.Name,
		Error:          strings.TrimSpace(r.URL.Query().Get("error")),
		Notice:         strings.TrimSpace(r.URL.Query().Get("notice")),
		AuthEnabled:    s.cfg.Auth.Mode == config.AuthModeOIDC && hasOIDC,
		User:           s.currentUser(r),
		TenantSlug:     tenant.Slug,
		TenantName:     tenant.Name,
		LoginProviders: providers,
		HasLocalLogin:  hasLocal,
		HasOIDCLogin:   hasOIDC,
		ResetEnabled:   resetEnabled,
	})
}

func (s *Server) handleTenantPasswordResetRequestPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantSlug := tenantSlugFromRequest(r)
	if tenantSlug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), tenantSlug)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !s.passwordResetEnabled(r.Context()) {
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Passwort-Reset ist derzeit nicht verfügbar"), http.StatusSeeOther)
		return
	}

	s.render(w, "password_reset_request", pageData{
		Title:        "Passwort zurücksetzen · " + tenant.Name,
		TenantSlug:   tenant.Slug,
		TenantName:   tenant.Name,
		Error:        strings.TrimSpace(r.URL.Query().Get("error")),
		Notice:       strings.TrimSpace(r.URL.Query().Get("notice")),
		ResetEnabled: true,
	})
}

func (s *Server) handleTenantPasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantSlug := tenantSlugFromRequest(r)
	if tenantSlug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), tenantSlug)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !s.passwordResetEnabled(r.Context()) {
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Passwort-Reset ist derzeit nicht verfügbar"), http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/"+tenantSlug+"/password-reset?error="+url.QueryEscape("Ungültige Eingaben"), http.StatusSeeOther)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))

	// Always answer with the same success notice to avoid user enumeration.
	noticeURL := "/" + tenantSlug + "/password-reset?notice=" + url.QueryEscape("Wenn ein Konto mit dieser E-Mail existiert, wurde ein Reset-Link versendet.")
	if email == "" {
		http.Redirect(w, r, noticeURL, http.StatusSeeOther)
		return
	}

	localUser, err := s.controlStore.FindLocalUserByEmail(r.Context(), tenant.ID, email)
	if err != nil {
		http.Redirect(w, r, noticeURL, http.StatusSeeOther)
		return
	}

	deliveryCfg, err := s.controlStore.GetGlobalSMTPDeliveryConfig(r.Context())
	if err != nil {
		s.logger.Error("load smtp delivery config for password reset", "error", err)
		http.Redirect(w, r, noticeURL, http.StatusSeeOther)
		return
	}

	expiresAt := time.Now().UTC().Add(passwordResetTTL)
	token, err := s.signPasswordResetToken(tenant.ID, localUser.UserID, expiresAt)
	if err != nil {
		s.logger.Error("create password reset token", "error", err)
		http.Redirect(w, r, noticeURL, http.StatusSeeOther)
		return
	}

	resetLink := s.cfg.BaseURL + "/" + tenantSlug + "/password-reset/confirm?token=" + url.QueryEscape(token)
	body := "Hallo " + strings.TrimSpace(localUser.DisplayName) + ",\n\n" +
		"für dein Konto wurde eine Passwort-Zurücksetzung angefordert.\n" +
		"Link: " + resetLink + "\n\n" +
		"Dieser Link ist 30 Minuten gültig.\n" +
		"Falls du das nicht angefordert hast, ignoriere diese E-Mail."
	if strings.TrimSpace(localUser.DisplayName) == "" {
		body = "Hallo,\n\n" +
			"für dein Konto wurde eine Passwort-Zurücksetzung angefordert.\n" +
			"Link: " + resetLink + "\n\n" +
			"Dieser Link ist 30 Minuten gültig.\n" +
			"Falls du das nicht angefordert hast, ignoriere diese E-Mail."
	}

	if err := sendSMTPMail(deliveryCfg, localUser.Email, "GoUp Passwort zurücksetzen", body); err != nil {
		s.logger.Error("send password reset mail failed", "tenant_id", tenant.ID, "user_id", localUser.UserID, "error", err)
	}

	http.Redirect(w, r, noticeURL, http.StatusSeeOther)
}

func (s *Server) handleTenantPasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	tenantSlug := tenantSlugFromRequest(r)
	if tenantSlug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), tenantSlug)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/"+tenantSlug+"/password-reset/confirm?token="+url.QueryEscape(token)+"&error="+url.QueryEscape("Ungültige Eingaben"), http.StatusSeeOther)
			return
		}
		token = strings.TrimSpace(r.FormValue("token"))
		newPassword := r.FormValue("password")
		confirmPassword := r.FormValue("password_confirm")
		if len(strings.TrimSpace(newPassword)) < 8 {
			http.Redirect(w, r, "/"+tenantSlug+"/password-reset/confirm?token="+url.QueryEscape(token)+"&error="+url.QueryEscape("Passwort muss mindestens 8 Zeichen haben"), http.StatusSeeOther)
			return
		}
		if newPassword != confirmPassword {
			http.Redirect(w, r, "/"+tenantSlug+"/password-reset/confirm?token="+url.QueryEscape(token)+"&error="+url.QueryEscape("Passwörter stimmen nicht überein"), http.StatusSeeOther)
			return
		}

		tokenTenantID, userID, _, err := s.parsePasswordResetToken(token)
		if err != nil || tokenTenantID != tenant.ID {
			http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Reset-Link ist ungültig oder abgelaufen"), http.StatusSeeOther)
			return
		}

		if err := s.controlStore.ResetLocalUserPassword(r.Context(), tenant.ID, userID, newPassword); err != nil {
			s.logger.Error("reset local user password failed", "tenant_id", tenant.ID, "user_id", userID, "error", err)
			http.Redirect(w, r, "/"+tenantSlug+"/password-reset/confirm?token="+url.QueryEscape(token)+"&error="+url.QueryEscape("Passwort konnte nicht gesetzt werden"), http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/"+tenantSlug+"/login?notice="+url.QueryEscape("Passwort wurde aktualisiert. Bitte anmelden."), http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if token == "" {
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Reset-Link fehlt"), http.StatusSeeOther)
		return
	}

	tokenTenantID, _, _, err := s.parsePasswordResetToken(token)
	if err != nil || tokenTenantID != tenant.ID {
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Reset-Link ist ungültig oder abgelaufen"), http.StatusSeeOther)
		return
	}

	s.render(w, "password_reset_confirm", pageData{
		Title:      "Neues Passwort · " + tenant.Name,
		TenantSlug: tenant.Slug,
		TenantName: tenant.Name,
		ResetToken: token,
		Error:      strings.TrimSpace(r.URL.Query().Get("error")),
		Notice:     strings.TrimSpace(r.URL.Query().Get("notice")),
	})
}

func (s *Server) handleTenantAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.dynamicOIDC == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tenantSlug := tenantSlugFromRequest(r)
	providerKey := strings.TrimSpace(r.URL.Query().Get("provider"))

	if tenantSlug == "" || providerKey == "" {
		http.Error(w, "tenant_slug and provider required", http.StatusBadRequest)
		return
	}

	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), tenantSlug)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	provider, err := s.controlStore.GetAuthProvider(r.Context(), tenant.ID, providerKey)
	if err != nil {
		s.logger.Warn("auth provider not found", "tenant_id", tenant.ID, "provider_key", providerKey, "error", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if provider.Kind != "oidc" {
		http.Error(w, "unsupported auth provider kind", http.StatusBadRequest)
		return
	}

	cfg := auth.TenantOIDCConfig{
		TenantSlug:  tenantSlug,
		ProviderKey: provider.ProviderKey,
		IssuerURL:   provider.IssuerURL,
		ClientID:    provider.ClientID,
		RedirectURL: s.cfg.BaseURL + "/" + tenantSlug + "/auth/callback",
	}

	redirectURL, err := s.dynamicOIDC.BeginAuthForTenant(w, r, cfg, s.cfg.SecureCookies())
	if err != nil {
		s.logger.Error("begin tenant oidc auth", "tenant_id", tenant.ID, "error", err)
		http.Error(w, "unable to start authentication", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleTenantAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.dynamicOIDC == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tenantSlug := tenantSlugFromRequest(r)
	if tenantSlug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	defer s.dynamicOIDC.ClearEphemeralCookiesForTenant(w, tenantSlug, s.cfg.SecureCookies())

	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), tenantSlug)
	if err != nil {
		s.logger.Warn("tenant not found for callback", "slug", tenantSlug, "error", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Provider key is part of state or stored in cookie from BeginAuthForTenant
	// For now, we'll need to determine the provider from available providers
	// In a real implementation, you might store provider_key in a cookie during BeginAuthForTenant
	providerKey := strings.TrimSpace(r.URL.Query().Get("provider"))
	if providerKey == "" {
		providerKey = s.dynamicOIDC.ProviderKeyFromRequest(r, tenantSlug)
	}
	if providerKey == "" {
		providerKey = "oidc-primary" // default, but should be from state
	}

	provider, err := s.controlStore.GetAuthProvider(r.Context(), tenant.ID, providerKey)
	if err != nil {
		// Try to find first available OIDC provider for tenant
		providers, err := s.controlStore.GetAuthProvidersByTenant(r.Context(), tenant.ID)
		if err != nil || len(providers) == 0 {
			s.logger.Warn("no auth providers found for tenant callback", "tenant_id", tenant.ID)
			http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Authentifizierung nicht konfiguriert"), http.StatusSeeOther)
			return
		}
		provider = providers[0]
	}

	if provider.Kind != "oidc" {
		http.Error(w, "unsupported auth provider kind", http.StatusBadRequest)
		return
	}

	tenantOIDCCfg := auth.TenantOIDCConfig{
		TenantSlug:   tenantSlug,
		ProviderKey:  provider.ProviderKey,
		IssuerURL:    provider.IssuerURL,
		ClientID:     provider.ClientID,
		ClientSecret: "",
		RedirectURL:  s.cfg.BaseURL + "/" + tenantSlug + "/auth/callback",
	}

	secret, err := s.controlStore.GetAuthProviderSecret(r.Context(), tenant.ID, provider.ProviderKey)
	if err == nil {
		tenantOIDCCfg.ClientSecret = secret
	} else {
		s.logger.Error("client secret not available for provider", "tenant_id", tenant.ID, "provider_key", provider.ProviderKey, "error", err)
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("SSO ist nicht vollständig konfiguriert. Bitte Client-Secret im Admin-Provider neu speichern."), http.StatusSeeOther)
		return
	}

	identity, err := s.dynamicOIDC.CompleteAuthForTenant(r.Context(), r, tenantOIDCCfg)
	if err != nil {
		s.logger.Warn("tenant oidc callback failed", "tenant_id", tenant.ID, "error", err)
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Anmeldung fehlgeschlagen"), http.StatusSeeOther)
		return
	}

	resolvedUser, err := s.controlStore.UpsertOIDCUserIdentity(r.Context(), provider.ProviderKey, identity.Subject, identity.Email, identity.Name, tenant.ID)
	if err != nil {
		s.logger.Error("persist tenant oidc user", "tenant_id", tenant.ID, "error", err)
		http.Error(w, "unable to persist user", http.StatusInternalServerError)
		return
	}

	session := auth.UserSession{
		UserID:       resolvedUser.UserID,
		Subject:      identity.Subject,
		Email:        resolvedUser.Email,
		Name:         resolvedUser.DisplayName,
		TenantID:     resolvedUser.TenantID,
		TenantSlug:   resolvedUser.TenantSlug,
		TenantName:   resolvedUser.TenantName,
		Role:         resolvedUser.Role,
		AuthProvider: provider.ProviderKey,
		ExpiresAt:    time.Now().Add(12 * time.Hour),
	}
	if err := s.sessions.Set(w, session); err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/"+tenantSlug+"/", http.StatusSeeOther)
}

func (s *Server) handleTenantLocalLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tenantSlug := tenantSlugFromRequest(r)
		if tenantSlug == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/"+tenantSlug+"/login", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantSlug := tenantSlugFromRequest(r)
	if tenantSlug == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), tenantSlug)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	providers, err := s.controlStore.GetAuthProvidersByTenant(r.Context(), tenant.ID)
	if err != nil {
		s.logger.Warn("get providers for local login", "tenant_id", tenant.ID, "error", err)
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Anmeldung nicht verfügbar"), http.StatusSeeOther)
		return
	}
	hasLocalProvider := false
	for _, provider := range providers {
		if provider.Kind == "local" {
			hasLocalProvider = true
			break
		}
	}
	if !hasLocalProvider {
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Lokale Anmeldung ist für diesen Tenant nicht aktiviert"), http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Ungültige Eingaben"), http.StatusSeeOther)
		return
	}

	loginName := strings.TrimSpace(r.FormValue("login_name"))
	password := r.FormValue("password")
	key := s.localLoginKey(r, tenant.ID, loginName)
	if allowed, wait := s.localLoginAllowed(key, time.Now()); !allowed {
		waitMinutes := int(wait.Round(time.Minute).Minutes())
		if waitMinutes < 1 {
			waitMinutes = 1
		}
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape(fmt.Sprintf("Zu viele Fehlversuche. Bitte in %d Minute(n) erneut versuchen", waitMinutes)), http.StatusSeeOther)
		return
	}

	resolvedUser, err := s.controlStore.AuthenticateLocalUser(r.Context(), tenant.ID, loginName, password)
	if err != nil {
		s.registerLocalLoginFailure(key, time.Now())
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Anmeldung fehlgeschlagen"), http.StatusSeeOther)
		return
	}
	s.clearLocalLoginAttempts(key)

	session := auth.UserSession{
		UserID:       resolvedUser.UserID,
		Subject:      "local:" + strings.ToLower(loginName),
		Email:        resolvedUser.Email,
		Name:         resolvedUser.DisplayName,
		TenantID:     resolvedUser.TenantID,
		TenantSlug:   resolvedUser.TenantSlug,
		TenantName:   resolvedUser.TenantName,
		Role:         resolvedUser.Role,
		AuthProvider: "local",
		ExpiresAt:    time.Now().Add(12 * time.Hour),
	}
	if err := s.sessions.Set(w, session); err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/"+tenantSlug+"/", http.StatusSeeOther)
}
