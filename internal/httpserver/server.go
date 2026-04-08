package httpserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
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

	"github.com/gorilla/websocket"
	"golang.org/x/net/html"
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

type dashboardIconAsset struct {
	Payload     []byte
	ContentType string
}

type localLoginAttempt struct {
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
}

type pageData struct {
	Title                string
	UILanguage           string
	Translations         map[string]string
	HideTopbar           bool
	User                 *auth.UserSession
	IsAdmin              bool
	Stats                store.DashboardStats
	Error                string
	Notice               string
	FormAction           string
	BackURL              string
	IsEdit               bool
	SettingsMode         bool
	AuthEnabled          bool
	AuthDisabled         bool
	OIDCTenantOnly       bool
	TrendValue           string
	TrendLabel           string
	TrendRanges          []trendRangeOptionView
	Monitors             []monitorView
	MonitorGroups        []monitorGroupView
	AvailableGroups      []string
	RemoteNodes          []remoteNodeView
	HasRemoteNodes       bool
	MonitorExecutors     []monitorExecutorOptionView
	Events               []notificationEventView
	StateEvents          []monitorStateEventView
	AdminTenants         []store.Tenant
	AdminMonitorCount    int
	AdminRemoteNodeCount int
	AdminTenant          store.Tenant
	AdminProviders       []store.AuthProvider
	AdminProviderRows    []adminProviderOverviewRow
	AdminProvider        store.AuthProvider
	AdminLocalUsers      []store.LocalUser
	AdminTenantUsers     []store.TenantUser
	AdminUserRows        []adminUserOverviewRow
	AdminLocalUser       store.LocalUser
	AdminRemoteNodeRows  []adminRemoteNodeOverviewRow
	ProfileUser          store.TenantUser
	ProfileNotify        store.UserNotificationSettings
	AdminAuditEvents     []store.AuditEvent
	AuditAction          string
	AuditActor           string
	AuditTargetType      string
	AuditActions         []string
	AuditTargetTypes     []string
	GlobalSMTP           store.GlobalSMTPSettings
	ControlPlaneAdmin    bool
	AutoDBPath           string
	TenantSlug           string
	TenantName           string
	AppBase              string
	LoginProviders       []store.AuthProvider
	HasLocalLogin        bool
	HasOIDCLogin         bool
	ResetEnabled         bool
	ResetToken           string
	AdminSetup           bool
	AdminUsername        string
	TOTPRequired         bool
	TOTPEnabled          bool
	TOTPSecret           string
	TOTPProvisioningURI  string
	LanguageOptions      []languageOptionView
}

type languageOptionView struct {
	Code     string
	Label    string
	Selected bool
}

const (
	localLoginMaxFailures  = 5
	localLoginWindow       = 10 * time.Minute
	localLoginLockout      = 15 * time.Minute
	adminAccessMaxFailures = 10
	adminAccessWindow      = 5 * time.Minute
	adminAccessLockout     = 30 * time.Minute
	bootstrapMaxFailures   = 8
	bootstrapWindow        = 5 * time.Minute
	bootstrapLockout       = 15 * time.Minute
	passwordResetTTL       = 15 * time.Minute
	controlPlaneAdminTTL   = 1 * time.Hour
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

type remoteNodeView struct {
	NodeID          string
	Name            string
	LastSeenAt      string
	LastSeenAtRaw   string
	Online          bool
	HeartbeatWindow string
	ProvisionURL    string
	Events          []remoteNodeEventView
}

type remoteNodeEventView struct {
	EventLabel    string
	SourceIP      string
	UserAgent     string
	Details       string
	OccurredAt    string
	OccurredAtRaw string
}

type adminProviderOverviewRow struct {
	TenantID    int64
	TenantName  string
	TenantSlug  string
	ProviderKey string
	Kind        string
	DisplayName string
	Enabled     bool
}

type adminUserOverviewRow struct {
	TenantID            int64
	TenantName          string
	TenantSlug          string
	UserID              int64
	LoginName           string
	Email               string
	DisplayName         string
	Role                string
	LastLoginAt         string
	LastLoginAtRaw      string
	HasLocalCredentials bool
	HasOIDCIdentity     bool
}

type adminRemoteNodeOverviewRow struct {
	TenantID        int64
	TenantName      string
	TenantSlug      string
	NodeID          string
	Name            string
	Online          bool
	LastSeenAt      string
	LastSeenAtRaw   string
	HeartbeatWindow string
}

type monitorExecutorOptionView struct {
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
	Value      string
	Source     string
	Preferred  bool
}

type dashboardIconSearchResult struct {
	Value     string `json:"value"`
	Slug      string `json:"slug"`
	Label     string `json:"label"`
	URL       string `json:"url"`
	Source    string `json:"source"`
	Preferred bool   `json:"preferred"`
}

type trendPointView struct {
	BucketRaw     string
	Percent       int
	Class         string
	Label         string
	Format        string
	Checks        int
	LatencyChecks int
	AvgMS         int
	MinMS         int
	MaxMS         int
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
	ExecutorKind     string
	ExecutorRef      string
	ExecutorValue    string
	ExecutorLabel    string
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

var (
	tenantIconDirKeyPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	dashboardIconFileSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

const (
	dashboardIconsBaseURL     = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons"
	dashboardIconsMetadataURL = "https://raw.githubusercontent.com/homarr-labs/dashboard-icons/refs/heads/main/metadata.json"
	dashboardIconSearchLimit  = 24
	groupIconUploadPrefix     = "upload:"
	groupIconUploadMaxBytes   = 2 << 20
)

var dashboardLiveUpgraderBase = websocket.Upgrader{
	ReadBufferSize:    1024,
	WriteBufferSize:   1024,
	EnableCompression: true,
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

func (s *Server) routes() (http.Handler, error) {
	mux := http.NewServeMux()

	staticFS, err := fs.Sub(web.FS, "static")
	if err != nil {
		return nil, fmt.Errorf("sub static fs: %w", err)
	}
	assetsFS, err := fs.Sub(webassets.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("sub assets fs: %w", err)
	}
	faviconFS, err := fs.Sub(webassets.FS, "favicon")
	if err != nil {
		return nil, fmt.Errorf("sub favicon fs: %w", err)
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
	mux.HandleFunc("/node/bootstrap", s.handleRemoteNodeBootstrap)
	mux.HandleFunc("/node/poll", s.handleRemoteNodePoll)
	mux.HandleFunc("/node/report", s.handleRemoteNodeReport)

	// Control-plane admin routes (separate access mechanism, no tenant session required)
	mux.HandleFunc("/admin/setup", s.handleAdminSetup)
	mux.HandleFunc("/admin/access", s.handleAdminAccess)
	mux.Handle("/admin/security", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminSecuritySettings)))
	mux.Handle("/admin/security/totp/disable", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTOTPDisable)))
	mux.Handle("/admin/", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminDashboard)))
	mux.Handle("/admin/tenants", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTenantsList)))
	mux.Handle("/admin/providers", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminProvidersOverview)))
	mux.Handle("/admin/users", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminUsersOverview)))
	mux.Handle("/admin/remote-nodes", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminRemoteNodesOverview)))
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
	mux.Handle("/admin/tenants/{id}/remote-nodes", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminRemoteNodesList)))
	mux.Handle("/admin/tenants/{id}/remote-nodes/create", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminCreateRemoteNode)))
	mux.Handle("/admin/tenants/{id}/remote-nodes/{nodeID}/rotate-bootstrap", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminRotateRemoteNodeBootstrapKey)))
	mux.Handle("/admin/tenants/{id}/remote-nodes/{nodeID}/delete", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminDeleteRemoteNode)))
	mux.Handle("/admin/tenants/{id}/users/{userID}/remove", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminTenantUserRemove)))
	mux.Handle("/admin/settings/smtp/save", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminSMTPSettingsSave)))

	return s.logging(s.securityHeaders(s.requireSameOrigin(mux))), nil
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
		if strings.HasPrefix(r.URL.Path, "/node/") {
			next.ServeHTTP(w, r)
			return
		}

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
	mux.Handle("/auth/logout", http.HandlerFunc(s.handleLogout))
	mux.Handle("/", s.requireAuth(http.HandlerFunc(s.handleDashboard)))
	mux.Handle("/live", s.requireAuth(http.HandlerFunc(s.handleDashboardLive)))
	mux.Handle("/live/snapshot", s.requireAuth(http.HandlerFunc(s.handleDashboardLiveSnapshot)))
	mux.Handle("/monitors", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSaveMonitor))))
	mux.Handle("/monitors/save", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSaveMonitor))))
	mux.Handle("/monitors/update-target", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleUpdateMonitorTarget))))
	mux.Handle("/monitors/reorder", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleReorderMonitor))))
	mux.Handle("/groups/save", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSaveGroup))))
	mux.Handle("/groups/delete", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleDeleteGroup))))
	mux.Handle("/groups/reorder", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleReorderGroup))))
	mux.Handle("/icons/search", s.requireAuth(http.HandlerFunc(s.handleSearchDashboardIcons)))
	mux.Handle("/icons/render", s.requireAuth(http.HandlerFunc(s.handleRenderIcon)))
	mux.Handle("/monitors/delete", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleDeleteMonitor))))
	mux.Handle("/monitors/enabled", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSetMonitorEnabled))))
	mux.Handle("/monitors/check-now", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleCheckMonitorNow))))
	mux.Handle("/monitors/latency-history", s.requireAuth(http.HandlerFunc(s.handleMonitorLatencyHistory)))
	mux.Handle("/settings/profile", s.requireAuth(http.HandlerFunc(s.handleSettingsProfile)))
	mux.Handle("/settings/profile/save", s.requireAuth(http.HandlerFunc(s.handleSettingsProfileSave)))
	mux.Handle("/settings/profile/notifiers/delete", s.requireAuth(http.HandlerFunc(s.handleSettingsProfileNotifierDelete)))
	mux.Handle("/settings/profile/password", s.requireAuth(http.HandlerFunc(s.handleSettingsProfilePassword)))
	mux.Handle("/settings/users", s.requireUserManagement(http.HandlerFunc(s.handleSettingsUsers)))
	mux.Handle("/settings/providers", s.requireUserManagement(http.HandlerFunc(s.handleSettingsProviders)))
	mux.Handle("/settings/providers/new", s.requireUserManagement(http.HandlerFunc(s.handleSettingsProviderForm)))
	mux.Handle("/settings/providers/{providerKey}/edit", s.requireUserManagement(http.HandlerFunc(s.handleSettingsProviderForm)))
	mux.Handle("/settings/providers/save", s.requireUserManagement(http.HandlerFunc(s.handleSettingsProviderSave)))
	mux.Handle("/settings/providers/{providerKey}/delete", s.requireUserManagement(http.HandlerFunc(s.handleSettingsProviderDelete)))
	mux.Handle("/settings/remote-nodes", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSettingsRemoteNodes))))
	mux.Handle("/settings/remote-nodes/live", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSettingsRemoteNodesLive))))
	mux.Handle("/settings/remote-nodes/live/snapshot", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleSettingsRemoteNodesLiveSnapshot))))
	mux.Handle("/settings/local-users/new", s.requireUserManagement(http.HandlerFunc(s.handleSettingsLocalUserForm)))
	mux.Handle("/settings/local-users/{userID}/edit", s.requireUserManagement(http.HandlerFunc(s.handleSettingsLocalUserForm)))
	mux.Handle("/settings/local-users/save", s.requireUserManagement(http.HandlerFunc(s.handleSettingsLocalUserSave)))
	mux.Handle("/settings/local-users/{userID}/delete", s.requireUserManagement(http.HandlerFunc(s.handleSettingsLocalUserDelete)))
	mux.Handle("/settings/users/{userID}/role", s.requireUserManagement(http.HandlerFunc(s.handleSettingsUserRoleSave)))
	mux.Handle("/settings/users/{userID}/remove", s.requireUserManagement(http.HandlerFunc(s.handleSettingsUserRemove)))
	mux.Handle("/settings/remote-nodes/create", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleCreateRemoteNode))))
	mux.Handle("/settings/remote-nodes/{nodeID}/rotate-bootstrap", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleRotateRemoteNodeBootstrapKey))))
	mux.Handle("/settings/remote-nodes/{nodeID}/delete", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleDeleteRemoteNode))))
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
	preferredLanguage := normalizeUILanguage(resolvedUser.PreferredLanguage)
	if strings.TrimSpace(resolvedUser.PreferredLanguage) == "" {
		preferredLanguage = detectPreferredLanguage(r)
		if err := s.controlStore.UpdateUserPreferredLanguageForTenant(r.Context(), resolvedUser.TenantID, resolvedUser.UserID, preferredLanguage); err != nil {
			s.logger.Warn("persist preferred language failed", "user_id", resolvedUser.UserID, "tenant_id", resolvedUser.TenantID, "error", err)
		}
	}

	session := auth.UserSession{
		UserID:            resolvedUser.UserID,
		Subject:           identity.Subject,
		Email:             resolvedUser.Email,
		Name:              resolvedUser.DisplayName,
		PreferredLanguage: preferredLanguage,
		TenantID:          resolvedUser.TenantID,
		TenantSlug:        resolvedUser.TenantSlug,
		TenantName:        resolvedUser.TenantName,
		Role:              resolvedUser.Role,
		AuthProvider:      "oidc-primary",
		ExpiresAt:         time.Now().Add(12 * time.Hour),
	}
	if err := s.sessions.Set(w, session); err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/"+resolvedUser.TenantSlug+"/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := s.sessionForRequest(r)
	if slug := strings.TrimSpace(tenantSlugFromRequest(r)); slug != "" {
		s.sessions.ClearForTenant(w, slug)
	} else if session != nil && strings.TrimSpace(session.TenantSlug) != "" {
		s.sessions.ClearForTenant(w, session.TenantSlug)
	} else {
		s.sessions.Clear(w)
	}
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

	data, err := s.loadDashboardPageData(r, appStore, strings.TrimSpace(r.URL.Query().Get("trend")), strings.TrimSpace(r.URL.Query().Get("notice")), strings.TrimSpace(r.URL.Query().Get("error")))
	if err != nil {
		http.Error(w, "unable to load dashboard", http.StatusInternalServerError)
		return
	}

	s.render(w, "dashboard", data)
}

func (s *Server) handleSearchDashboardIcons(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}
	results, err := s.searchDashboardIcons(r.Context(), s.tenantSlugForRequest(r), appStore, s.tenantAppBase(r), strings.TrimSpace(r.URL.Query().Get("q")), dashboardIconSearchLimit)
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

func (s *Server) handleRenderIcon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ref := normalizeGroupIconReference(strings.TrimSpace(r.URL.Query().Get("ref")))
	if ref == "" {
		http.NotFound(w, r)
		return
	}

	var (
		payload     []byte
		contentType string
		err         error
	)
	switch kind, value := splitGroupIconReference(ref); kind {
	case groupIconSourceUpload:
		payload, contentType, err = s.loadUploadedIcon(r, value)
	default:
		payload, contentType, err = s.loadDashboardIconAsset(r.Context(), s.tenantSlugForRequest(r), value)
	}
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "private, max-age=86400")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(payload)
}

type dashboardLiveSnapshotResponse struct {
	StatsHTML              string            `json:"stats_html,omitempty"`
	BoardHTML              string            `json:"board_html,omitempty"`
	BoardGroupsHTML        map[string]string `json:"board_groups_html,omitempty"`
	StateEventsHTML        string            `json:"state_events_html,omitempty"`
	NotificationEventsHTML string            `json:"notification_events_html,omitempty"`
	GroupOptionsHTML       string            `json:"group_options_html,omitempty"`
	StatsHash              string            `json:"stats_hash,omitempty"`
	BoardHash              string            `json:"board_hash,omitempty"`
	BoardGroupsHash        map[string]string `json:"board_groups_hash,omitempty"`
	StateEventsHash        string            `json:"state_events_hash,omitempty"`
	NotificationEventsHash string            `json:"notification_events_hash,omitempty"`
	GroupOptionsHash       string            `json:"group_options_hash,omitempty"`
	BoardGroupHashes       map[string]string `json:"-"`
	BoardGroupOrder        []string          `json:"-"`
}

type dashboardLiveRefreshMessage struct {
	Type        string   `json:"type"`
	Parts       []string `json:"parts,omitempty"`
	BoardGroups []string `json:"board_groups,omitempty"`
}

func (s *Server) handleDashboardLiveSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	data, err := s.loadDashboardPageData(r, appStore, strings.TrimSpace(r.URL.Query().Get("trend")), "", "")
	if err != nil {
		http.Error(w, "unable to load dashboard snapshot", http.StatusInternalServerError)
		return
	}

	snapshot, err := s.renderDashboardLiveSnapshotResponse(data)
	if err != nil {
		http.Error(w, "unable to render dashboard snapshot", http.StatusInternalServerError)
		return
	}

	parts := parseDashboardLiveRequestedParts(strings.TrimSpace(r.URL.Query().Get("parts")))
	boardGroups := parseDashboardLiveRequestedBoardGroups(strings.TrimSpace(r.URL.Query().Get("board_groups")))
	if len(parts) > 0 {
		snapshot = filterDashboardLiveSnapshotParts(snapshot, parts)
	}
	if len(boardGroups) > 0 && (parts == nil || hasDashboardLivePart(parts, "board")) {
		snapshot = filterDashboardLiveSnapshotBoardGroups(snapshot, boardGroups)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, "unable to encode dashboard snapshot", http.StatusInternalServerError)
		return
	}
}

func (s *Server) loadDashboardPageData(r *http.Request, appStore *store.Store, trendValue string, noticeText string, errorText string) (pageData, error) {
	stats, err := appStore.DashboardStats(r.Context())
	if err != nil {
		return pageData{}, err
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		return pageData{}, err
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
		return pageData{}, err
	}

	now := time.Now().UTC()
	selectedTrend := parseTrendRange(strings.TrimSpace(trendValue))
	trendSince := trendRangeStart(now, selectedTrend)
	rollups, err := appStore.ListMonitorHourlyRollupsSince(r.Context(), trendSince)
	if err != nil {
		s.logger.Warn("load monitor trends failed", "error", err)
		rollups = nil
	}

	tenantID := tenantIDFromRequest(r)
	remoteNodes, err := s.controlStore.ListRemoteNodesByTenant(r.Context(), tenantID)
	if err != nil {
		s.logger.Warn("load remote nodes failed", "tenant_id", tenantID, "error", err)
		remoteNodes = nil
	}
	monitorViews := buildMonitorViews(snapshots, rollups, now, selectedTrend, buildRemoteNodeNameMap(remoteNodes))
	availableGroups := buildAvailableGroups(groupMetadata)
	availableGroups = mergeAvailableGroups(availableGroups, monitorViews)
	remoteNodeViews := buildRemoteNodeViews(remoteNodes, now, s.cfg.BaseURL, nil)
	executorOptions := buildMonitorExecutorOptions(remoteNodes)

	curUser := s.currentUser(r)
	preferredLanguage := defaultUILanguage
	if curUser != nil {
		preferredLanguage = normalizeUILanguage(curUser.PreferredLanguage)
		if strings.TrimSpace(curUser.PreferredLanguage) == "" {
			preferredLanguage = detectPreferredLanguage(r)
		}
	} else {
		preferredLanguage = detectPreferredLanguage(r)
	}
	translations := s.translationsForLanguage(preferredLanguage)
	noticeLocalized := localizeFlashMessage(translations, noticeText)
	errorLocalized := localizeFlashMessage(translations, errorText)

	return pageData{
		Title:            "Dashboard · GoUp",
		User:             curUser,
		UILanguage:       preferredLanguage,
		Translations:     translations,
		IsAdmin:          curUser == nil || strings.EqualFold(strings.TrimSpace(curUser.Role), "admin"),
		Stats:            stats,
		Notice:           noticeLocalized,
		Error:            errorLocalized,
		AuthEnabled:      s.cfg.Auth.Mode == config.AuthModeOIDC,
		AuthDisabled:     s.cfg.Auth.Mode != config.AuthModeOIDC,
		TrendValue:       selectedTrend.Value,
		TrendLabel:       selectedTrend.Label,
		TrendRanges:      buildTrendRangeOptions(selectedTrend),
		Monitors:         monitorViews,
		MonitorGroups:    buildMonitorGroups(s.tenantAppBase(r), monitorViews, groupMetadata),
		AvailableGroups:  availableGroups,
		RemoteNodes:      remoteNodeViews,
		HasRemoteNodes:   len(executorOptions) > 1,
		MonitorExecutors: executorOptions,
		Events:           buildNotificationEventViews(events),
		StateEvents:      buildMonitorStateEventViews(stateEvents),
		AppBase:          s.tenantAppBase(r),
	}, nil
}

func (s *Server) renderDashboardTemplateFragment(name string, data pageData) (string, error) {
	tmpl, ok := s.templates["dashboard"]
	if !ok {
		return "", fmt.Errorf("dashboard template not found")
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, name, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

func (s *Server) renderDashboardLiveSnapshotResponse(data pageData) (dashboardLiveSnapshotResponse, error) {
	tmpl, ok := s.templates["dashboard"]
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard template not found")
	}

	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "layout", data); err != nil {
		return dashboardLiveSnapshotResponse{}, err
	}

	doc, err := html.Parse(strings.NewReader(out.String()))
	if err != nil {
		return dashboardLiveSnapshotResponse{}, err
	}

	statsHTML, ok := outerHTMLByID(doc, "dashboard-live-stats")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard stats fragment not found")
	}
	boardHTML, ok := outerHTMLByID(doc, "dashboard-live-board")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard board fragment not found")
	}
	boardNode := htmlNodeByID(doc, "dashboard-live-board")
	boardGroupsHTML, boardGroupOrder := boardClustersByGroup(boardNode)
	boardGroupHashes := make(map[string]string, len(boardGroupsHTML))
	for group, fragment := range boardGroupsHTML {
		boardGroupHashes[group] = hashDashboardFragment(fragment)
	}
	stateEventsHTML, ok := outerHTMLByID(doc, "dashboard-live-state-events")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard state events fragment not found")
	}
	notificationEventsHTML, ok := outerHTMLByID(doc, "dashboard-live-notification-events")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard notification events fragment not found")
	}
	groupOptionsHTML, ok := innerHTMLByID(doc, "monitor-group-options")
	if !ok {
		groupOptionsHTML = ""
	}

	return dashboardLiveSnapshotResponse{
		StatsHTML:              statsHTML,
		BoardHTML:              boardHTML,
		BoardGroupsHTML:        boardGroupsHTML,
		StateEventsHTML:        stateEventsHTML,
		NotificationEventsHTML: notificationEventsHTML,
		GroupOptionsHTML:       groupOptionsHTML,
		StatsHash:              hashDashboardFragment(statsHTML),
		BoardHash:              hashDashboardFragment(boardHTML),
		BoardGroupsHash:        boardGroupHashes,
		StateEventsHash:        hashDashboardFragment(stateEventsHTML),
		NotificationEventsHash: hashDashboardFragment(notificationEventsHTML),
		GroupOptionsHash:       hashDashboardFragment(groupOptionsHTML),
		BoardGroupHashes:       boardGroupHashes,
		BoardGroupOrder:        boardGroupOrder,
	}, nil
}

func hashDashboardFragment(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func parseDashboardLiveRequestedParts(raw string) map[string]struct{} {
	if raw == "" {
		return nil
	}
	allowed := map[string]struct{}{
		"stats":               {},
		"board":               {},
		"state_events":        {},
		"notification_events": {},
		"group_options":       {},
	}
	parts := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		part := strings.TrimSpace(strings.ToLower(item))
		if part == "" {
			continue
		}
		if _, ok := allowed[part]; ok {
			parts[part] = struct{}{}
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return parts
}

func parseDashboardLiveRequestedBoardGroups(raw string) []string {
	if raw == "" {
		return nil
	}
	groups := make([]string, 0, 8)
	seen := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		group := strings.TrimSpace(item)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
		if len(groups) >= 64 {
			break
		}
	}
	if len(groups) == 0 {
		return nil
	}
	return groups
}

func hasDashboardLivePart(parts map[string]struct{}, part string) bool {
	_, ok := parts[part]
	return ok
}

func filterDashboardLiveSnapshotParts(snapshot dashboardLiveSnapshotResponse, parts map[string]struct{}) dashboardLiveSnapshotResponse {
	if _, ok := parts["stats"]; !ok {
		snapshot.StatsHTML = ""
		snapshot.StatsHash = ""
	}
	if _, ok := parts["board"]; !ok {
		snapshot.BoardHTML = ""
		snapshot.BoardHash = ""
		snapshot.BoardGroupsHTML = nil
		snapshot.BoardGroupsHash = nil
	}
	if _, ok := parts["state_events"]; !ok {
		snapshot.StateEventsHTML = ""
		snapshot.StateEventsHash = ""
	}
	if _, ok := parts["notification_events"]; !ok {
		snapshot.NotificationEventsHTML = ""
		snapshot.NotificationEventsHash = ""
	}
	if _, ok := parts["group_options"]; !ok {
		snapshot.GroupOptionsHTML = ""
		snapshot.GroupOptionsHash = ""
	}
	return snapshot
}

func filterDashboardLiveSnapshotBoardGroups(snapshot dashboardLiveSnapshotResponse, groups []string) dashboardLiveSnapshotResponse {
	if len(groups) == 0 {
		return snapshot
	}
	if len(snapshot.BoardGroupsHTML) == 0 {
		return snapshot
	}

	filteredHTML := make(map[string]string)
	filteredHashes := make(map[string]string)
	for _, group := range groups {
		fragment, ok := snapshot.BoardGroupsHTML[group]
		if !ok {
			continue
		}
		filteredHTML[group] = fragment
		hash := snapshot.BoardGroupsHash[group]
		if hash == "" {
			hash = hashDashboardFragment(fragment)
		}
		filteredHashes[group] = hash
	}

	snapshot.BoardHTML = ""
	snapshot.BoardGroupsHTML = filteredHTML
	snapshot.BoardGroupsHash = filteredHashes
	return snapshot
}

func dashboardLiveChangedParts(previous dashboardLiveSnapshotResponse, next dashboardLiveSnapshotResponse) []string {
	parts := make([]string, 0, 5)
	if previous.StatsHash != next.StatsHash {
		parts = append(parts, "stats")
	}
	if previous.BoardHash != next.BoardHash {
		parts = append(parts, "board")
	}
	if previous.StateEventsHash != next.StateEventsHash {
		parts = append(parts, "state_events")
	}
	if previous.NotificationEventsHash != next.NotificationEventsHash {
		parts = append(parts, "notification_events")
	}
	if previous.GroupOptionsHash != next.GroupOptionsHash {
		parts = append(parts, "group_options")
	}
	return parts
}

func dashboardLiveChangedBoardGroups(previous dashboardLiveSnapshotResponse, next dashboardLiveSnapshotResponse) []string {
	if len(previous.BoardGroupOrder) == 0 || len(next.BoardGroupOrder) == 0 {
		return nil
	}
	if !equalStringSlices(previous.BoardGroupOrder, next.BoardGroupOrder) {
		return nil
	}
	if len(previous.BoardGroupHashes) != len(next.BoardGroupHashes) {
		return nil
	}

	changed := make([]string, 0, len(next.BoardGroupOrder))
	for _, group := range next.BoardGroupOrder {
		nextHash, nextOK := next.BoardGroupHashes[group]
		prevHash, prevOK := previous.BoardGroupHashes[group]
		if !nextOK || !prevOK {
			return nil
		}
		if nextHash != prevHash {
			changed = append(changed, group)
		}
	}

	if len(changed) == 0 {
		return nil
	}
	return changed
}

func equalStringSlices(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func boardClustersByGroup(boardNode *html.Node) (map[string]string, []string) {
	if boardNode == nil {
		return nil, nil
	}

	groups := make(map[string]string)
	order := make([]string, 0, 16)
	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node == nil {
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "details") && htmlHasClass(node, "service-cluster") {
			group := htmlAttr(node, "data-group")
			if group != "" {
				var buf bytes.Buffer
				if err := html.Render(&buf, node); err == nil {
					groups[group] = buf.String()
					order = append(order, group)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(boardNode)
	if len(groups) == 0 {
		return nil, nil
	}
	return groups, order
}

func htmlHasClass(node *html.Node, className string) bool {
	if node == nil || className == "" {
		return false
	}
	for _, attr := range node.Attr {
		if attr.Key != "class" {
			continue
		}
		for _, value := range strings.Fields(attr.Val) {
			if value == className {
				return true
			}
		}
	}
	return false
}

func htmlAttr(node *html.Node, key string) string {
	if node == nil || key == "" {
		return ""
	}
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func outerHTMLByID(root *html.Node, id string) (string, bool) {
	node := htmlNodeByID(root, id)
	if node == nil {
		return "", false
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, node); err != nil {
		return "", false
	}
	return buf.String(), true
}

func innerHTMLByID(root *html.Node, id string) (string, bool) {
	node := htmlNodeByID(root, id)
	if node == nil {
		return "", false
	}
	var buf bytes.Buffer
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if err := html.Render(&buf, child); err != nil {
			return "", false
		}
	}
	return buf.String(), true
}

func htmlNodeByID(node *html.Node, id string) *html.Node {
	if node == nil {
		return nil
	}
	if node.Type == html.ElementNode {
		for _, attr := range node.Attr {
			if attr.Key == "id" && attr.Val == id {
				return node
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if match := htmlNodeByID(child, id); match != nil {
			return match
		}
	}
	return nil
}

func (s *Server) handleDashboardLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.websocketOriginAllowed(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	trendValue := strings.TrimSpace(r.URL.Query().Get("trend"))
	initialData, err := s.loadDashboardPageData(r, appStore, trendValue, "", "")
	if err != nil {
		http.Error(w, "unable to initialize live updates", http.StatusInternalServerError)
		return
	}
	previousSnapshot, err := s.renderDashboardLiveSnapshotResponse(initialData)
	if err != nil {
		http.Error(w, "unable to initialize live updates", http.StatusInternalServerError)
		return
	}

	upgrader := s.dashboardLiveUpgrader()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.EnableWriteCompression(true)

	const readTimeout = 120 * time.Second
	const writeTimeout = 10 * time.Second

	conn.SetReadLimit(1024)
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		return nil
	})

	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err == nil {
		_ = conn.WriteJSON(struct {
			Type string `json:"type"`
		}{Type: "connected"})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, readErr := conn.ReadMessage(); readErr != nil {
				return
			}
		}
	}()

	pingTicker := time.NewTicker(25 * time.Second)
	pollTicker := time.NewTicker(4 * time.Second)
	defer pingTicker.Stop()
	defer pollTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case <-pingTicker.C:
			if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.PingMessage, []byte("ping")); err != nil {
				return
			}
		case <-pollTicker.C:
			if _, sessErr := s.sessionForRequest(r); sessErr != nil {
				_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				_ = conn.WriteJSON(map[string]string{"type": "session_expired"})
				return
			}
			nextData, dataErr := s.loadDashboardPageData(r, appStore, trendValue, "", "")
			if dataErr != nil {
				s.logger.Warn("load dashboard live data failed", "error", dataErr)
				continue
			}
			nextSnapshot, snapshotErr := s.renderDashboardLiveSnapshotResponse(nextData)
			if snapshotErr != nil {
				s.logger.Warn("render dashboard live snapshot failed", "error", snapshotErr)
				continue
			}

			changedParts := dashboardLiveChangedParts(previousSnapshot, nextSnapshot)
			if len(changedParts) == 0 {
				continue
			}
			changedBoardGroups := make([]string, 0, 8)
			for _, part := range changedParts {
				if part == "board" {
					changedBoardGroups = dashboardLiveChangedBoardGroups(previousSnapshot, nextSnapshot)
					break
				}
			}
			previousSnapshot = nextSnapshot

			if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return
			}
			if err := conn.WriteJSON(dashboardLiveRefreshMessage{Type: "refresh", Parts: changedParts, BoardGroups: changedBoardGroups}); err != nil {
				return
			}
		}
	}
}

func (s *Server) websocketOriginAllowed(r *http.Request) bool {
	origin := normalizeOrigin(strings.TrimSpace(r.Header.Get("Origin")))
	if origin == "" {
		return true
	}

	expected, err := url.Parse(strings.TrimSpace(s.cfg.BaseURL))
	if err != nil || strings.TrimSpace(expected.Scheme) == "" || strings.TrimSpace(expected.Host) == "" {
		return true
	}

	allowed := make(map[string]struct{})
	for _, value := range buildAllowedOrigins(
		strings.ToLower(strings.TrimSpace(expected.Scheme)),
		strings.ToLower(strings.TrimSpace(expected.Hostname())),
		strings.TrimSpace(expected.Port()),
		r,
	) {
		allowed[value] = struct{}{}
	}
	_, ok := allowed[origin]
	return ok
}

func (s *Server) dashboardLiveUpgrader() websocket.Upgrader {
	upgrader := dashboardLiveUpgraderBase
	upgrader.CheckOrigin = s.websocketOriginAllowed
	return upgrader
}

func (s *Server) dashboardLiveSignature(ctx context.Context, appStore *store.Store) (string, error) {
	stats, err := appStore.DashboardStats(ctx)
	if err != nil {
		return "", err
	}

	snapshots, err := appStore.ListMonitorSnapshots(ctx)
	if err != nil {
		return "", err
	}

	groups, err := appStore.ListMonitorGroupMetadata(ctx)
	if err != nil {
		return "", err
	}

	stateEvents, stateErr := appStore.ListRecentMonitorStateEvents(ctx, 5)
	if stateErr != nil {
		s.logger.Warn("load state events for live signature failed", "error", stateErr)
		stateEvents = nil
	}

	notificationEvents, notifErr := appStore.ListRecentNotificationEvents(ctx, 5)
	if notifErr != nil {
		s.logger.Warn("load notification events for live signature failed", "error", notifErr)
		notificationEvents = nil
	}

	h := sha256.New()
	_, _ = fmt.Fprintf(h, "stats:%d:%d:%d\n", stats.MonitorCount, stats.EnabledMonitorCount, stats.OpenIncidentCount)
	for _, snapshot := range snapshots {
		item := snapshot.Monitor
		_, _ = fmt.Fprintf(h,
			"m:%d|%s|%s|%d|%s|%s|%t|%s|%d|%d|%s\n",
			item.ID,
			strings.TrimSpace(item.Name),
			strings.TrimSpace(item.Group),
			item.SortOrder,
			item.Kind,
			strings.TrimSpace(item.Target),
			item.Enabled,
			item.TLSMode,
			int(item.Interval.Seconds()),
			int(item.Timeout.Seconds()),
			item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		)
		if snapshot.LastResult != nil {
			last := snapshot.LastResult
			_, _ = fmt.Fprintf(h,
				"r:%d|%s|%s|%s|%d\n",
				item.ID,
				last.CheckedAt.UTC().Format(time.RFC3339Nano),
				last.Status,
				strings.TrimSpace(last.Message),
				last.Latency.Milliseconds(),
			)
		}
	}

	for _, group := range groups {
		_, _ = fmt.Fprintf(h, "g:%s|%s|%d\n", strings.TrimSpace(group.Name), strings.TrimSpace(group.IconSlug), group.SortOrder)
	}

	for _, event := range stateEvents {
		_, _ = fmt.Fprintf(h,
			"se:%d|%d|%s|%s|%s|%s\n",
			event.ID,
			event.MonitorID,
			event.CheckedAt.UTC().Format(time.RFC3339Nano),
			strings.TrimSpace(event.FromStatus),
			strings.TrimSpace(event.ToStatus),
			strings.TrimSpace(event.Message),
		)
	}

	for _, event := range notificationEvents {
		_, _ = fmt.Fprintf(h,
			"ne:%d|%d|%d|%s|%s|%s\n",
			event.ID,
			event.MonitorID,
			event.EndpointID,
			strings.TrimSpace(event.EventType),
			event.CreatedAt.UTC().Format(time.RFC3339Nano),
			strings.TrimSpace(event.Error),
		)
		if event.DeliveredAt != nil {
			_, _ = fmt.Fprintf(h, "ned:%d|%s\n", event.ID, event.DeliveredAt.UTC().Format(time.RFC3339Nano))
		}
	}

	return hex.EncodeToString(h.Sum(nil)), nil
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
		monitorViews := buildMonitorViews(snapshots, nil, time.Now().UTC(), supportedTrendRanges[0], nil)
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
	monitorViews := buildMonitorViews(snapshots, nil, time.Now().UTC(), supportedTrendRanges[0], nil)
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
	r.Body = http.MaxBytesReader(w, r.Body, groupIconUploadMaxBytes+(1<<20))
	if err := r.ParseMultipartForm(groupIconUploadMaxBytes + (256 << 10)); err != nil && err != http.ErrNotMultipart {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	iconRef := normalizeGroupIconReference(strings.TrimSpace(r.FormValue("icon_slug")))
	uploadedIconRef, err := s.storeUploadedGroupIcon(r, groupName)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	if uploadedIconRef != "" {
		iconRef = uploadedIconRef
	} else if err := s.persistSelectedDashboardIcon(r.Context(), s.tenantSlugForRequest(r), iconRef); err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	if err := appStore.UpdateMonitorGroupIcon(r.Context(), groupName, iconRef); err != nil {
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
	if kind == monitor.KindHTTPS || kind == monitor.KindDNS || kind == monitor.KindUDP {
		expectedText = strings.TrimSpace(r.FormValue("expected_text"))
	}

	target := strings.TrimSpace(r.FormValue("target"))
	if kind == monitor.KindDNS {
		dnsHost := strings.TrimSpace(r.FormValue("dns_host"))
		dnsRecordType := monitor.NormalizeDNSRecordType(strings.TrimSpace(r.FormValue("dns_record_type")))
		dnsServer := strings.TrimSpace(r.FormValue("dns_server"))
		if dnsHost != "" || dnsServer != "" || dnsRecordType != monitor.DNSRecordTypeMixed {
			target = monitor.ComposeDNSTarget(dnsHost, dnsRecordType, dnsServer)
		}
		if normalizedTarget, normalizeErr := monitor.NormalizeDNSTarget(target); normalizeErr == nil {
			target = normalizedTarget
		}
	}
	if kind == monitor.KindHTTPS {
		httpHost := strings.TrimSpace(r.FormValue("http_host"))
		httpPort := strings.TrimSpace(r.FormValue("http_port"))
		httpPath := strings.TrimSpace(r.FormValue("http_path"))
		if httpHost != "" || httpPort != "" || httpPath != "" {
			target = buildHTTPMonitorTarget(httpHost, httpPort, httpPath, tlsMode)
		} else {
			target = normalizeHTTPMonitorTarget(target, tlsMode)
		}

		if parsedTarget, parseErr := url.Parse(target); parseErr == nil {
			hostname := strings.TrimSpace(parsedTarget.Hostname())
			if hostname != "" {
				if isLiteralIPAddress(hostname) {
					tlsMode = monitor.ComposeHTTPSTLSMode(tlsMode, monitor.TCPAddressFamilyDual)
				} else {
					family := monitor.NormalizeTCPAddressFamily(strings.TrimSpace(r.FormValue("https_family")))
					tlsMode = monitor.ComposeHTTPSTLSMode(tlsMode, family)
				}
			}
		}
	}
	if kind == monitor.KindTCP {
		tcpHost := strings.TrimSpace(r.FormValue("tcp_host"))
		tcpPort := strings.TrimSpace(r.FormValue("tcp_port"))
		if tcpHost != "" || tcpPort != "" {
			target = strings.TrimSpace(net.JoinHostPort(strings.Trim(tcpHost, "[]"), tcpPort))
		}
		if host, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			if isLiteralIPAddress(host) {
				tlsMode = monitor.ComposeTCPTLSMode(tlsMode, monitor.TCPAddressFamilyDual)
			} else {
				family := monitor.NormalizeTCPAddressFamily(strings.TrimSpace(r.FormValue("tcp_family")))
				tlsMode = monitor.ComposeTCPTLSMode(tlsMode, family)
			}
		}
	}
	if kind == monitor.KindSMTP || kind == monitor.KindIMAP {
		mailHost := strings.TrimSpace(r.FormValue("mail_host"))
		mailPort := strings.TrimSpace(r.FormValue("mail_port"))
		if mailHost != "" || mailPort != "" {
			target = strings.TrimSpace(net.JoinHostPort(strings.Trim(mailHost, "[]"), mailPort))
		}
		mailSecurityMode, mailVerifyCert, _ := monitor.ParseMailTLSMode(tlsMode)
		if rawSkip := strings.TrimSpace(r.FormValue("mail_skip_cert")); rawSkip != "" {
			mailSkipCert := strings.EqualFold(rawSkip, "on") || strings.EqualFold(rawSkip, "true") || rawSkip == "1"
			mailVerifyCert = !mailSkipCert
		} else if rawVerify := strings.TrimSpace(r.FormValue("mail_verify_cert")); rawVerify != "" {
			// Backward compatibility for older form payloads.
			mailVerifyCert = strings.EqualFold(rawVerify, "on") || strings.EqualFold(rawVerify, "true") || rawVerify == "1"
		}
		if mailSecurityMode == monitor.TLSModeNone {
			mailVerifyCert = false
		}
		mailFamily := monitor.TCPAddressFamilyDual
		if host, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			if isLiteralIPAddress(host) {
				mailFamily = monitor.TCPAddressFamilyDual
			} else {
				mailFamily = monitor.NormalizeTCPAddressFamily(strings.TrimSpace(r.FormValue("mail_family")))
			}
		}
		tlsMode = monitor.ComposeMailTLSMode(mailSecurityMode, mailVerifyCert, mailFamily)
	}
	if kind == monitor.KindICMP {
		if !isLiteralIPAddress(target) && target != "" {
			switch strings.ToLower(strings.TrimSpace(r.FormValue("icmp_family"))) {
			case "ipv6":
				tlsMode = monitor.TLSModeSTARTTLS
			case "dual":
				tlsMode = monitor.TLSModeNone
			default:
				tlsMode = monitor.TLSModeTLS
			}
		} else {
			tlsMode = monitor.TLSModeNone
		}
	}
	if kind == monitor.KindUDP {
		udpHost := strings.TrimSpace(r.FormValue("udp_host"))
		udpPort := strings.TrimSpace(r.FormValue("udp_port"))
		if udpHost != "" || udpPort != "" {
			target = strings.TrimSpace(net.JoinHostPort(strings.Trim(udpHost, "[]"), udpPort))
		}
		probeKind := monitor.NormalizeUDPProbeKind(strings.TrimSpace(r.FormValue("udp_check")))
		family := monitor.TCPAddressFamilyDual
		if host, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			if !isLiteralIPAddress(host) {
				family = monitor.NormalizeTCPAddressFamily(strings.TrimSpace(r.FormValue("udp_family")))
			}
		}
		tlsMode = monitor.ComposeUDPMode(probeKind, family)
		if probeKind != monitor.UDPProbeKindWireGuard {
			expectedText = ""
		}
	}

	executorKind, executorRef := parseMonitorExecutorSelection(strings.TrimSpace(r.FormValue("executor")))
	if executorKind == "remote" {
		tenantID := tenantIDFromRequest(r)
		if tenantID <= 0 {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
			return
		}
		if _, err := s.controlStore.GetRemoteNodeByTenantAndNodeID(r.Context(), tenantID, executorRef); err != nil {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ausgewählte Remote-Node ist nicht verfügbar"), http.StatusSeeOther)
			return
		}
	}

	params := store.CreateMonitorParams{
		Name:               strings.TrimSpace(r.FormValue("name")),
		Group:              strings.TrimSpace(r.FormValue("group")),
		ExecutorKind:       executorKind,
		ExecutorRef:        executorRef,
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

func checkerForMonitorKind(kind monitor.Kind) (monitor.Checker, bool) {
	switch kind {
	case monitor.KindHTTPS:
		return monitor.HTTPSChecker{}, true
	case monitor.KindTCP:
		return monitor.TCPChecker{}, true
	case monitor.KindICMP:
		return monitor.ICMPChecker{}, true
	case monitor.KindSMTP:
		return monitor.SMTPChecker{}, true
	case monitor.KindIMAP:
		return monitor.IMAPChecker{}, true
	case monitor.KindDNS:
		return monitor.DNSChecker{}, true
	case monitor.KindUDP:
		return monitor.UDPChecker{}, true
	case monitor.KindWhois:
		return monitor.WhoisChecker{}, true
	default:
		return nil, false
	}
}

func (s *Server) handleCheckMonitorNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form payload", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid monitor id", http.StatusBadRequest)
		return
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Error(w, "unable to load monitor", http.StatusInternalServerError)
		return
	}

	var selected *monitor.Snapshot
	for i := range snapshots {
		if snapshots[i].Monitor.ID == id {
			selected = &snapshots[i]
			break
		}
	}
	if selected == nil {
		http.Error(w, "monitor not found", http.StatusNotFound)
		return
	}
	if strings.EqualFold(strings.TrimSpace(selected.Monitor.ExecutorKind), "remote") {
		http.Error(w, "manual checks are disabled for remote-node monitors", http.StatusConflict)
		return
	}

	checker, ok := checkerForMonitorKind(selected.Monitor.Kind)
	if !ok {
		http.Error(w, "monitor kind is not supported", http.StatusBadRequest)
		return
	}

	runCtx, cancel := context.WithTimeout(r.Context(), selected.Monitor.Timeout+2*time.Second)
	result := checker.Check(runCtx, selected.Monitor)
	cancel()

	if err := appStore.SaveMonitorResult(r.Context(), result); err != nil {
		http.Error(w, "unable to store check result", http.StatusInternalServerError)
		return
	}
	if err := appStore.RecordMonitorState(r.Context(), selected.Monitor.ID, result.Status, result.Message, result.CheckedAt); err != nil {
		http.Error(w, "unable to store monitor state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK        bool   `json:"ok"`
		CheckedAt string `json:"checked_at"`
		Status    string `json:"status"`
		Message   string `json:"message"`
	}{
		OK:        true,
		CheckedAt: result.CheckedAt.UTC().Format(time.RFC3339),
		Status:    string(result.Status),
		Message:   strings.TrimSpace(result.Message),
	})
}

func (s *Server) handleMonitorLatencyHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	monitorID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("monitor_id")), 10, 64)
	if err != nil || monitorID <= 0 {
		http.Error(w, "invalid monitor id", http.StatusBadRequest)
		return
	}

	rangeValue := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("range")))
	if rangeValue == "" {
		rangeValue = "1h"
	}

	now := time.Now().UTC()
	since := now.Add(-time.Hour)
	limit := 480
	switch rangeValue {
	case "6h":
		since = now.Add(-6 * time.Hour)
		limit = 2400
	case "24h":
		since = now.Add(-24 * time.Hour)
		limit = 6000
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
		limit = 24000
	default:
		rangeValue = "1h"
	}

	points, err := appStore.ListMonitorLatencyHistory(r.Context(), monitorID, since, limit)
	if err != nil {
		http.Error(w, "unable to load latency history", http.StatusInternalServerError)
		return
	}

	type latencyPointPayload struct {
		CheckedAt string `json:"checked_at"`
		LatencyMS int    `json:"latency_ms"`
		Status    string `json:"status"`
	}
	responsePoints := make([]latencyPointPayload, 0, len(points))
	latencySum := 0
	latencyCount := 0
	for _, point := range points {
		responsePoints = append(responsePoints, latencyPointPayload{
			CheckedAt: point.CheckedAt.UTC().Format(time.RFC3339),
			LatencyMS: point.LatencyMS,
			Status:    strings.TrimSpace(point.Status),
		})
		if !strings.EqualFold(strings.TrimSpace(point.Status), string(monitor.StatusDown)) && point.LatencyMS >= 0 {
			latencySum += point.LatencyMS
			latencyCount++
		}
	}

	averageMS := 0
	if latencyCount > 0 {
		averageMS = int(float64(latencySum)/float64(latencyCount) + 0.5)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK        bool                  `json:"ok"`
		MonitorID int64                 `json:"monitor_id"`
		Range     string                `json:"range"`
		AverageMS int                   `json:"average_ms"`
		Points    []latencyPointPayload `json:"points"`
	}{
		OK:        true,
		MonitorID: monitorID,
		Range:     rangeValue,
		AverageMS: averageMS,
		Points:    responsePoints,
	})
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

		session, err := s.sessionForRequest(r)
		if err != nil {
			slug := tenantSlugFromRequest(r)
			if slug != "" {
				http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
			return
		}

		if tenantID := tenantIDFromRequest(r); tenantID > 0 && session != nil && session.TenantID > 0 && session.TenantID != tenantID {
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
		session, err := s.sessionForRequest(r)
		if err != nil {
			slug := tenantSlugFromRequest(r)
			if slug != "" {
				http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
			return
		}
		if tenantID := tenantIDFromRequest(r); tenantID > 0 && session.TenantID > 0 && session.TenantID != tenantID {
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
		session, err := s.sessionForRequest(r)
		if err == nil {
			if tenantID := tenantIDFromRequest(r); tenantID > 0 && session.TenantID > 0 && session.TenantID != tenantID {
				slug := tenantSlugFromRequest(r)
				if slug != "" {
					http.Redirect(w, r, "/"+slug+"/login", http.StatusSeeOther)
				} else {
					http.Redirect(w, r, "/", http.StatusSeeOther)
				}
				return
			}
			if !strings.EqualFold(strings.TrimSpace(session.Role), "admin") {
				http.Error(w, "forbidden: admin role required", http.StatusForbidden)
				return
			}
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

func (s *Server) bootstrapAttemptKey(r *http.Request, nodeID string) string {
	return "node-bootstrap|" + strings.ToLower(strings.TrimSpace(nodeID)) + "|" + s.clientIP(r)
}

func (s *Server) bootstrapAllowed(key string, now time.Time) (bool, time.Duration) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	attempt, ok := s.bootstrapAttempts[key]
	if !ok {
		return true, 0
	}
	if !attempt.LockedUntil.IsZero() && attempt.LockedUntil.After(now) {
		return false, time.Until(attempt.LockedUntil)
	}
	if !attempt.WindowStart.IsZero() && now.Sub(attempt.WindowStart) > bootstrapWindow {
		delete(s.bootstrapAttempts, key)
	}
	return true, 0
}

func (s *Server) registerBootstrapFailure(key string, now time.Time) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	attempt := s.bootstrapAttempts[key]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > bootstrapWindow {
		attempt = localLoginAttempt{Failures: 1, WindowStart: now}
		s.bootstrapAttempts[key] = attempt
		return
	}
	attempt.Failures++
	if attempt.Failures >= bootstrapMaxFailures {
		attempt.Failures = 0
		attempt.WindowStart = now
		attempt.LockedUntil = now.Add(bootstrapLockout)
	}
	s.bootstrapAttempts[key] = attempt
}

func (s *Server) clearBootstrapAttempts(key string) {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	delete(s.bootstrapAttempts, key)
}

func (s *Server) currentUser(r *http.Request) *auth.UserSession {
	session, err := s.sessionForRequest(r)
	if err != nil {
		return nil
	}
	return session
}

func (s *Server) sessionForRequest(r *http.Request) (*auth.UserSession, error) {
	if slug := strings.TrimSpace(tenantSlugFromRequest(r)); slug != "" {
		return s.sessions.GetForTenant(r, slug)
	}
	return s.sessions.Get(r)
}

func (s *Server) appStore(r *http.Request) (*store.Store, error) {
	if s.tenantStores == nil {
		return s.store, nil
	}
	if tenantID := tenantIDFromRequest(r); tenantID > 0 {
		return s.tenantStores.StoreForTenant(r.Context(), tenantID)
	}
	currentUser := s.currentUser(r)
	if currentUser == nil || currentUser.TenantID <= 0 {
		return s.store, nil
	}
	return s.tenantStores.StoreForTenant(r.Context(), currentUser.TenantID)
}

func (s *Server) tenantSlugForRequest(r *http.Request) string {
	if slug := strings.TrimSpace(tenantSlugFromRequest(r)); slug != "" {
		return slug
	}
	if currentUser := s.currentUser(r); currentUser != nil && strings.TrimSpace(currentUser.TenantSlug) != "" {
		return strings.TrimSpace(currentUser.TenantSlug)
	}
	if slug := strings.TrimSpace(s.defaultTenant.Slug); slug != "" {
		return slug
	}
	return "default"
}

func (s *Server) uploadedIconsDir(tenantSlug string) string {
	tenantSlug = normalizeTenantIconDirKey(tenantSlug)
	if tenantSlug == "" {
		tenantSlug = "default"
	}
	return filepath.Join(s.cfg.DataDir, "icons", tenantSlug)
}

func (s *Server) persistedDashboardIconsDir(tenantSlug string) string {
	return filepath.Join(s.uploadedIconsDir(tenantSlug), "dashboard")
}

func (s *Server) storeUploadedGroupIcon(r *http.Request, groupName string) (string, error) {
	file, header, err := r.FormFile("icon_upload")
	if err != nil {
		if err == http.ErrMissingFile {
			return "", nil
		}
		return "", fmt.Errorf("Icon-Upload konnte nicht gelesen werden")
	}
	defer file.Close()

	payload, err := io.ReadAll(io.LimitReader(file, groupIconUploadMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("Icon-Upload konnte nicht gelesen werden")
	}
	if len(payload) == 0 {
		return "", nil
	}
	if len(payload) > groupIconUploadMaxBytes {
		return "", fmt.Errorf("Icon-Upload ist zu groß (max. 2 MB)")
	}

	contentType := http.DetectContentType(payload)
	ext, ok := detectUploadedIconExtension(contentType, header.Filename)
	if !ok {
		return "", fmt.Errorf("Nur SVG, PNG, WEBP, JPEG oder ICO werden als Gruppen-Icon unterstützt")
	}

	hashBytes := sha256.Sum256(payload)
	hash := hex.EncodeToString(hashBytes[:])
	baseName := sanitizeUploadedIconBaseName(header.Filename)
	if baseName == "" {
		baseName = normalizeDashboardIconSlug(groupName)
	}
	if baseName == "" {
		baseName = "custom-icon"
	}

	dir := s.uploadedIconsDir(s.tenantSlugForRequest(r))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("Upload-Verzeichnis konnte nicht vorbereitet werden")
	}
	if existing := findUploadedIconByHash(dir, hash); existing != "" {
		return groupIconUploadPrefix + existing, nil
	}

	fileName := hash + "-" + baseName + ext
	iconPath, err := safePathWithinDir(dir, fileName)
	if err != nil {
		return "", fmt.Errorf("Icon-Upload konnte nicht gespeichert werden")
	}
	if err := os.WriteFile(iconPath, payload, 0o644); err != nil {
		return "", fmt.Errorf("Icon-Upload konnte nicht gespeichert werden")
	}
	return groupIconUploadPrefix + fileName, nil
}

func (s *Server) loadUploadedIcon(r *http.Request, fileName string) ([]byte, string, error) {
	fileName = sanitizeUploadedIconName(fileName)
	if fileName == "" {
		return nil, "", os.ErrNotExist
	}
	iconPath, err := safePathWithinDir(s.uploadedIconsDir(s.tenantSlugForRequest(r)), fileName)
	if err != nil {
		return nil, "", os.ErrNotExist
	}
	payload, err := os.ReadFile(iconPath)
	if err != nil {
		return nil, "", err
	}
	contentType := mime.TypeByExtension(filepath.Ext(fileName))
	if contentType == "" {
		contentType = http.DetectContentType(payload)
	}
	return payload, contentType, nil
}

func (s *Server) persistSelectedDashboardIcon(ctx context.Context, tenantSlug string, ref string) error {
	kind, slug := splitGroupIconReference(ref)
	slug = sanitizeDashboardIconFileSlug(slug)
	if kind != groupIconSourceDashboard || slug == "" {
		return nil
	}
	known, err := s.dashboardIconExists(ctx, slug)
	if err != nil {
		return fmt.Errorf("Dashboard-Icon konnte nicht geprüft werden")
	}
	if !known {
		return nil
	}
	payload, _, err := s.loadDashboardIconAsset(ctx, tenantSlug, slug)
	if err != nil {
		return fmt.Errorf("Dashboard-Icon konnte nicht lokal gespeichert werden")
	}
	dir := s.persistedDashboardIconsDir(tenantSlug)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("Dashboard-Icon-Verzeichnis konnte nicht vorbereitet werden")
	}
	iconPath, err := safePathWithinDir(dir, slug+".svg")
	if err != nil {
		return fmt.Errorf("Dashboard-Icon konnte nicht lokal gespeichert werden")
	}
	if err := os.WriteFile(iconPath, payload, 0o644); err != nil {
		return fmt.Errorf("Dashboard-Icon konnte nicht lokal gespeichert werden")
	}
	return nil
}

func (s *Server) dashboardIconExists(ctx context.Context, slug string) (bool, error) {
	slug = sanitizeDashboardIconFileSlug(slug)
	if slug == "" {
		return false, nil
	}
	entries, err := s.loadDashboardIconIndex(ctx)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Source == groupIconSourceDashboard && entry.Slug == slug {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) loadPersistedDashboardIcon(tenantSlug string, slug string) ([]byte, string, error) {
	slug = sanitizeDashboardIconFileSlug(slug)
	if slug == "" {
		return nil, "", os.ErrNotExist
	}
	iconPath, err := safePathWithinDir(s.persistedDashboardIconsDir(tenantSlug), slug+".svg")
	if err != nil {
		return nil, "", os.ErrNotExist
	}
	payload, err := os.ReadFile(iconPath)
	if err != nil {
		return nil, "", err
	}
	contentType := mime.TypeByExtension(".svg")
	if contentType == "" {
		contentType = http.DetectContentType(payload)
	}
	return payload, contentType, nil
}

func sanitizeUploadedIconName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "." || name == ".." || name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `/\\`) {
		return ""
	}
	return name
}

func sanitizeDashboardIconFileSlug(slug string) string {
	slug = normalizeDashboardIconSlug(slug)
	if slug == "" || strings.Contains(slug, "..") || strings.ContainsAny(slug, `/\\`) {
		return ""
	}
	if !dashboardIconFileSlugPattern.MatchString(slug) {
		return ""
	}
	return slug
}

func normalizeTenantIconDirKey(slug string) string {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" {
		return ""
	}
	if !tenantIconDirKeyPattern.MatchString(slug) {
		return ""
	}
	return slug
}

func safePathWithinDir(baseDir string, name string) (string, error) {
	baseDir = strings.TrimSpace(baseDir)
	name = strings.TrimSpace(name)
	if baseDir == "" || name == "" {
		return "", fmt.Errorf("invalid path")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("invalid path")
	}
	cleanName := filepath.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid path")
	}
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(absBaseDir, cleanName)
	rel, err := filepath.Rel(absBaseDir, fullPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid path")
	}
	return fullPath, nil
}

func sanitizeUploadedIconBaseName(name string) string {
	name = sanitizeUploadedIconName(name)
	if name == "" {
		return ""
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	base = normalizeDashboardIconSlug(base)
	if base == "" {
		return ""
	}
	return base
}

// detectUploadedIconExtension validates an uploaded icon by requiring BOTH a
// whitelisted file extension AND a matching MIME type.  Checking the extension
// first prevents an attacker from uploading a file whose content passes MIME
// sniffing but whose extension hints at a dangerous type.
func detectUploadedIconExtension(contentType string, originalName string) (string, bool) {
	// Step 1: validate the file extension against the strict whitelist.
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(originalName)))
	if ext == ".jpeg" {
		ext = ".jpg"
	}
	allowedExts := map[string]string{
		".svg":  "image/svg+xml",
		".png":  "image/png",
		".webp": "image/webp",
		".jpg":  "image/jpeg",
		".ico":  "image/x-icon",
	}
	expectedMIME, extOK := allowedExts[ext]
	if !extOK {
		return "", false
	}

	// Step 2: confirm the detected MIME type matches the extension.
	detectedMIME := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch detectedMIME {
	case "image/svg+xml", "image/png", "image/webp", "image/jpeg",
		"image/x-icon", "image/vnd.microsoft.icon":
		// Acceptable MIME; verify it corresponds to the declared extension.
		if detectedMIME == "image/vnd.microsoft.icon" {
			detectedMIME = "image/x-icon"
		}
		if detectedMIME != expectedMIME {
			return "", false
		}
		return ext, true
	default:
		return "", false
	}
}

func findUploadedIconByHash(dir string, hash string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	prefix := hash + "-"
	for _, item := range entries {
		if item.IsDir() {
			continue
		}
		name := sanitizeUploadedIconName(item.Name())
		if strings.HasPrefix(name, prefix) {
			return name
		}
	}
	return ""
}

func formatUploadedIconLabel(fileName string) string {
	name := sanitizeUploadedIconName(fileName)
	if name == "" {
		return "Eigenes Icon"
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if len(base) > 65 && base[64] == '-' {
		base = base[65:]
	}
	label := formatDashboardIconLabel(base)
	if label == "" {
		return "Eigenes Icon"
	}
	return label
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
	case "login", "admin_access", "admin_setup", "no_tenant":
		data.HideTopbar = true
	}
	if strings.TrimSpace(data.UILanguage) == "" {
		if data.User != nil {
			data.UILanguage = normalizeUILanguage(data.User.PreferredLanguage)
		} else {
			data.UILanguage = defaultUILanguage
		}
	}
	if data.Translations == nil {
		data.Translations = s.translationsForLanguage(data.UILanguage)
	}
	data.Error = localizeFlashMessage(data.Translations, data.Error)
	data.Notice = localizeFlashMessage(data.Translations, data.Notice)

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
		// Content Security Policy: only same-origin assets, including locally served icon cache/uploads
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self' data:; "+
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
	pages := []string{"dashboard", "login", "password_reset_request", "password_reset_confirm", "admin_dashboard", "admin_tenants", "admin_tenant_form", "admin_providers", "admin_providers_overview", "admin_provider_form", "admin_local_users", "admin_users_overview", "admin_local_user_form", "admin_remote_nodes", "admin_remote_nodes_overview", "settings_users", "settings_profile", "settings_providers", "settings_provider_form", "settings_remote_nodes", "admin_access", "admin_setup", "admin_security", "no_tenant"}
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

func buildMonitorViews(items []monitor.Snapshot, rollups []store.MonitorHourlyRollup, now time.Time, selectedTrend trendRange, remoteNodeNames map[string]string) []monitorView {
	rollupsByMonitor := groupRollupsByMonitor(rollups)
	views := make([]monitorView, 0, len(items))
	for _, item := range items {
		kindLabel := monitorKindLabel(item.Monitor.Kind)
		tlsLabel := monitorTLSModeLabel(item.Monitor)
		if item.Monitor.Kind == monitor.KindHTTPS {
			kindLabel = monitorHTTPKindLabel(item.Monitor.Target, item.Monitor.TLSMode)
			tlsLabel = ""
		}

		view := monitorView{
			ID:               item.Monitor.ID,
			Name:             item.Monitor.Name,
			Group:            effectiveMonitorGroup(strings.TrimSpace(item.Monitor.Group), item.Monitor.Name, item.Monitor.Target),
			SortOrder:        item.Monitor.SortOrder,
			ExecutorKind:     strings.TrimSpace(item.Monitor.ExecutorKind),
			ExecutorRef:      strings.TrimSpace(item.Monitor.ExecutorRef),
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
		if view.ExecutorKind == "" {
			view.ExecutorKind = "local"
		}
		if view.ExecutorKind == "remote" && view.ExecutorRef != "" {
			view.ExecutorValue = "remote:" + view.ExecutorRef
			view.ExecutorLabel = "Remote: " + view.ExecutorRef
			if remoteNodeNames != nil {
				if remoteName := strings.TrimSpace(remoteNodeNames[view.ExecutorRef]); remoteName != "" {
					view.ExecutorLabel = "Remote: " + remoteName + " (" + view.ExecutorRef + ")"
				}
			}
		} else {
			view.ExecutorKind = "local"
			view.ExecutorRef = ""
			view.ExecutorValue = "local"
			view.ExecutorLabel = "Control-Plane (lokal)"
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
			view.LastLatency = formatLatencyLabel(item.LastResult.Latency)
			if isTimeoutMessage(item.LastResult.Message) {
				view.LastLatency = ""
			}
			if item.Monitor.Kind == monitor.KindICMP {
				if dualLatency := icmpDualStackLatencyLabel(item.LastResult.Message); dualLatency != "" {
					view.LastLatency = dualLatency
				}
			}
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

func icmpDualStackLatencyLabel(message string) string {
	trimmed := strings.TrimSpace(message)
	if !strings.HasPrefix(trimmed, "ICMP dual stack") {
		return ""
	}
	parts := strings.Split(trimmed, " · ")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[1:], " · ")
}

func formatLatencyLabel(duration time.Duration) string {
	if duration <= 0 {
		return "0ms"
	}
	if duration < time.Millisecond {
		return "<1ms"
	}
	if duration < time.Second {
		return strconv.FormatInt(duration.Milliseconds(), 10) + "ms"
	}
	seconds := duration.Seconds()
	formatted := strconv.FormatFloat(seconds, 'f', 2, 64)
	formatted = strings.TrimRight(strings.TrimRight(formatted, "0"), ".")
	return formatted + "s"
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

func buildRemoteNodeViews(items []store.RemoteNode, now time.Time, baseURL string, eventsByNode map[string][]store.RemoteNodeEvent) []remoteNodeView {
	views := make([]remoteNodeView, 0, len(items))
	bootstrapURL := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/node/bootstrap"
	for _, item := range items {
		view := remoteNodeView{
			NodeID:          item.NodeID,
			Name:            item.Name,
			Online:          item.IsOnline(now),
			HeartbeatWindow: fmt.Sprintf("%ds", item.HeartbeatTimeoutSeconds),
			ProvisionURL:    bootstrapURL,
		}
		if item.LastSeenAt != nil {
			view.LastSeenAtRaw = item.LastSeenAt.UTC().Format(time.RFC3339)
			view.LastSeenAt = view.LastSeenAtRaw
		}
		if eventsByNode != nil {
			events := eventsByNode[item.NodeID]
			if len(events) > 0 {
				view.Events = make([]remoteNodeEventView, 0, len(events))
				for _, event := range events {
					eventTime := event.CreatedAt.UTC().Format(time.RFC3339)
					view.Events = append(view.Events, remoteNodeEventView{
						EventLabel:    remoteNodeEventLabel(event.EventType),
						SourceIP:      strings.TrimSpace(event.RemoteIP),
						UserAgent:     strings.TrimSpace(event.UserAgent),
						Details:       strings.TrimSpace(event.Details),
						OccurredAt:    eventTime,
						OccurredAtRaw: eventTime,
					})
				}
			}
		}
		views = append(views, view)
	}
	return views
}

func buildRemoteNodeNameMap(nodes []store.RemoteNode) map[string]string {
	if len(nodes) == 0 {
		return nil
	}
	result := make(map[string]string, len(nodes))
	for _, node := range nodes {
		nodeID := strings.TrimSpace(node.NodeID)
		if nodeID == "" {
			continue
		}
		result[nodeID] = strings.TrimSpace(node.Name)
	}
	return result
}

func groupRemoteNodeEventsByNode(items []store.RemoteNodeEvent, perNodeLimit int) map[string][]store.RemoteNodeEvent {
	if len(items) == 0 {
		return nil
	}
	if perNodeLimit <= 0 {
		perNodeLimit = 6
	}
	grouped := make(map[string][]store.RemoteNodeEvent)
	for _, item := range items {
		nodeID := strings.TrimSpace(item.NodeID)
		if nodeID == "" {
			continue
		}
		if len(grouped[nodeID]) >= perNodeLimit {
			continue
		}
		grouped[nodeID] = append(grouped[nodeID], item)
	}
	return grouped
}

func remoteNodeEventLabel(eventType string) string {
	switch strings.TrimSpace(strings.ToLower(eventType)) {
	case "bootstrap":
		return "Bootstrap"
	case "poll":
		return "Poll"
	case "report":
		return "Report"
	default:
		return strings.TrimSpace(eventType)
	}
}

func buildMonitorExecutorOptions(nodes []store.RemoteNode) []monitorExecutorOptionView {
	options := make([]monitorExecutorOptionView, 0, len(nodes)+1)
	options = append(options, monitorExecutorOptionView{Value: "local", Label: "Control-Plane (lokal)", Selected: true})
	for _, node := range nodes {
		options = append(options, monitorExecutorOptionView{
			Value: "remote:" + node.NodeID,
			Label: strings.TrimSpace(node.Name),
		})
	}
	return options
}

func buildMonitorGroups(appBase string, monitors []monitorView, metadata []store.MonitorGroup) []monitorGroupView {
	groupSortOrder := make(map[string]int, len(metadata))
	groupIcons := make(map[string]string, len(metadata))
	for idx, item := range metadata {
		name := strings.TrimSpace(item.Name)
		groupSortOrder[name] = idx
		groupIcons[name] = normalizeGroupIconReference(item.IconSlug)
	}

	services := buildMonitorServiceGroups(appBase, monitors, groupSortOrder, groupIcons, len(metadata))
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

func buildMonitorStatusGroup(title string, subtitle string, emptyText string, accentClass string, monitors []monitorView, groupSortOrder map[string]int, groupIcons map[string]string, totalGroups int, appBase string) monitorGroupView {
	services := buildMonitorServiceGroups(appBase, monitors, groupSortOrder, groupIcons, totalGroups)
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

func buildMonitorServiceGroups(appBase string, monitors []monitorView, groupSortOrder map[string]int, groupIcons map[string]string, totalGroups int) []monitorServiceGroupView {
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
		iconRef := effectiveGroupIconReference(label, groupIcons[label])
		services = append(services, monitorServiceGroupView{
			Title:       label,
			Subtitle:    subtitle,
			StatusLabel: statusLabel,
			StatusClass: statusClass,
			StatusInfo:  statusInfo,
			TrendLabel:  trendLabel,
			UptimeLabel: uptimeLabel,
			TrendPoints: aggregatePoints,
			IconSlug:    iconRef,
			IconURL:     localIconURL(appBase, iconRef),
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
		totalChecks   int
		upChecks      int
		latencyChecks int
		latencySum    int
		hasMinMS      bool
		minMS         int
		maxMS         int
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
			agg[i].latencyChecks += point.LatencyChecks
			agg[i].latencySum += point.AvgMS * point.LatencyChecks
			if point.LatencyChecks > 0 && (!agg[i].hasMinMS || point.MinMS < agg[i].minMS) {
				agg[i].hasMinMS = true
				agg[i].minMS = point.MinMS
			}
			if point.LatencyChecks > 0 && point.MaxMS > agg[i].maxMS {
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
		buckets[i].LatencyChecks = agg[i].latencyChecks
		if agg[i].latencyChecks > 0 {
			buckets[i].AvgMS = agg[i].latencySum / agg[i].latencyChecks
		}
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

func normalizeDashboardIconSlug(slug string) string {
	slug = strings.ToLower(strings.TrimSpace(slug))
	slug = strings.ReplaceAll(slug, " ", "-")
	return slug
}

const (
	groupIconSourceDashboard = "dashboard"
	groupIconSourceUpload    = "upload"
)

func normalizeGroupIconReference(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(ref), groupIconUploadPrefix) {
		name := sanitizeUploadedIconName(strings.TrimSpace(ref[len(groupIconUploadPrefix):]))
		if name == "" {
			return ""
		}
		return groupIconUploadPrefix + name
	}
	return normalizeDashboardIconSlug(ref)
}

func splitGroupIconReference(ref string) (kind string, value string) {
	ref = normalizeGroupIconReference(ref)
	if strings.HasPrefix(ref, groupIconUploadPrefix) {
		return groupIconSourceUpload, strings.TrimSpace(ref[len(groupIconUploadPrefix):])
	}
	return groupIconSourceDashboard, normalizeDashboardIconSlug(ref)
}

func effectiveGroupIconReference(groupName string, storedRef string) string {
	storedRef = normalizeGroupIconReference(storedRef)
	if storedRef != "" {
		return storedRef
	}
	return normalizeDashboardIconSlug(groupName)
}

func localIconURL(appBase string, ref string) string {
	ref = normalizeGroupIconReference(ref)
	if ref == "" {
		return ""
	}
	base := strings.TrimSpace(appBase)
	if base == "" {
		base = "/"
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + "icons/render?ref=" + url.QueryEscape(ref)
}

func (s *Server) searchDashboardIcons(ctx context.Context, tenantSlug string, appStore *store.Store, appBase string, query string, limit int) ([]dashboardIconSearchResult, error) {
	remoteEntries, err := s.loadDashboardIconIndex(ctx)
	if err != nil {
		return nil, err
	}
	entries := s.mergeIconEntries(s.loadRecycledIconEntries(ctx, tenantSlug, appStore), remoteEntries)
	if limit <= 0 {
		limit = dashboardIconSearchLimit
	}
	normalizedQuery := strings.ToLower(strings.TrimSpace(query))
	type scoredIcon struct {
		entry     dashboardIconEntry
		score     int
		preferred bool
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
		scored = append(scored, scoredIcon{entry: entry, score: score, preferred: entry.Preferred})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score < scored[j].score
		}
		if scored[i].preferred != scored[j].preferred {
			return scored[i].preferred
		}
		if scored[i].entry.Source != scored[j].entry.Source {
			return scored[i].entry.Source < scored[j].entry.Source
		}
		return scored[i].entry.Slug < scored[j].entry.Slug
	})
	if len(scored) > limit {
		scored = scored[:limit]
	}
	results := make([]dashboardIconSearchResult, 0, len(scored))
	for _, item := range scored {
		results = append(results, dashboardIconSearchResult{
			Value:     item.entry.Value,
			Slug:      item.entry.Slug,
			Label:     item.entry.Label,
			URL:       localIconURL(appBase, item.entry.Value),
			Source:    item.entry.Source,
			Preferred: item.entry.Preferred,
		})
	}
	return results, nil
}

func (s *Server) loadDashboardIconIndex(ctx context.Context) ([]dashboardIconEntry, error) {
	s.iconIndexMu.RLock()
	if len(s.iconIndex) > 0 {
		cached := append([]dashboardIconEntry(nil), s.iconIndex...)
		s.iconIndexMu.RUnlock()
		return cached, nil
	}
	s.iconIndexMu.RUnlock()

	s.iconIndexMu.Lock()
	defer s.iconIndexMu.Unlock()
	if len(s.iconIndex) > 0 {
		return append([]dashboardIconEntry(nil), s.iconIndex...), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dashboardIconsMetadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build dashboard icons metadata request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch dashboard icons metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dashboard icons metadata returned %s", resp.Status)
	}
	metadata := make(map[string]dashboardIconMetadata)
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
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
			Value:      normalizedSlug,
			Source:     groupIconSourceDashboard,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Slug < entries[j].Slug
	})
	s.iconIndex = entries
	return append([]dashboardIconEntry(nil), entries...), nil
}

func (s *Server) mergeIconEntries(priority []dashboardIconEntry, fallback []dashboardIconEntry) []dashboardIconEntry {
	merged := make([]dashboardIconEntry, 0, len(priority)+len(fallback))
	seen := make(map[string]struct{}, len(priority)+len(fallback))
	for _, entry := range append(append([]dashboardIconEntry(nil), priority...), fallback...) {
		value := normalizeGroupIconReference(entry.Value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		entry.Value = value
		entry.Slug = strings.TrimSpace(entry.Slug)
		if entry.Slug == "" {
			_, entry.Slug = splitGroupIconReference(value)
		}
		seen[value] = struct{}{}
		merged = append(merged, entry)
	}
	return merged
}

func (s *Server) loadRecycledIconEntries(ctx context.Context, tenantSlug string, appStore *store.Store) []dashboardIconEntry {
	metadata, err := appStore.ListMonitorGroupMetadata(ctx)
	if err != nil {
		return s.loadUploadedIconEntries(tenantSlug, nil)
	}

	usedRefs := make(map[string][]string, len(metadata))
	entries := make([]dashboardIconEntry, 0, len(metadata))
	for _, item := range metadata {
		ref := normalizeGroupIconReference(item.IconSlug)
		if ref == "" {
			continue
		}
		usedRefs[ref] = append(usedRefs[ref], strings.TrimSpace(item.Name))
	}
	for ref, groupNames := range usedRefs {
		kind, value := splitGroupIconReference(ref)
		label := formatDashboardIconLabel(value)
		searchParts := []string{strings.ToLower(label), strings.ToLower(value)}
		if kind == groupIconSourceUpload {
			label = formatUploadedIconLabel(value)
			searchParts = append(searchParts, strings.ToLower(strings.TrimSuffix(value, filepath.Ext(value))), "upload", "custom")
		}
		for _, groupName := range groupNames {
			if trimmed := strings.ToLower(strings.TrimSpace(groupName)); trimmed != "" {
				searchParts = append(searchParts, trimmed)
			}
		}
		entries = append(entries, dashboardIconEntry{
			Slug:       value,
			Label:      label,
			SearchText: strings.Join(searchParts, " "),
			Value:      ref,
			Source:     kind,
			Preferred:  true,
		})
	}
	return s.mergeIconEntries(entries, s.loadUploadedIconEntries(tenantSlug, usedRefs))
}

func (s *Server) loadUploadedIconEntries(tenantSlug string, usedRefs map[string][]string) []dashboardIconEntry {
	dir := s.uploadedIconsDir(tenantSlug)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	results := make([]dashboardIconEntry, 0, len(entries))
	for _, item := range entries {
		if item.IsDir() {
			continue
		}
		name := sanitizeUploadedIconName(item.Name())
		if name == "" {
			continue
		}
		ref := groupIconUploadPrefix + name
		label := formatUploadedIconLabel(name)
		searchParts := []string{strings.ToLower(label), strings.ToLower(strings.TrimSuffix(name, filepath.Ext(name))), "upload", "custom"}
		preferred := false
		if usedRefs != nil {
			if groups := usedRefs[ref]; len(groups) > 0 {
				preferred = true
				for _, groupName := range groups {
					if trimmed := strings.ToLower(strings.TrimSpace(groupName)); trimmed != "" {
						searchParts = append(searchParts, trimmed)
					}
				}
			}
		}
		results = append(results, dashboardIconEntry{
			Slug:       strings.TrimSuffix(name, filepath.Ext(name)),
			Label:      label,
			SearchText: strings.Join(searchParts, " "),
			Value:      ref,
			Source:     groupIconSourceUpload,
			Preferred:  preferred,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Preferred != results[j].Preferred {
			return results[i].Preferred
		}
		return results[i].Label < results[j].Label
	})
	return results
}

func (s *Server) loadDashboardIconAsset(ctx context.Context, tenantSlug string, slug string) ([]byte, string, error) {
	slug = normalizeDashboardIconSlug(slug)
	if slug == "" {
		return nil, "", os.ErrNotExist
	}

	if payload, contentType, err := s.loadPersistedDashboardIcon(tenantSlug, slug); err == nil {
		return payload, contentType, nil
	}

	s.iconAssetMu.RLock()
	if asset, ok := s.iconAssets[slug]; ok && len(asset.Payload) > 0 {
		payload := append([]byte(nil), asset.Payload...)
		contentType := asset.ContentType
		s.iconAssetMu.RUnlock()
		return payload, contentType, nil
	}
	s.iconAssetMu.RUnlock()

	s.iconAssetMu.Lock()
	defer s.iconAssetMu.Unlock()
	if asset, ok := s.iconAssets[slug]; ok && len(asset.Payload) > 0 {
		return append([]byte(nil), asset.Payload...), asset.ContentType, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dashboardIconsBaseURL+"/svg/"+url.PathEscape(slug)+".svg", nil)
	if err != nil {
		return nil, "", fmt.Errorf("build dashboard icon request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch dashboard icon: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("dashboard icon returned %s", resp.Status)
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, groupIconUploadMaxBytes))
	if err != nil {
		return nil, "", fmt.Errorf("read dashboard icon: %w", err)
	}
	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = mime.TypeByExtension(".svg")
	}
	asset := dashboardIconAsset{Payload: payload, ContentType: contentType}
	s.iconAssets[slug] = asset
	return append([]byte(nil), payload...), contentType, nil
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
		latencyChecks  int
		latencySumMS   int
		hasLatencyMin  bool
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
		currentLatencyChecks := item.UpChecks + item.DegradedChecks
		entry.latencyChecks += currentLatencyChecks
		entry.latencySumMS += item.LatencySumMS
		if currentLatencyChecks > 0 && (!entry.hasLatencyMin || item.LatencyMinMS < entry.latencyMinMS) {
			entry.hasLatencyMin = true
			entry.latencyMinMS = item.LatencyMinMS
		}
		if currentLatencyChecks > 0 && item.LatencyMaxMS > entry.latencyMaxMS {
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
			point.LatencyChecks = agg.latencyChecks
			if agg.latencyChecks > 0 {
				point.AvgMS = agg.latencySumMS / agg.latencyChecks
			}
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
		return monitor.NormalizeHTTPSTLSSecurityMode(requested)
	case monitor.KindTCP:
		return monitor.NormalizeTCPTLSSecurityMode(requested)
	case monitor.KindICMP:
		if requested == monitor.TLSModeNone || requested == monitor.TLSModeTLS || requested == monitor.TLSModeSTARTTLS {
			return requested
		}
		return monitor.TLSModeNone
	case monitor.KindSMTP:
		if monitor.IsValidMailTLSMode(requested) {
			return requested
		}
		return monitor.TLSModeSTARTTLS
	case monitor.KindIMAP:
		if monitor.IsValidMailTLSMode(requested) {
			return requested
		}
		return monitor.TLSModeTLS
	case monitor.KindUDP:
		if monitor.IsValidUDPMode(requested) {
			return requested
		}
		return monitor.TLSModeNone
	case monitor.KindDNS, monitor.KindWhois:
		return monitor.TLSModeNone
	default:
		return requested
	}
}

func parseMonitorExecutorSelection(raw string) (executorKind string, executorRef string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "local") {
		return "local", ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "remote:") {
		ref := strings.TrimSpace(raw[len("remote:"):])
		if ref == "" {
			return "local", ""
		}
		return "remote", ref
	}
	return "local", ""
}

func monitorTargetLabel(item monitor.Monitor) string {
	if item.Kind == monitor.KindDNS {
		parsed := monitor.ParseDNSTarget(item.Target)
		parts := make([]string, 0, 3)
		if parsed.Host != "" {
			parts = append(parts, parsed.Host)
		}
		switch monitor.NormalizeDNSRecordType(string(parsed.RecordType)) {
		case monitor.DNSRecordTypeA:
			parts = append(parts, "A")
		case monitor.DNSRecordTypeAAAA:
			parts = append(parts, "AAAA")
		case monitor.DNSRecordTypeCNAME:
			parts = append(parts, "CNAME")
		case monitor.DNSRecordTypeMX:
			parts = append(parts, "MX")
		case monitor.DNSRecordTypeTXT:
			parts = append(parts, "TXT")
		case monitor.DNSRecordTypeNS:
			parts = append(parts, "NS")
		case monitor.DNSRecordTypeSRV:
			parts = append(parts, "SRV")
		case monitor.DNSRecordTypeCAA:
			parts = append(parts, "CAA")
		case monitor.DNSRecordTypeSOA:
			parts = append(parts, "SOA")
		default:
			parts = append(parts, "A+AAAA")
		}
		if parsed.Server != "" {
			parts = append(parts, "via "+parsed.Server)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " · ")
		}
		return item.Target
	}
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
	return net.JoinHostPort(host, port)
}

func monitorTLSModeLabel(item monitor.Monitor) string {
	switch item.Kind {
	case monitor.KindHTTPS:
		return ""
	case monitor.KindSMTP, monitor.KindIMAP:
		securityMode, verifyCertificate, family := monitor.ParseMailTLSMode(item.TLSMode)
		parts := make([]string, 0, 2)
		switch securityMode {
		case monitor.TLSModeNone:
			parts = append(parts, "Plaintext")
		case monitor.TLSModeSTARTTLS:
			if verifyCertificate {
				parts = append(parts, "STARTTLS")
			} else {
				parts = append(parts, "STARTTLS (selfsigned)")
			}
		default:
			if verifyCertificate {
				parts = append(parts, "TLS")
			} else {
				parts = append(parts, "TLS (selfsigned)")
			}
		}
		host := ""
		if parsedHost, _, err := net.SplitHostPort(strings.TrimSpace(item.Target)); err == nil {
			host = strings.TrimSpace(strings.Trim(parsedHost, "[]"))
		}
		if host != "" && !isLiteralIPAddress(host) {
			switch family {
			case monitor.TCPAddressFamilyIPv4:
				parts = append(parts, "IPv4")
			case monitor.TCPAddressFamilyIPv6:
				parts = append(parts, "IPv6")
			default:
				parts = append(parts, "Dual Stack")
			}
		}
		return strings.Join(parts, " · ")
	case monitor.KindTCP:
		securityMode, _, family := monitor.ParseTCPTLSMode(item.TLSMode)
		parts := make([]string, 0, 2)
		switch securityMode {
		case monitor.TLSModeTLS:
			parts = append(parts, "TLS")
		case monitor.TLSModeSTARTTLS:
			parts = append(parts, "TLS (selfsigned)")
		}
		switch family {
		case monitor.TCPAddressFamilyIPv4:
			parts = append(parts, "IPv4")
		case monitor.TCPAddressFamilyIPv6:
			parts = append(parts, "IPv6")
		}
		return strings.Join(parts, " · ")
	case monitor.KindICMP:
		switch item.TLSMode {
		case monitor.TLSModeTLS:
			return "IPv4"
		case monitor.TLSModeSTARTTLS:
			return "IPv6"
		case monitor.TLSModeNone:
			if !isLiteralIPAddress(item.Target) {
				return "Dual Stack"
			}
			return ""
		default:
			return ""
		}
	case monitor.KindUDP:
		probeKind, family := monitor.ParseUDPMode(item.TLSMode)
		kindLabel := "WireGuard"
		switch probeKind {
		case monitor.UDPProbeKindDNS:
			kindLabel = "DNS"
		case monitor.UDPProbeKindNTP:
			kindLabel = "NTP"
		}
		if monitor.IsExplicitUDPFamilyMode(item.TLSMode) {
			switch family {
			case monitor.TCPAddressFamilyIPv4:
				return kindLabel + " · IPv4"
			case monitor.TCPAddressFamilyIPv6:
				return kindLabel + " · IPv6"
			default:
				return kindLabel + " · Dual Stack"
			}
		}
		return kindLabel
	default:
		return ""
	}
}

func isTimeoutMessage(message string) bool {
	text := strings.ToLower(strings.TrimSpace(message))
	if text == "" {
		return false
	}
	return strings.Contains(text, "timeout") ||
		strings.Contains(text, "timed out") ||
		strings.Contains(text, "deadline exceeded") ||
		strings.Contains(text, "i/o timeout")
}

func normalizeHTTPMonitorTarget(raw string, mode monitor.TLSMode) string {
	target := strings.TrimSpace(raw)
	if target == "" {
		return target
	}
	if strings.Contains(target, "://") {
		return target
	}
	target = strings.TrimPrefix(target, "//")
	if mode == monitor.TLSModeNone {
		return "http://" + target
	}
	return "https://" + target
}

func isLiteralIPAddress(raw string) bool {
	target := strings.TrimSpace(raw)
	target = strings.Trim(target, "[]")
	if target == "" {
		return false
	}
	return net.ParseIP(target) != nil
}

func monitorHTTPKindLabel(target string, mode monitor.TLSMode) string {
	securityMode, _, family := monitor.ParseHTTPSTLSMode(mode)
	base := "HTTPS"
	switch securityMode {
	case monitor.TLSModeNone:
		base = "HTTP"
	case monitor.TLSModeSTARTTLS:
		base = "HTTPS (selfsigned)"
	}

	parsed, err := url.Parse(strings.TrimSpace(target))
	hasLiteralIPHost := false
	if err == nil && parsed != nil {
		hostname := strings.TrimSpace(parsed.Hostname())
		hasLiteralIPHost = isLiteralIPAddress(hostname)
	}

	switch family {
	case monitor.TCPAddressFamilyIPv4:
		return base + " · IPv4"
	case monitor.TCPAddressFamilyIPv6:
		return base + " · IPv6"
	case monitor.TCPAddressFamilyDual:
		if !hasLiteralIPHost {
			return base + " · Dual Stack"
		}
		return base
	default:
		return base
	}
}

func buildHTTPMonitorTarget(host string, port string, path string, mode monitor.TLSMode) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return normalizeHTTPMonitorTarget(path, mode)
	}
	port = strings.TrimSpace(port)
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	path = strings.TrimSpace(path)
	if path != "" && !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "?") {
		path = "/" + path
	}

	scheme := "https://"
	if mode == monitor.TLSModeNone {
		scheme = "http://"
	}
	return scheme + host + path
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

	if session, err := s.sessionForRequest(r); err == nil && session != nil && session.TenantID == tenant.ID {
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
	preferredLanguage := defaultUILanguage
	if tenantUser, err := s.controlStore.GetTenantUser(r.Context(), tenant.ID, localUser.UserID); err == nil {
		preferredLanguage = normalizeUILanguage(tenantUser.PreferredLanguage)
	}
	translations := s.translationsForLanguage(preferredLanguage)

	greeting := translateFlashMessage(translations, "email.password_reset.greeting_generic", "Hello,", nil)
	if displayName := strings.TrimSpace(localUser.DisplayName); displayName != "" {
		greeting = translateFlashMessage(translations, "email.password_reset.greeting_named", "Hello {name},", map[string]string{"name": displayName})
	}
	bodyLines := []string{
		greeting,
		"",
		translateFlashMessage(translations, "email.password_reset.requested", "A password reset has been requested for your account.", nil),
		translateFlashMessage(translations, "email.password_reset.link_line", "Link: {reset_link}", map[string]string{"reset_link": resetLink}),
		"",
		translateFlashMessage(translations, "email.password_reset.valid_for", "This link is valid for 30 minutes.", nil),
		translateFlashMessage(translations, "email.password_reset.ignore", "If you did not request this, you can ignore this email.", nil),
	}
	body := strings.Join(bodyLines, "\n")
	subject := translateFlashMessage(translations, "email.password_reset.subject", "GoUp reset password", nil)

	if err := sendSMTPMail(deliveryCfg, localUser.Email, subject, body); err != nil {
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

		tokenTenantID, userID, tokenExpiresAt, err := s.parsePasswordResetToken(token)
		if err != nil || tokenTenantID != tenant.ID {
			http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Reset-Link ist ungültig oder abgelaufen"), http.StatusSeeOther)
			return
		}
		if s.passwordResetTokenUsed(token) {
			http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Reset-Link wurde bereits verwendet"), http.StatusSeeOther)
			return
		}

		if err := s.controlStore.ResetLocalUserPassword(r.Context(), tenant.ID, userID, newPassword); err != nil {
			s.logger.Error("reset local user password failed", "tenant_id", tenant.ID, "user_id", userID, "error", err)
			http.Redirect(w, r, "/"+tenantSlug+"/password-reset/confirm?token="+url.QueryEscape(token)+"&error="+url.QueryEscape("Passwort konnte nicht gesetzt werden"), http.StatusSeeOther)
			return
		}
		s.markPasswordResetTokenUsed(token, tokenExpiresAt)

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
	if s.passwordResetTokenUsed(token) {
		http.Redirect(w, r, "/"+tenantSlug+"/login?error="+url.QueryEscape("Reset-Link wurde bereits verwendet"), http.StatusSeeOther)
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
	preferredLanguage := normalizeUILanguage(resolvedUser.PreferredLanguage)
	if strings.TrimSpace(resolvedUser.PreferredLanguage) == "" {
		preferredLanguage = detectPreferredLanguage(r)
		if err := s.controlStore.UpdateUserPreferredLanguageForTenant(r.Context(), resolvedUser.TenantID, resolvedUser.UserID, preferredLanguage); err != nil {
			s.logger.Warn("persist preferred language failed", "tenant_id", tenant.ID, "user_id", resolvedUser.UserID, "error", err)
		}
	}

	session := auth.UserSession{
		UserID:            resolvedUser.UserID,
		Subject:           identity.Subject,
		Email:             resolvedUser.Email,
		Name:              resolvedUser.DisplayName,
		PreferredLanguage: preferredLanguage,
		TenantID:          resolvedUser.TenantID,
		TenantSlug:        resolvedUser.TenantSlug,
		TenantName:        resolvedUser.TenantName,
		Role:              resolvedUser.Role,
		AuthProvider:      provider.ProviderKey,
		ExpiresAt:         time.Now().Add(12 * time.Hour),
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
	preferredLanguage := normalizeUILanguage(resolvedUser.PreferredLanguage)
	if strings.TrimSpace(resolvedUser.PreferredLanguage) == "" {
		preferredLanguage = detectPreferredLanguage(r)
		if err := s.controlStore.UpdateUserPreferredLanguageForTenant(r.Context(), resolvedUser.TenantID, resolvedUser.UserID, preferredLanguage); err != nil {
			s.logger.Warn("persist preferred language failed", "tenant_id", tenant.ID, "user_id", resolvedUser.UserID, "error", err)
		}
	}

	session := auth.UserSession{
		UserID:            resolvedUser.UserID,
		Subject:           "local:" + strings.ToLower(loginName),
		Email:             resolvedUser.Email,
		Name:              resolvedUser.DisplayName,
		PreferredLanguage: preferredLanguage,
		TenantID:          resolvedUser.TenantID,
		TenantSlug:        resolvedUser.TenantSlug,
		TenantName:        resolvedUser.TenantName,
		Role:              resolvedUser.Role,
		AuthProvider:      "local",
		ExpiresAt:         time.Now().Add(12 * time.Hour),
	}
	if err := s.sessions.Set(w, session); err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/"+tenantSlug+"/", http.StatusSeeOther)
}
