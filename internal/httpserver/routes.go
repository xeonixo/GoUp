package httpserver

import (
	"context"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"

	webassets "goup/assets"
	store "goup/internal/store/sqlite"
	"goup/web"
)

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
	mux.Handle("/admin/tenants/{id}/remote-nodes/live", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminRemoteNodesLive)))
	mux.Handle("/admin/tenants/{id}/remote-nodes/live/snapshot", s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminRemoteNodesLiveSnapshot)))
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
	mux.Handle("/monitors/export", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleMonitorExport))))
	mux.Handle("/monitors/import", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleMonitorImport))))
	mux.Handle("/monitors/import/preview", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleMonitorImportPreview))))
	mux.Handle("/monitors/import/confirm", s.requireAuth(s.requireAdminWhenAuth(http.HandlerFunc(s.handleMonitorImportConfirm))))
	mux.Handle("/state-events", s.requireAuth(http.HandlerFunc(s.handleStateEventsHistory)))
	mux.Handle("/notification-events", s.requireAuth(http.HandlerFunc(s.handleNotificationEventsHistory)))
	mux.Handle("/settings/profile", s.requireAuth(http.HandlerFunc(s.handleSettingsProfile)))
	mux.Handle("/settings/profile/save", s.requireAuth(http.HandlerFunc(s.handleSettingsProfileSave)))
	mux.Handle("/settings/profile/notifiers/delete", s.requireAuth(http.HandlerFunc(s.handleSettingsProfileNotifierDelete)))
	mux.Handle("/settings/profile/password", s.requireAuth(http.HandlerFunc(s.handleSettingsProfilePassword)))
	mux.Handle("/settings/users", s.requireUserManagement(http.HandlerFunc(s.handleSettingsUsers)))
	mux.Handle("/settings/webhooks", s.requireUserManagement(http.HandlerFunc(s.handleSettingsWebhooks)))
	mux.Handle("/settings/webhooks/save", s.requireUserManagement(http.HandlerFunc(s.handleSettingsWebhooksSave)))
	mux.Handle("/settings/webhooks/{id}/test", s.requireUserManagement(http.HandlerFunc(s.handleSettingsWebhookTest)))
	mux.Handle("/settings/webhooks/{id}/delete", s.requireUserManagement(http.HandlerFunc(s.handleSettingsWebhookDelete)))
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
