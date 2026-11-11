package httpserver

import (
	"context"
	"net/http"
	"strings"

	store "goup/internal/store/sqlite"
)

type tenantSlugContextKey struct{}
type tenantIDContextKey struct{}
type statusCustomDomainContextKey struct{}

func requestWithTenantSlug(r *http.Request, slug string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), tenantSlugContextKey{}, strings.TrimSpace(slug)))
}

func requestWithTenantID(r *http.Request, tenantID int64) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), tenantIDContextKey{}, tenantID))
}

func requestWithStatusCustomDomain(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), statusCustomDomainContextKey{}, true))
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

func statusPageCustomDomainFromRequest(r *http.Request) bool {
	ok, _ := r.Context().Value(statusCustomDomainContextKey{}).(bool)
	return ok
}

// handleCustomDomainStatus serves the public status page when the request Host matches a
// tenant's configured custom_domain. The reverse proxy must forward that Host to GoUp.
// Paths: /, /status, and the usual /status/* assets/feeds/subscriptions (no slug required).
func (s *Server) handleCustomDomainStatus(w http.ResponseWriter, r *http.Request) bool {
	if s.controlStore == nil {
		return false
	}
	host := store.NormalizeStatusPageCustomDomain(r.Host)
	if host == "" {
		return false
	}
	tenant, ok := s.lookupTenantByStatusCustomDomain(r.Context(), host)
	if !ok {
		return false
	}

	trimmed := strings.Trim(strings.TrimSpace(r.URL.Path), "/")
	parts := []string{}
	if trimmed != "" {
		parts = strings.Split(trimmed, "/")
	}

	r = requestWithTenantSlug(r, tenant.Slug)
	r = requestWithTenantID(r, tenant.ID)
	r = requestWithStatusCustomDomain(r)

	switch {
	case len(parts) == 0:
		s.handleStatusPage(w, r)
		return true
	case len(parts) == 1 && parts[0] == "status":
		s.handleStatusPage(w, r)
		return true
	case len(parts) >= 1 && parts[0] == "status":
		return s.serveStatusPageSubpath(w, r, parts[1:])
	default:
		// Host matches a status custom domain; unknown paths stay 404 rather than
		// falling through to the tenant app (which requires auth / slug URLs).
		http.NotFound(w, r)
		return true
	}
}

func (s *Server) serveStatusPageSubpath(w http.ResponseWriter, r *http.Request, subParts []string) bool {
	switch {
	case len(subParts) == 1 && (strings.EqualFold(subParts[0], "feed.xml") || strings.EqualFold(subParts[0], "feed.atom")):
		s.handleStatusPageFeed(w, r)
		return true
	case len(subParts) == 1 && subParts[0] == "subscribe":
		s.handleStatusPageSubscribe(w, r)
		return true
	case len(subParts) == 2 && subParts[0] == "subscribe" && subParts[1] == "confirm":
		s.handleStatusPageSubscribeConfirm(w, r)
		return true
	case len(subParts) == 2 && subParts[0] == "subscribe" && subParts[1] == "unsubscribe":
		s.handleStatusPageUnsubscribe(w, r)
		return true
	case len(subParts) == 1 && subParts[0] == "logo":
		s.handleStatusPageLogo(w, r)
		return true
	case len(subParts) == 1 && subParts[0] == "brand.css":
		s.handleStatusPageBrandCSS(w, r)
		return true
	default:
		http.NotFound(w, r)
		return true
	}
}

func (s *Server) lookupTenantByStatusCustomDomain(ctx context.Context, host string) (store.Tenant, bool) {
	host = store.NormalizeStatusPageCustomDomain(host)
	if host == "" || s.controlStore == nil {
		return store.Tenant{}, false
	}
	tenants, err := s.controlStore.GetAllTenants(ctx)
	if err != nil {
		return store.Tenant{}, false
	}
	for _, tenant := range tenants {
		if !tenant.Active {
			continue
		}
		appStore, err := s.storeForTenantLookup(ctx, tenant)
		if err != nil || appStore == nil {
			continue
		}
		settings, err := appStore.GetStatusPageSettings(ctx)
		if err != nil {
			continue
		}
		// Match the configured hostname even when the page is disabled so the
		// Host stays reserved and handleStatusPage can return 404.
		if store.NormalizeStatusPageCustomDomain(settings.CustomDomain) == host {
			return tenant, true
		}
	}
	return store.Tenant{}, false
}

func (s *Server) storeForTenantLookup(ctx context.Context, tenant store.Tenant) (*store.Store, error) {
	if s.tenantStores != nil {
		return s.tenantStores.StoreForTenant(ctx, tenant.ID)
	}
	if s.store != nil {
		return s.store, nil
	}
	return nil, http.ErrNotSupported
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
	if slug == "admin" || slug == "static" || slug == "healthz" || slug == "readyz" || slug == "auth" || slug == "node" || slug == "hb" || slug == "assets" || slug == "favicon" || slug == "sw.js" || slug == "offline" || slug == "metrics-internal" {
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
	case len(parts) == 2 && parts[1] == "manifest.webmanifest":
		s.handleTenantManifest(w, r)
		return true
	case len(parts) == 2 && parts[1] == "status":
		s.handleStatusPage(w, r)
		return true
	case statusPageFeedPath(parts):
		s.handleStatusPageFeed(w, r)
		return true
	case len(parts) == 3 && parts[1] == "status" && parts[2] == "subscribe":
		s.handleStatusPageSubscribe(w, r)
		return true
	case len(parts) == 4 && parts[1] == "status" && parts[2] == "subscribe" && parts[3] == "confirm":
		s.handleStatusPageSubscribeConfirm(w, r)
		return true
	case len(parts) == 4 && parts[1] == "status" && parts[2] == "subscribe" && parts[3] == "unsubscribe":
		s.handleStatusPageUnsubscribe(w, r)
		return true
	case len(parts) == 3 && parts[1] == "status" && parts[2] == "logo":
		s.handleStatusPageLogo(w, r)
		return true
	case len(parts) == 3 && parts[1] == "status" && parts[2] == "brand.css":
		s.handleStatusPageBrandCSS(w, r)
		return true
	case len(parts) == 2 && parts[1] == "metrics":
		s.handleTenantMetrics(w, r)
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
