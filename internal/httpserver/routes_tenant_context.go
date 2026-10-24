package httpserver

import (
	"context"
	"net/http"
	"strings"
)

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
	if slug == "admin" || slug == "static" || slug == "healthz" || slug == "auth" || slug == "node" || slug == "assets" || slug == "favicon" || slug == "sw.js" || slug == "offline" {
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
