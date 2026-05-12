package httpserver

import (
	"context"
	"errors"
	"goup/internal/auth"
	store "goup/internal/store/sqlite"
	"net/http"
	"strings"
)

func (s *Server) requireAuth(next http.Handler) http.Handler {
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

func (s *Server) currentUser(r *http.Request) *auth.UserSession {
	session, err := s.sessionForRequest(r)
	if err != nil {
		return nil
	}
	return session
}

func (s *Server) sessionForRequest(r *http.Request) (*auth.UserSession, error) {
	var (
		session *auth.UserSession
		err     error
	)
	if slug := strings.TrimSpace(tenantSlugFromRequest(r)); slug != "" {
		session, err = s.sessions.GetForTenant(r, slug)
	} else {
		session, err = s.sessions.Get(r)
	}
	if err != nil {
		return nil, err
	}
	if err := s.validateTenantSession(r.Context(), session); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *Server) validateTenantSession(ctx context.Context, session *auth.UserSession) error {
	if session == nil {
		return http.ErrNoCookie
	}
	if s.controlStore == nil || session.TenantID <= 0 || session.UserID <= 0 {
		return nil
	}
	if session.SessionVersion <= 0 {
		return errors.New("session version missing")
	}
	version, err := s.controlStore.GetTenantMembershipSessionVersion(ctx, session.TenantID, session.UserID)
	if err != nil {
		return err
	}
	if version != session.SessionVersion {
		return errors.New("session version mismatch")
	}
	return nil
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
