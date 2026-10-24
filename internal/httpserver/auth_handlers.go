package httpserver

import (
	"net/http"
	"strings"
)

func (s *Server) handleGlobalAuthDisabled(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "tenant slug required (use /{tenant}/auth/login)", http.StatusNotFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Logout changes state (it invalidates all sessions of the member), so it
	// must not be triggerable via GET (e.g. <img src=".../auth/logout">).
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, _ := s.sessionForRequest(r)
	if session != nil && session.TenantID > 0 && session.UserID > 0 {
		if err := s.controlStore.BumpTenantMembershipSessionVersion(r.Context(), session.TenantID, session.UserID); err != nil {
			s.logger.Warn("logout: bump session version failed", "tenant_id", session.TenantID, "user_id", session.UserID, "error", err)
		}
	}
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
