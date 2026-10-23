package httpserver

import (
	"goup/internal/auth"
	"goup/internal/config"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) handleGlobalAuthDisabled(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "tenant slug required (use /{tenant}/auth/login)", http.StatusNotFound)
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

	resolvedUser, err := s.controlStore.UpsertOIDCUserIdentity(r.Context(), "oidc-primary", identity.Subject, identity.Email, identity.Name, s.defaultTenant.ID, "viewer")
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
		SessionVersion:    resolvedUser.SessionVersion,
		ExpiresAt:         time.Now().Add(auth.DefaultSessionLifetime),
	}
	if err := s.sessions.SetSecure(w, session, s.requestIsHTTPS(r)); err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/"+resolvedUser.TenantSlug+"/", http.StatusSeeOther)
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
