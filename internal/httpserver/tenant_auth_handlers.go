package httpserver

import (
	"fmt"
	"goup/internal/auth"
	"goup/internal/config"
	store "goup/internal/store/sqlite"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
		SessionVersion:    resolvedUser.SessionVersion,
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

	loginName := strings.TrimSpace(r.FormValue("username"))
	if loginName == "" {
		loginName = strings.TrimSpace(r.FormValue("login_name"))
	}
	password := r.FormValue("password")
	key := s.localLoginKey(r, tenant.ID, loginName)
	if allowed, wait := s.localLoginAllowed(key, time.Now()); !allowed {
		s.writeAudit(r, "tenant_user.login.lockout", "tenant", tenant.ID, "local login locked")
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
		s.writeAudit(r, "tenant_user.login.failure", "tenant", tenant.ID, "invalid local credentials")
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
		SessionVersion:    resolvedUser.SessionVersion,
		ExpiresAt:         time.Now().Add(12 * time.Hour),
	}
	if err := s.sessions.Set(w, session); err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/"+tenantSlug+"/", http.StatusSeeOther)
}
