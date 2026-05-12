package httpserver

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"goup/internal/auth"
	"goup/internal/config"
	store "goup/internal/store/sqlite"
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
		SessionVersion:    resolvedUser.SessionVersion,
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
	s.writeAudit(r, "tenant_user.password_reset.request", "tenant", tenant.ID, "password reset requested")

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
		s.writeAudit(r, "tenant_user.password_reset.complete", "tenant", tenant.ID, fmt.Sprintf("user_id=%d", userID))

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
