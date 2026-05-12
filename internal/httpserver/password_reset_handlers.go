package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
