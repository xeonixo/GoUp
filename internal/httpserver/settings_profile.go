package httpserver

import (
	"context"
	"fmt"
	matrixnotify "goup/internal/notify/matrix"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) handleSettingsProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tenant, err := s.controlStore.GetTenantByID(r.Context(), user.TenantID)
	if err != nil {
		s.logger.Error("settings profile load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}

	profileUser, err := s.controlStore.GetTenantUser(r.Context(), user.TenantID, user.UserID)
	if err != nil {
		s.logger.Error("settings profile load user failed", "tenant_id", user.TenantID, "user_id", user.UserID, "error", err)
		http.Error(w, "unable to load profile", http.StatusInternalServerError)
		return
	}

	notify, err := s.controlStore.GetUserNotificationSettings(r.Context(), user.TenantID, user.UserID)
	if err != nil {
		s.logger.Error("settings profile load notifications failed", "tenant_id", user.TenantID, "user_id", user.UserID, "error", err)
		http.Error(w, "unable to load notification settings", http.StatusInternalServerError)
		return
	}

	s.render(w, "settings_profile", pageData{
		Title:           "Einstellungen · Profil · GoUp",
		UILanguage:      normalizeUILanguage(profileUser.PreferredLanguage),
		User:            user,
		AdminTenant:     tenant,
		ProfileUser:     profileUser,
		ProfileNotify:   notify,
		LanguageOptions: languageOptions(profileUser.PreferredLanguage),
		AppBase:         s.tenantAppBase(r),
		Notice:          strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:           strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleSettingsProfileSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	preferredLanguage := normalizeUILanguage(r.FormValue("preferred_language"))
	emailEnabled := r.FormValue("email_enabled") == "on"
	matrixEnabled := r.FormValue("matrix_enabled") == "on"
	matrixHomeserver := strings.TrimSpace(r.FormValue("matrix_homeserver_url"))
	matrixRoomID := strings.TrimSpace(r.FormValue("matrix_room_id"))
	matrixAccessToken := strings.TrimSpace(r.FormValue("matrix_access_token"))

	if err := s.controlStore.UpdateUserProfileForTenant(r.Context(), user.TenantID, user.UserID, email, displayName, preferredLanguage); err != nil {
		s.logger.Error("settings profile update user failed", "tenant_id", user.TenantID, "user_id", user.UserID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?error="+url.QueryEscape("Profil konnte nicht gespeichert werden"), http.StatusSeeOther)
		return
	}

	if err := s.controlStore.SaveUserNotificationSettings(r.Context(), user.TenantID, user.UserID, emailEnabled, matrixEnabled, matrixHomeserver, matrixRoomID, matrixAccessToken); err != nil {
		s.logger.Error("settings profile save notifications failed", "tenant_id", user.TenantID, "user_id", user.UserID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?error="+url.QueryEscape("Benachrichtigungen konnten nicht gespeichert werden"), http.StatusSeeOther)
		return
	}

	if session, err := s.sessionForRequest(r); err == nil {
		session.Email = email
		session.Name = displayName
		session.PreferredLanguage = preferredLanguage
		_ = s.sessions.Set(w, *session)
	}

	http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?notice="+url.QueryEscape("Profil gespeichert"), http.StatusSeeOther)
}

func (s *Server) handleSettingsProfileNotifierDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	kind := strings.ToLower(strings.TrimSpace(r.FormValue("kind")))
	if kind != "matrix" {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?error="+url.QueryEscape("Unbekannter Benachrichtigungskanal"), http.StatusSeeOther)
		return
	}

	if err := s.controlStore.DeleteUserNotificationChannel(r.Context(), user.TenantID, user.UserID, kind); err != nil {
		s.logger.Warn("settings profile delete notifier failed", "tenant_id", user.TenantID, "user_id", user.UserID, "kind", kind, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?error="+url.QueryEscape("Benachrichtigungskanal konnte nicht gelöscht werden"), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?notice="+url.QueryEscape("Benachrichtigungskanal entfernt"), http.StatusSeeOther)
}

func (s *Server) handleSettingsProfileNotifierTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	kind := strings.ToLower(strings.TrimSpace(r.PathValue("kind")))
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var err error
	switch kind {
	case "email":
		err = s.sendProfileEmailTest(ctx, r, user.TenantID, user.UserID)
	case "matrix":
		err = s.sendProfileMatrixTest(ctx, r, user.TenantID, user.UserID)
	default:
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?error="+url.QueryEscape("Unbekannter Benachrichtigungskanal"), http.StatusSeeOther)
		return
	}
	if err != nil {
		s.logger.Warn("settings profile notification test failed", "tenant_id", user.TenantID, "user_id", user.UserID, "kind", kind, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?error="+url.QueryEscape("Testversand fehlgeschlagen: "+err.Error()), http.StatusSeeOther)
		return
	}

	s.writeAudit(r, "tenant.notification.test", "tenant", user.TenantID, fmt.Sprintf("user_id=%d kind=%s", user.UserID, kind))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?notice="+url.QueryEscape("Testversand erfolgreich"), http.StatusSeeOther)
}

func (s *Server) sendProfileEmailTest(ctx context.Context, r *http.Request, tenantID, userID int64) error {
	recipient := strings.TrimSpace(r.FormValue("email"))
	if recipient == "" {
		profileUser, err := s.controlStore.GetTenantUser(ctx, tenantID, userID)
		if err != nil {
			return fmt.Errorf("Profil konnte nicht geladen werden")
		}
		recipient = strings.TrimSpace(profileUser.Email)
	}
	if recipient == "" {
		return fmt.Errorf("E-Mail-Adresse fehlt")
	}
	cfg, err := s.controlStore.GetGlobalSMTPDeliveryConfig(ctx)
	if err != nil {
		return fmt.Errorf("SMTP-Konfiguration konnte nicht geladen werden: %w", err)
	}
	if strings.TrimSpace(cfg.Settings.Host) == "" || strings.TrimSpace(cfg.Settings.FromEmail) == "" {
		return fmt.Errorf("SMTP Host/Absender ist nicht konfiguriert")
	}
	if strings.TrimSpace(cfg.Password) == "" {
		return fmt.Errorf("SMTP Passwort ist nicht konfiguriert")
	}
	body := "Dies ist eine Testbenachrichtigung von GoUp.\n\nWenn du diese Nachricht erhalten hast, funktioniert der E-Mail-Kanal."
	return sendSMTPMail(cfg, recipient, "GoUp Testbenachrichtigung", body)
}

func (s *Server) sendProfileMatrixTest(ctx context.Context, r *http.Request, tenantID, userID int64) error {
	homeserverURL := strings.TrimSpace(strings.TrimRight(r.FormValue("matrix_homeserver_url"), "/"))
	roomID := strings.TrimSpace(r.FormValue("matrix_room_id"))
	accessToken := strings.TrimSpace(r.FormValue("matrix_access_token"))
	if accessToken == "" {
		settings, err := s.controlStore.GetUserNotificationSettings(ctx, tenantID, userID)
		if err != nil {
			return fmt.Errorf("Matrix-Konfiguration konnte nicht geladen werden")
		}
		if homeserverURL == "" {
			homeserverURL = strings.TrimSpace(settings.MatrixHomeserver)
		}
		if roomID == "" {
			roomID = strings.TrimSpace(settings.MatrixRoomID)
		}
		accessToken = strings.TrimSpace(settings.MatrixAccessToken)
	}
	if homeserverURL == "" || roomID == "" || accessToken == "" {
		return fmt.Errorf("Matrix Homeserver, Room ID und Access Token sind erforderlich")
	}
	client := matrixnotify.New(homeserverURL, accessToken, roomID)
	return client.SendMessage(ctx, "GoUp Testbenachrichtigung\n\nWenn du diese Nachricht erhalten hast, funktioniert der Matrix-Kanal.")
}

func (s *Server) handleSettingsProfilePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")
	if strings.TrimSpace(newPassword) == "" || strings.TrimSpace(currentPassword) == "" {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?error="+url.QueryEscape("Bitte aktuelles und neues Passwort angeben"), http.StatusSeeOther)
		return
	}
	if newPassword != confirmPassword {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?error="+url.QueryEscape("Passwort-Bestätigung stimmt nicht überein"), http.StatusSeeOther)
		return
	}

	if err := s.controlStore.ChangeOwnLocalPassword(r.Context(), user.TenantID, user.UserID, currentPassword, newPassword); err != nil {
		s.logger.Warn("settings profile password change failed", "tenant_id", user.TenantID, "user_id", user.UserID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/profile?error="+url.QueryEscape("Passwort konnte nicht geändert werden"), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "tenant_user.password.update", "tenant", user.TenantID, fmt.Sprintf("user_id=%d", user.UserID))
	s.sessions.ClearForTenant(w, user.TenantSlug)

	http.Redirect(w, r, s.tenantAppBase(r)+"login?notice="+url.QueryEscape("Passwort geändert. Bitte erneut anmelden."), http.StatusSeeOther)
}
