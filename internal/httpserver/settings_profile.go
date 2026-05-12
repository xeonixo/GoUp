package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
