package httpserver

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	webhooknotify "goup/internal/notify/webhook"
	store "goup/internal/store/sqlite"
)

func (s *Server) handleSettingsUsers(w http.ResponseWriter, r *http.Request) {
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
		s.logger.Error("settings users load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}

	tenantUsers, err := s.controlStore.ListTenantUsers(r.Context(), user.TenantID)
	if err != nil {
		s.logger.Error("settings users list tenant users failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load users", http.StatusInternalServerError)
		return
	}

	s.render(w, "settings_users", pageData{
		Title:            "Einstellungen · Benutzer · GoUp",
		User:             user,
		AdminTenant:      tenant,
		AdminTenantUsers: tenantUsers,
		AppBase:          s.tenantAppBase(r),
		Notice:           strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:            strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleSettingsWebhooks(w http.ResponseWriter, r *http.Request) {
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
		s.logger.Error("settings webhooks load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		s.logger.Error("settings webhooks resolve tenant store failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load webhook settings", http.StatusInternalServerError)
		return
	}
	endpoints, err := appStore.ListWebhookEndpoints(r.Context())
	if err != nil {
		s.logger.Error("settings webhooks list failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load webhook settings", http.StatusInternalServerError)
		return
	}
	secretIDs, err := s.controlStore.ListTenantNotificationEndpointSecretIDs(r.Context(), user.TenantID, webhooknotify.NotificationKind)
	if err != nil {
		s.logger.Warn("settings webhooks list secrets failed", "tenant_id", user.TenantID, "error", err)
	}
	configured := make(map[int64]struct{}, len(secretIDs))
	for _, id := range secretIDs {
		configured[id] = struct{}{}
	}
	for i := range endpoints {
		_, endpoints[i].SecretConfigured = configured[endpoints[i].ID]
	}

	s.render(w, "settings_webhooks", pageData{
		Title:                 "Einstellungen · WebHooks · GoUp",
		User:                  user,
		AdminTenant:           tenant,
		AdminWebhookEndpoints: endpoints,
		AppBase:               s.tenantAppBase(r),
		Notice:                strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:                 strings.TrimSpace(r.URL.Query().Get("error")),
		SettingsMode:          true,
	})
}

func (s *Server) handleSettingsWebhooksSave(w http.ResponseWriter, r *http.Request) {
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
	appStore, err := s.appStore(r)
	if err != nil {
		s.logger.Error("settings webhooks resolve tenant store failed", "tenant_id", user.TenantID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("WebHooks konnten nicht geladen werden"), http.StatusSeeOther)
		return
	}

	endpointID, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	name := strings.TrimSpace(r.FormValue("name"))
	targetURL := strings.TrimSpace(r.FormValue("url"))
	secret := strings.TrimSpace(r.FormValue("secret"))
	timeoutSeconds, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("timeout_seconds")))
	enabled := r.FormValue("enabled") == "on"
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	if timeoutSeconds > 30 {
		timeoutSeconds = 30
	}
	if _, err := webhooknotify.ValidateTargetURL(targetURL); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if endpointID <= 0 && secret == "" {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("Signing-Secret ist erforderlich"), http.StatusSeeOther)
		return
	}

	id, err := appStore.UpsertWebhookEndpoint(r.Context(), store.WebhookEndpoint{
		ID:             endpointID,
		Name:           name,
		URL:            targetURL,
		Enabled:        enabled,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		s.logger.Error("settings webhooks save endpoint failed", "tenant_id", user.TenantID, "endpoint_id", endpointID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("WebHook konnte nicht gespeichert werden"), http.StatusSeeOther)
		return
	}
	if secret != "" {
		if err := s.controlStore.SaveTenantNotificationEndpointSecret(r.Context(), user.TenantID, id, webhooknotify.NotificationKind, secret); err != nil {
			s.logger.Error("settings webhooks save secret failed", "tenant_id", user.TenantID, "endpoint_id", id, "error", err)
			http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("WebHook-Secret konnte nicht gespeichert werden"), http.StatusSeeOther)
			return
		}
	}
	action := "tenant.webhook.create"
	if endpointID > 0 {
		action = "tenant.webhook.update"
	}
	s.writeAudit(r, action, "tenant", user.TenantID, fmt.Sprintf("endpoint_id=%d name=%s", id, name))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?notice="+url.QueryEscape("WebHook gespeichert"), http.StatusSeeOther)
}

func (s *Server) handleSettingsWebhookDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	endpointID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || endpointID <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("Ungültiger WebHook"), http.StatusSeeOther)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("WebHooks konnten nicht geladen werden"), http.StatusSeeOther)
		return
	}
	if err := appStore.DeleteWebhookEndpoint(r.Context(), endpointID); err != nil {
		if err != sql.ErrNoRows {
			s.logger.Warn("settings webhooks delete endpoint failed", "tenant_id", user.TenantID, "endpoint_id", endpointID, "error", err)
		}
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("WebHook konnte nicht gelöscht werden"), http.StatusSeeOther)
		return
	}
	if err := s.controlStore.DeleteTenantNotificationEndpointSecret(r.Context(), user.TenantID, endpointID, webhooknotify.NotificationKind); err != nil {
		s.logger.Warn("settings webhooks delete secret failed", "tenant_id", user.TenantID, "endpoint_id", endpointID, "error", err)
	}
	s.writeAudit(r, "tenant.webhook.delete", "tenant", user.TenantID, fmt.Sprintf("endpoint_id=%d", endpointID))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?notice="+url.QueryEscape("WebHook gelöscht"), http.StatusSeeOther)
}

func (s *Server) handleSettingsWebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	endpointID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || endpointID <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("Ungültiger WebHook"), http.StatusSeeOther)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("WebHooks konnten nicht geladen werden"), http.StatusSeeOther)
		return
	}
	tenantSlug := strings.TrimSpace(user.TenantSlug)
	if tenantSlug == "" {
		tenant, tenantErr := s.controlStore.GetTenantByID(r.Context(), user.TenantID)
		if tenantErr == nil {
			tenantSlug = strings.TrimSpace(tenant.Slug)
		}
	}
	notifier := webhooknotify.NewNotifier(appStore, s.controlStore, user.TenantID)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := notifier.SendTest(ctx, endpointID, tenantSlug); err != nil {
		s.logger.Warn("settings webhooks test failed", "tenant_id", user.TenantID, "endpoint_id", endpointID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?error="+url.QueryEscape("Testversand fehlgeschlagen: "+err.Error()), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "tenant.webhook.test", "tenant", user.TenantID, fmt.Sprintf("endpoint_id=%d", endpointID))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?notice="+url.QueryEscape("Testversand erfolgreich"), http.StatusSeeOther)
}

func (s *Server) handleSettingsRemoteNodes(w http.ResponseWriter, r *http.Request) {
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
		s.logger.Error("settings remote nodes load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}

	nodes, err := s.controlStore.ListRemoteNodesByTenant(r.Context(), user.TenantID)
	if err != nil {
		s.logger.Error("settings remote nodes list failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load remote nodes", http.StatusInternalServerError)
		return
	}
	var events []store.RemoteNodeEvent
	if len(nodes) > 0 {
		events, err = s.controlStore.ListRecentRemoteNodeEventsByTenant(r.Context(), user.TenantID, 200)
		if err != nil {
			s.logger.Warn("settings remote node events list failed", "tenant_id", user.TenantID, "error", err)
			events = nil
		}
	}

	s.render(w, "settings_remote_nodes", pageData{
		Title:        "Einstellungen · Remote Nodes · GoUp",
		User:         user,
		AdminTenant:  tenant,
		RemoteNodes:  buildRemoteNodeViews(nodes, time.Now().UTC(), s.cfg.BaseURL, groupRemoteNodeEventsByNode(events, 8)),
		AppBase:      s.tenantAppBase(r),
		Notice:       strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:        strings.TrimSpace(r.URL.Query().Get("error")),
		SettingsMode: true,
	})
}

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

func (s *Server) handleSettingsUserRoleSave(w http.ResponseWriter, r *http.Request) {
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

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil || userID <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Ungültige Benutzer-ID"), http.StatusSeeOther)
		return
	}

	role := strings.TrimSpace(r.FormValue("role"))
	if err := s.controlStore.UpdateTenantUserRole(r.Context(), user.TenantID, userID, role); err != nil {
		s.logger.Error("settings users update role failed", "tenant_id", user.TenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Rolle konnte nicht aktualisiert werden"), http.StatusSeeOther)
		return
	}
	if userID == user.UserID {
		user.Role = strings.ToLower(strings.TrimSpace(role))
		user.SessionVersion++
		_ = s.sessions.Set(w, *user)
	}

	s.writeAudit(r, "tenant_user.role_update", "tenant", user.TenantID, fmt.Sprintf("user_id=%d role=%s", userID, role))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Rolle aktualisiert"), http.StatusSeeOther)
}

func (s *Server) handleSettingsUserRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil || userID <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Ungültige Benutzer-ID"), http.StatusSeeOther)
		return
	}
	if userID == user.UserID {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Du kannst dich nicht selbst aus dem Tenant entfernen"), http.StatusSeeOther)
		return
	}

	if err := s.controlStore.RemoveUserFromTenant(r.Context(), user.TenantID, userID); err != nil {
		s.logger.Error("settings users remove failed", "tenant_id", user.TenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Benutzer konnte nicht entfernt werden"), http.StatusSeeOther)
		return
	}

	s.writeAudit(r, "tenant_user.remove", "tenant", user.TenantID, fmt.Sprintf("user_id=%d", userID))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Benutzer entfernt"), http.StatusSeeOther)
}

func (s *Server) handleSettingsLocalUserForm(w http.ResponseWriter, r *http.Request) {
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
		http.NotFound(w, r)
		return
	}

	data := pageData{
		Title:        "Lokales Konto · GoUp",
		User:         user,
		AdminTenant:  tenant,
		FormAction:   s.tenantAppBase(r) + "settings/local-users/save",
		BackURL:      s.tenantAppBase(r) + "settings/users",
		SettingsMode: true,
		AppBase:      s.tenantAppBase(r),
		Notice:       strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:        strings.TrimSpace(r.URL.Query().Get("error")),
	}

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	if userIDRaw != "" {
		userID, err := strconv.ParseInt(userIDRaw, 10, 64)
		if err != nil {
			http.Error(w, "invalid user id", http.StatusBadRequest)
			return
		}
		localUser, err := s.controlStore.GetLocalUserByID(r.Context(), user.TenantID, userID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data.AdminLocalUser = localUser
		data.IsEdit = true
	}

	s.render(w, "admin_local_user_form", data)
}

func (s *Server) handleSettingsLocalUserSave(w http.ResponseWriter, r *http.Request) {
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

	userIDRaw := strings.TrimSpace(r.FormValue("user_id"))
	loginName := strings.TrimSpace(r.FormValue("login_name"))
	password := r.FormValue("password")
	email := strings.TrimSpace(r.FormValue("email"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	role := strings.TrimSpace(r.FormValue("role"))
	if role == "" {
		role = "viewer"
	}

	if _, err := s.controlStore.UpsertAuthProvider(r.Context(), user.TenantID, "local-primary", "local", "Local Login", "", ""); err != nil {
		s.logger.Error("settings ensure local auth provider failed", "tenant_id", user.TenantID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Lokaler Provider konnte nicht angelegt werden"), http.StatusSeeOther)
		return
	}

	if userIDRaw == "" {
		if strings.TrimSpace(password) == "" {
			http.Redirect(w, r, s.tenantAppBase(r)+"settings/local-users/new?error="+url.QueryEscape("Passwort ist erforderlich"), http.StatusSeeOther)
			return
		}
		_, err := s.controlStore.CreateLocalUserForTenant(r.Context(), user.TenantID, loginName, password, email, displayName, role)
		if err != nil {
			s.logger.Error("settings create local user failed", "tenant_id", user.TenantID, "error", err)
			http.Redirect(w, r, s.tenantAppBase(r)+"settings/local-users/new?error="+url.QueryEscape("Lokaler Benutzer konnte nicht erstellt werden"), http.StatusSeeOther)
			return
		}
		s.writeAudit(r, "local_user.create", "tenant", user.TenantID, fmt.Sprintf("login=%s email=%s source=settings", loginName, email))
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Lokaler Benutzer erstellt"), http.StatusSeeOther)
		return
	}

	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	_, err = s.controlStore.UpdateLocalUserForTenant(r.Context(), user.TenantID, userID, loginName, password, email, displayName, role)
	if err != nil {
		s.logger.Error("settings update local user failed", "tenant_id", user.TenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/local-users/"+strconv.FormatInt(userID, 10)+"/edit?error="+url.QueryEscape("Lokaler Benutzer konnte nicht gespeichert werden"), http.StatusSeeOther)
		return
	}

	if userID == user.UserID {
		if session, err := s.sessionForRequest(r); err == nil {
			session.Role = role
			_ = s.sessions.Set(w, *session)
		}
	}

	s.writeAudit(r, "local_user.update", "tenant", user.TenantID, fmt.Sprintf("user_id=%d login=%s source=settings", userID, loginName))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Lokaler Benutzer gespeichert"), http.StatusSeeOther)
}

func (s *Server) handleSettingsLocalUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil || userID <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Ungültige Benutzer-ID"), http.StatusSeeOther)
		return
	}
	if userID == user.UserID {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Du kannst dich nicht selbst löschen"), http.StatusSeeOther)
		return
	}

	if err := s.controlStore.DeleteLocalUserFromTenant(r.Context(), user.TenantID, userID); err != nil {
		s.logger.Error("settings delete local user failed", "tenant_id", user.TenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Lokaler Benutzer konnte nicht entfernt werden"), http.StatusSeeOther)
		return
	}

	s.writeAudit(r, "local_user.delete", "tenant", user.TenantID, fmt.Sprintf("user_id=%d source=settings", userID))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Lokaler Benutzer entfernt"), http.StatusSeeOther)
}

func (s *Server) handleSettingsProviders(w http.ResponseWriter, r *http.Request) {
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
		s.logger.Error("settings providers load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}

	providers, err := s.controlStore.GetAllAuthProvidersByTenant(r.Context(), user.TenantID)
	if err != nil {
		s.logger.Error("settings providers list failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load providers", http.StatusInternalServerError)
		return
	}

	s.render(w, "settings_providers", pageData{
		Title:          "Einstellungen · Provider · GoUp",
		User:           user,
		AdminTenant:    tenant,
		AdminProviders: providers,
		AppBase:        s.tenantAppBase(r),
		Notice:         strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:          strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleSettingsProviderForm(w http.ResponseWriter, r *http.Request) {
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
		http.NotFound(w, r)
		return
	}

	appBase := s.tenantAppBase(r)
	data := pageData{
		Title:        "Provider · GoUp",
		User:         user,
		AdminTenant:  tenant,
		FormAction:   appBase + "settings/providers/save",
		SettingsMode: true,
		AppBase:      appBase,
		Notice:       strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:        strings.TrimSpace(r.URL.Query().Get("error")),
	}

	providerKey := strings.TrimSpace(r.PathValue("providerKey"))
	if providerKey != "" {
		provider, err := s.controlStore.GetAuthProvider(r.Context(), user.TenantID, providerKey)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if provider.Kind == "local" {
			http.Redirect(w, r, appBase+"settings/providers?error="+url.QueryEscape("Lokale Provider können nicht bearbeitet werden"), http.StatusSeeOther)
			return
		}
		data.AdminProvider = provider
		data.IsEdit = true
	}

	s.render(w, "settings_provider_form", data)
}

func (s *Server) handleSettingsProviderSave(w http.ResponseWriter, r *http.Request) {
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

	appBase := s.tenantAppBase(r)
	providerKey := strings.TrimSpace(r.FormValue("provider_key"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	issuerURL := strings.TrimSpace(r.FormValue("issuer_url"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))

	if providerKey == "" || issuerURL == "" || clientID == "" {
		http.Redirect(w, r, appBase+"settings/providers/new?error="+url.QueryEscape("Provider Key, Issuer URL und Client ID sind erforderlich"), http.StatusSeeOther)
		return
	}
	if displayName == "" {
		displayName = providerKey
	}

	_, err := s.controlStore.UpsertAuthProvider(r.Context(), user.TenantID, providerKey, "oidc", displayName, issuerURL, clientID)
	if err != nil {
		s.logger.Error("settings upsert auth provider failed", "tenant_id", user.TenantID, "error", err)
		http.Redirect(w, r, appBase+"settings/providers/new?error="+url.QueryEscape("Provider konnte nicht gespeichert werden"), http.StatusSeeOther)
		return
	}

	if clientSecret != "" {
		if err := s.controlStore.UpdateAuthProviderSecret(r.Context(), user.TenantID, providerKey, clientSecret); err != nil {
			s.logger.Error("settings update auth provider secret failed", "tenant_id", user.TenantID, "provider_key", providerKey, "error", err)
			http.Redirect(w, r, appBase+"settings/providers/"+providerKey+"/edit?error="+url.QueryEscape("Provider gespeichert, Secret konnte nicht gespeichert werden"), http.StatusSeeOther)
			return
		}
	}

	s.writeAudit(r, "auth_provider.upsert", "tenant", user.TenantID, fmt.Sprintf("provider=%s kind=oidc source=settings", providerKey))
	http.Redirect(w, r, appBase+"settings/providers?notice="+url.QueryEscape("Provider gespeichert"), http.StatusSeeOther)
}

func (s *Server) handleSettingsProviderDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	appBase := s.tenantAppBase(r)
	providerKey := strings.TrimSpace(r.PathValue("providerKey"))
	if providerKey == "" {
		http.Redirect(w, r, appBase+"settings/providers?error="+url.QueryEscape("Ungültiger Provider Key"), http.StatusSeeOther)
		return
	}

	if err := s.controlStore.DeleteAuthProvider(r.Context(), user.TenantID, providerKey); err != nil {
		s.logger.Error("settings delete auth provider failed", "tenant_id", user.TenantID, "provider_key", providerKey, "error", err)
		http.Redirect(w, r, appBase+"settings/providers?error="+url.QueryEscape("Provider konnte nicht gelöscht werden"), http.StatusSeeOther)
		return
	}

	s.writeAudit(r, "auth_provider.delete", "tenant", user.TenantID, fmt.Sprintf("provider=%s source=settings", providerKey))
	http.Redirect(w, r, appBase+"settings/providers?notice="+url.QueryEscape("Provider gelöscht"), http.StatusSeeOther)
}
