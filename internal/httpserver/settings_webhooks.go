package httpserver

import (
	"context"
	"database/sql"
	"fmt"
	webhooknotify "goup/internal/notify/webhook"
	store "goup/internal/store/sqlite"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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
