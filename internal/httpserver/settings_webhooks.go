package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"goup/internal/notify/route"
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
	s.renderSettingsWebhooks(w, r, "", strings.TrimSpace(r.URL.Query().Get("notice")), strings.TrimSpace(r.URL.Query().Get("error")))
}

func (s *Server) renderSettingsWebhooks(w http.ResponseWriter, r *http.Request, newSecret, notice, errText string) {
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
		NewWebhookSecret:      newSecret,
		AppBase:               s.tenantAppBase(r),
		Notice:                notice,
		Error:                 errText,
		SettingsMode:          true,
	})
}

func (s *Server) webhooksRedirect(w http.ResponseWriter, r *http.Request, kind, message string) {
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/webhooks?"+kind+"="+url.QueryEscape(message), http.StatusSeeOther)
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
		s.webhooksRedirect(w, r, "error", "WebHooks konnten nicht geladen werden")
		return
	}

	endpointID, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	name := strings.TrimSpace(r.FormValue("name"))
	targetURL := strings.TrimSpace(r.FormValue("url"))
	secret := strings.TrimSpace(r.FormValue("secret"))
	generateSecret := r.FormValue("generate_secret") == "1" || r.FormValue("generate_secret") == "on"
	timeoutSeconds, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("timeout_seconds")))
	enabled := r.FormValue("enabled") == "on"
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	if timeoutSeconds > 30 {
		timeoutSeconds = 30
	}
	if _, err := webhooknotify.ValidateTargetURL(targetURL); err != nil {
		s.webhooksRedirect(w, r, "error", err.Error())
		return
	}

	revealedSecret := ""
	if generateSecret {
		generated, genErr := webhooknotify.GenerateSigningSecret()
		if genErr != nil {
			s.logger.Error("settings webhooks generate secret failed", "tenant_id", user.TenantID, "error", genErr)
			s.webhooksRedirect(w, r, "error", "WebHook-Secret konnte nicht erzeugt werden")
			return
		}
		secret = generated
		revealedSecret = generated
	} else if secret != "" {
		if err := webhooknotify.ValidateSigningSecret(secret); err != nil {
			s.webhooksRedirect(w, r, "error", err.Error())
			return
		}
	} else if endpointID <= 0 {
		s.webhooksRedirect(w, r, "error", "Signing-Secret ist erforderlich")
		return
	}

	id, err := appStore.UpsertWebhookEndpoint(r.Context(), store.WebhookEndpoint{
		ID:             endpointID,
		Name:           name,
		URL:            targetURL,
		Enabled:        enabled,
		TimeoutSeconds: timeoutSeconds,
		Route:          parseWebhookRouteForm(r),
	})
	if err != nil {
		s.logger.Error("settings webhooks save endpoint failed", "tenant_id", user.TenantID, "endpoint_id", endpointID, "error", err)
		s.webhooksRedirect(w, r, "error", "WebHook konnte nicht gespeichert werden")
		return
	}
	if secret != "" {
		if err := s.controlStore.SaveTenantNotificationEndpointSecret(r.Context(), user.TenantID, id, webhooknotify.NotificationKind, secret); err != nil {
			s.logger.Error("settings webhooks save secret failed", "tenant_id", user.TenantID, "endpoint_id", id, "error", err)
			s.webhooksRedirect(w, r, "error", "WebHook-Secret konnte nicht gespeichert werden")
			return
		}
	}
	action := "tenant.webhook.create"
	if endpointID > 0 {
		action = "tenant.webhook.update"
	}
	if generateSecret && endpointID > 0 {
		action = "tenant.webhook.secret_rotate"
	}
	s.writeAudit(r, action, "tenant", user.TenantID, fmt.Sprintf("endpoint_id=%d name=%s", id, name))
	if revealedSecret != "" {
		s.renderSettingsWebhooks(w, r, revealedSecret, s.settingsFlash(r, "settings.webhooks.secret_created", "Webhook saved. Copy the signing secret now; it will not be shown again."), "")
		return
	}
	s.webhooksRedirect(w, r, "notice", "WebHook gespeichert")
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
		s.webhooksRedirect(w, r, "error", "Ungültiger WebHook")
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		s.webhooksRedirect(w, r, "error", "WebHooks konnten nicht geladen werden")
		return
	}
	if err := appStore.DeleteWebhookEndpoint(r.Context(), endpointID); err != nil {
		if err != sql.ErrNoRows {
			s.logger.Warn("settings webhooks delete endpoint failed", "tenant_id", user.TenantID, "endpoint_id", endpointID, "error", err)
		}
		s.webhooksRedirect(w, r, "error", "WebHook konnte nicht gelöscht werden")
		return
	}
	if err := s.controlStore.DeleteTenantNotificationEndpointSecret(r.Context(), user.TenantID, endpointID, webhooknotify.NotificationKind); err != nil {
		s.logger.Warn("settings webhooks delete secret failed", "tenant_id", user.TenantID, "endpoint_id", endpointID, "error", err)
	}
	s.writeAudit(r, "tenant.webhook.delete", "tenant", user.TenantID, fmt.Sprintf("endpoint_id=%d", endpointID))
	s.webhooksRedirect(w, r, "notice", "WebHook gelöscht")
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
		s.webhooksRedirect(w, r, "error", "Ungültiger WebHook")
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		s.webhooksRedirect(w, r, "error", "WebHooks konnten nicht geladen werden")
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
		s.webhooksRedirect(w, r, "error", "Testversand fehlgeschlagen: "+err.Error())
		return
	}
	s.writeAudit(r, "tenant.webhook.test", "tenant", user.TenantID, fmt.Sprintf("endpoint_id=%d", endpointID))
	s.webhooksRedirect(w, r, "notice", "Testversand erfolgreich")
}

func parseWebhookRouteForm(r *http.Request) route.Route {
	rt := route.Route{
		Groups:     splitCSV(r.FormValue("route_groups")),
		MonitorIDs: parseInt64CSV(r.FormValue("route_monitor_ids")),
		Severities: normalizeRouteSeverities(r.Form["route_severities"]),
	}
	if r.FormValue("quiet_hours_enabled") == "on" {
		rt.QuietHours = &route.QuietHours{
			TZ:    strings.TrimSpace(r.FormValue("quiet_hours_tz")),
			Start: strings.TrimSpace(r.FormValue("quiet_hours_start")),
			End:   strings.TrimSpace(r.FormValue("quiet_hours_end")),
			Mode:  route.QuietModeSuppress,
		}
	}
	type wrap struct {
		Route route.Route `json:"route"`
	}
	raw, err := json.Marshal(wrap{Route: rt})
	if err != nil {
		return rt
	}
	parsed, err := route.Parse(raw)
	if err != nil {
		return rt
	}
	return parsed
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseInt64CSV(raw string) []int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]int64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil || id <= 0 {
			continue
		}
		out = append(out, id)
	}
	return out
}

func normalizeRouteSeverities(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	allowed := map[string]struct{}{
		route.SeverityDown:     {},
		route.SeverityDegraded: {},
		route.SeverityRecovery: {},
		route.SeverityReminder: {},
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if _, ok := allowed[value]; !ok {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
