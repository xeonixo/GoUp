package httpserver

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"goup/internal/auth"
	store "goup/internal/store/sqlite"
	"goup/internal/version"
	"goup/web"
)

type pageData struct {
	Title                             string
	UILanguage                        string
	Translations                      map[string]string
	HideTopbar                        bool
	User                              *auth.UserSession
	IsAdmin                           bool
	Stats                             store.DashboardStats
	Error                             string
	Notice                            string
	FormAction                        string
	BackURL                           string
	IsEdit                            bool
	SettingsMode                      bool
	AuthEnabled                       bool
	AuthDisabled                      bool
	OIDCTenantOnly                    bool
	TrendValue                        string
	TrendLabel                        string
	TrendRanges                       []trendRangeOptionView
	Monitors                          []monitorView
	MonitorGroups                     []monitorGroupView
	AvailableGroups                   []string
	RemoteNodes                       []remoteNodeView
	RemoteNodeProvisioningVars        []remoteNodeProvisioningVarView
	RemoteNodeProvisioningTitle       string
	HasRemoteNodes                    bool
	MonitorExecutors                  []monitorExecutorOptionView
	Events                            []notificationEventView
	StateEvents                       []monitorStateEventView
	AdminTenants                      []store.Tenant
	AdminMonitorCount                 int
	AdminRemoteNodeCount              int
	AdminTenant                       store.Tenant
	AdminProviders                    []store.AuthProvider
	AdminProviderRows                 []adminProviderOverviewRow
	AdminProvider                     store.AuthProvider
	AdminLocalUsers                   []store.LocalUser
	AdminTenantUsers                  []store.TenantUser
	AdminUserRows                     []adminUserOverviewRow
	AdminLocalUser                    store.LocalUser
	AdminRemoteNodeRows               []adminRemoteNodeOverviewRow
	AdminWebhookEndpoints             []store.WebhookEndpoint
	ProfileUser                       store.TenantUser
	ProfileNotify                     store.UserNotificationSettings
	AdminAuditEvents                  []store.AuditEvent
	AuditAction                       string
	AuditActor                        string
	AuditTargetType                   string
	AuditActions                      []string
	AuditTargetTypes                  []string
	GlobalSMTP                        store.GlobalSMTPSettings
	ControlPlaneAdmin                 bool
	AutoDBPath                        string
	TenantSlug                        string
	TenantName                        string
	AppBase                           string
	LoginProviders                    []store.AuthProvider
	HasLocalLogin                     bool
	HasOIDCLogin                      bool
	ResetEnabled                      bool
	ResetToken                        string
	AdminSetup                        bool
	AdminUsername                     string
	AdminAccessTOTPStage              bool
	TOTPRequired                      bool
	TOTPEnabled                       bool
	TOTPSecret                        string
	TOTPProvisioningURI               string
	LanguageOptions                   []languageOptionView
	Pagination                        paginationView
	StateEventHistorySubtitle         string
	StateEventHistoryPageLabel        string
	NotificationEventHistorySubtitle  string
	NotificationEventHistoryPageLabel string
	ImportRows                        []importPreviewRow
	Version                           string
}

type remoteNodeProvisioningVarView struct {
	Key   string
	Value string
}

func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	switch name {
	case "login", "admin_access", "admin_setup", "no_tenant":
		data.HideTopbar = true
	}
	if strings.TrimSpace(data.UILanguage) == "" {
		if data.User != nil {
			data.UILanguage = normalizeUILanguage(data.User.PreferredLanguage)
		} else {
			data.UILanguage = defaultUILanguage
		}
	}
	if data.Translations == nil {
		data.Translations = s.translationsForLanguage(data.UILanguage)
	}
	if title, vars, notice := parseRemoteNodeProvisioningNotice(data.Notice); len(vars) > 0 {
		data.RemoteNodeProvisioningTitle = title
		data.RemoteNodeProvisioningVars = vars
		data.Notice = notice
	}
	data.Error = localizeFlashMessage(data.Translations, data.Error)
	data.Notice = localizeFlashMessage(data.Translations, data.Notice)
	data.Version = version.Version

	tmpl, ok := s.templates[name]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("render template failed", "template", name, "error", err)
		http.Error(w, fmt.Sprintf("render %s failed", name), http.StatusInternalServerError)
	}
}

func parseRemoteNodeProvisioningNotice(message string) (string, []remoteNodeProvisioningVarView, string) {
	message = strings.TrimSpace(message)
	var details string
	var notice string
	var title string
	switch {
	case strings.HasPrefix(message, "Remote-Node erstellt."):
		details = strings.TrimSpace(strings.TrimPrefix(message, "Remote-Node erstellt."))
		notice = "Remote-Node erstellt."
		title = "Remote Node Provisioning"
	case strings.HasPrefix(message, "Bootstrap-Key rotiert."):
		details = strings.TrimSpace(strings.TrimPrefix(message, "Bootstrap-Key rotiert."))
		notice = "Bootstrap-Key rotiert."
		title = "Bootstrap Provisioning"
	default:
		return "", nil, message
	}
	if details == "" {
		return "", nil, message
	}
	vars := make([]remoteNodeProvisioningVarView, 0, 3)
	for _, field := range strings.Fields(details) {
		key, value, ok := strings.Cut(field, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			continue
		}
		vars = append(vars, remoteNodeProvisioningVarView{Key: key, Value: value})
	}
	if len(vars) == 0 {
		return "", nil, message
	}
	return title, vars, notice
}

func parseTemplates() (map[string]*template.Template, error) {
	pages := []string{"dashboard", "login", "password_reset_request", "password_reset_confirm", "admin_dashboard", "admin_tenants", "admin_tenant_form", "admin_providers", "admin_providers_overview", "admin_provider_form", "admin_local_users", "admin_users_overview", "admin_local_user_form", "admin_remote_nodes", "admin_remote_nodes_overview", "settings_users", "settings_profile", "settings_webhooks", "settings_providers", "settings_provider_form", "settings_remote_nodes", "admin_access", "admin_setup", "admin_security", "no_tenant", "state_events_history", "notification_events_history", "monitors_import", "monitors_import_preview"}
	parsed := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		tmpl, err := template.ParseFS(web.FS, "templates/layout.tmpl", "templates/"+page+".tmpl")
		if err != nil {
			return nil, err
		}
		parsed[page] = tmpl
	}
	return parsed, nil
}
