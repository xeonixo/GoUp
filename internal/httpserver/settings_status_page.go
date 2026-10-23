package httpserver

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	store "goup/internal/store/sqlite"
)

type statusPageAdminMonitorView struct {
	ID          int64
	Name        string
	Group       string
	Selected    bool
	DisplayName string
}

type apiTokenView struct {
	ID        int64
	Name      string
	Scope     string
	CreatedBy string
	CreatedAt string
	LastUsed  string
}

// statusPageAdminView backs the "Status page & metrics" settings page.
type statusPageAdminView struct {
	Enabled     bool
	Title       string
	Description string
	Monitors    []statusPageAdminMonitorView
	PublicURL   string
	MetricsURL  string
	Tokens      []apiTokenView
	// NewToken is only set in the response to a token creation; it is never stored in plain text.
	NewToken string
}

func (s *Server) settingsFlash(r *http.Request, key, fallback string) string {
	lang := defaultUILanguage
	if user := s.currentUser(r); user != nil {
		lang = normalizeUILanguage(user.PreferredLanguage)
	}
	return statusPageTr(s.translationsForLanguage(lang), key, fallback)
}

func (s *Server) statusPageSettingsRedirect(w http.ResponseWriter, r *http.Request, kind, message string) {
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/status-page?"+kind+"="+url.QueryEscape(message), http.StatusSeeOther)
}

func (s *Server) publicTenantURL(r *http.Request, suffix string) string {
	base := strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")
	return base + "/" + tenantSlugFromRequest(r) + "/" + suffix
}

func (s *Server) loadStatusPageAdminView(r *http.Request, tenantID int64) (*statusPageAdminView, error) {
	appStore, err := s.appStore(r)
	if err != nil {
		return nil, err
	}
	settings, err := appStore.GetStatusPageSettings(r.Context())
	if err != nil {
		return nil, err
	}
	selected, err := appStore.ListStatusPageMonitors(r.Context())
	if err != nil {
		return nil, err
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		return nil, err
	}
	tokens, err := s.controlStore.ListAPITokens(r.Context(), tenantID)
	if err != nil {
		return nil, err
	}

	selectedNames := make(map[int64]string, len(selected))
	for _, item := range selected {
		selectedNames[item.MonitorID] = item.DisplayName
	}
	view := &statusPageAdminView{
		Enabled:     settings.Enabled,
		Title:       settings.Title,
		Description: settings.Description,
		PublicURL:   s.publicTenantURL(r, "status"),
		MetricsURL:  s.publicTenantURL(r, "metrics"),
	}
	for _, snap := range snapshots {
		display, isSelected := selectedNames[snap.Monitor.ID]
		if display == "" {
			display = snap.Monitor.Name
		}
		view.Monitors = append(view.Monitors, statusPageAdminMonitorView{
			ID:          snap.Monitor.ID,
			Name:        snap.Monitor.Name,
			Group:       strings.TrimSpace(snap.Monitor.Group),
			Selected:    isSelected,
			DisplayName: display,
		})
	}
	for _, token := range tokens {
		item := apiTokenView{ID: token.ID, Name: token.Name, Scope: token.Scope, CreatedBy: token.CreatedBy, CreatedAt: token.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")}
		if token.LastUsedAt != nil {
			item.LastUsed = token.LastUsedAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		view.Tokens = append(view.Tokens, item)
	}
	return view, nil
}

func (s *Server) renderStatusPageSettings(w http.ResponseWriter, r *http.Request, newToken string, notice string, errText string) {
	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tenant, err := s.controlStore.GetTenantByID(r.Context(), user.TenantID)
	if err != nil {
		s.logger.Error("settings status page load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}
	view, err := s.loadStatusPageAdminView(r, user.TenantID)
	if err != nil {
		s.logger.Error("settings status page load failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load status page settings", http.StatusInternalServerError)
		return
	}
	view.NewToken = newToken
	s.render(w, "settings_status_page", pageData{
		Title:        "Einstellungen · Status & Metriken · GoUp",
		User:         user,
		AdminTenant:  tenant,
		AppBase:      s.tenantAppBase(r),
		Notice:       notice,
		Error:        errText,
		SettingsMode: true,
		StatusAdmin:  view,
	})
}

func (s *Server) handleSettingsStatusPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.renderStatusPageSettings(w, r, "", strings.TrimSpace(r.URL.Query().Get("notice")), strings.TrimSpace(r.URL.Query().Get("error")))
}

func (s *Server) handleSettingsStatusPageSave(w http.ResponseWriter, r *http.Request) {
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
		s.logger.Error("settings status page resolve store failed", "tenant_id", user.TenantID, "error", err)
		s.statusPageSettingsRedirect(w, r, "error", s.settingsFlash(r, "settings.status_page.error_save", "Status page could not be saved"))
		return
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		s.logger.Error("settings status page list monitors failed", "tenant_id", user.TenantID, "error", err)
		s.statusPageSettingsRedirect(w, r, "error", s.settingsFlash(r, "settings.status_page.error_save", "Status page could not be saved"))
		return
	}

	monitors := make([]store.StatusPageMonitor, 0)
	for _, snap := range snapshots {
		idText := strconv.FormatInt(snap.Monitor.ID, 10)
		if r.FormValue("monitor_"+idText) != "on" {
			continue
		}
		display := strings.TrimSpace(r.FormValue("display_" + idText))
		if display == "" {
			display = strings.TrimSpace(snap.Monitor.Name)
		}
		monitors = append(monitors, store.StatusPageMonitor{MonitorID: snap.Monitor.ID, DisplayName: display})
	}
	settings := store.StatusPageSettings{
		Enabled:     r.FormValue("enabled") == "on",
		Title:       r.FormValue("title"),
		Description: r.FormValue("description"),
	}
	if err := appStore.SaveStatusPageSettings(r.Context(), settings, monitors); err != nil {
		s.logger.Error("settings status page save failed", "tenant_id", user.TenantID, "error", err)
		s.statusPageSettingsRedirect(w, r, "error", s.settingsFlash(r, "settings.status_page.error_save", "Status page could not be saved"))
		return
	}
	s.statusCache.invalidate()
	s.writeAudit(r, "tenant.status_page.update", "tenant", user.TenantID, "enabled="+strconv.FormatBool(settings.Enabled)+" monitors="+strconv.Itoa(len(monitors)))
	s.statusPageSettingsRedirect(w, r, "notice", s.settingsFlash(r, "settings.status_page.saved", "Status page saved"))
}

func (s *Server) handleSettingsAPITokenCreate(w http.ResponseWriter, r *http.Request) {
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
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.statusPageSettingsRedirect(w, r, "error", s.settingsFlash(r, "settings.status_page.error_token_name", "Token name is required"))
		return
	}
	createdBy := strings.TrimSpace(user.Email)
	if createdBy == "" {
		createdBy = strings.TrimSpace(user.Name)
	}
	plain, token, err := s.controlStore.CreateAPIToken(r.Context(), user.TenantID, name, store.APITokenScopeMetrics, createdBy)
	if err != nil {
		s.logger.Error("settings create api token failed", "tenant_id", user.TenantID, "error", err)
		s.statusPageSettingsRedirect(w, r, "error", s.settingsFlash(r, "settings.status_page.error_token", "Token could not be created"))
		return
	}
	s.writeAudit(r, "tenant.api_token.create", "tenant", user.TenantID, "token_id="+strconv.FormatInt(token.ID, 10)+" scope="+token.Scope)
	// The plain token is rendered directly in this response (never via redirect/query string).
	s.renderStatusPageSettings(w, r, plain, s.settingsFlash(r, "settings.status_page.token_created", "Token created. Copy it now; it will not be shown again."), "")
}

func (s *Server) handleSettingsAPITokenRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tokenID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || tokenID <= 0 {
		http.Error(w, "invalid token id", http.StatusBadRequest)
		return
	}
	removed, err := s.controlStore.RevokeAPIToken(r.Context(), user.TenantID, tokenID)
	if err != nil {
		s.logger.Error("settings revoke api token failed", "tenant_id", user.TenantID, "token_id", tokenID, "error", err)
		s.statusPageSettingsRedirect(w, r, "error", s.settingsFlash(r, "settings.status_page.error_token", "Token could not be revoked"))
		return
	}
	if removed {
		s.writeAudit(r, "tenant.api_token.revoke", "tenant", user.TenantID, "token_id="+strconv.FormatInt(tokenID, 10))
	}
	s.statusPageSettingsRedirect(w, r, "notice", s.settingsFlash(r, "settings.status_page.token_revoked", "Token revoked"))
}
