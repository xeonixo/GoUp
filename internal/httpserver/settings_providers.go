package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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
