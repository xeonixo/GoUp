package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (s *Server) handleAdminProvidersList(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	id := r.PathValue("id")
	tenantID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	tenant, err := s.controlStore.GetTenantByID(r.Context(), tenantID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	providers, err := s.controlStore.GetAllAuthProvidersByTenant(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("get auth providers failed", "error", err)
		http.Error(w, "unable to load providers", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_providers", pageData{
		Title:             fmt.Sprintf("Provider für %s · GoUp", tenant.Name),
		User:              user,
		ControlPlaneAdmin: true,
		AdminTenant:       tenant,
		AdminProviders:    providers,
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleAdminProviderForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	tenant, err := s.controlStore.GetTenantByID(r.Context(), tenantID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := pageData{
		Title:             fmt.Sprintf("Provider für %s · GoUp", tenant.Name),
		User:              user,
		ControlPlaneAdmin: true,
		AdminTenant:       tenant,
		FormAction:        fmt.Sprintf("/admin/tenants/%d/providers/save", tenant.ID),
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
	}

	providerKey := strings.TrimSpace(r.PathValue("providerKey"))
	if providerKey != "" {
		provider, err := s.controlStore.GetAuthProvider(r.Context(), tenantID, providerKey)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if provider.Kind == "local" {
			http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/providers?error=%s", tenant.ID, url.QueryEscape("Lokale Provider können nicht bearbeitet werden")), http.StatusSeeOther)
			return
		}
		data.AdminProvider = provider
		data.IsEdit = true
	}

	s.render(w, "admin_provider_form", data)
}

func (s *Server) handleAdminProviderSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		id = strings.TrimSpace(r.FormValue("tenant_id"))
	}
	providerKey := strings.TrimSpace(r.FormValue("provider_key"))
	kind := strings.TrimSpace(r.FormValue("kind"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	issuerURL := strings.TrimSpace(r.FormValue("issuer_url"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))

	if id == "" || providerKey == "" || kind == "" {
		http.Error(w, "tenant_id, provider_key, and kind are required", http.StatusBadRequest)
		return
	}

	if displayName == "" {
		displayName = providerKey
	}

	if kind == "oidc" && (issuerURL == "" || clientID == "") {
		http.Error(w, "issuer_url and client_id are required for oidc providers", http.StatusBadRequest)
		return
	}

	tenantID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	if kind == "local" {
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/providers?error=%s", tenantID, url.QueryEscape("Lokale Provider werden automatisch verwaltet und sind nicht konfigurierbar")), http.StatusSeeOther)
		return
	}

	_, err = s.controlStore.UpsertAuthProvider(r.Context(), tenantID, providerKey, kind, displayName, issuerURL, clientID)
	if err != nil {
		s.logger.Error("upsert auth provider failed", "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/providers/new?error=%s", tenantID, url.QueryEscape("Provider konnte nicht gespeichert werden")), http.StatusSeeOther)
		return
	}

	if kind == "oidc" && clientSecret != "" {
		if err := s.controlStore.UpdateAuthProviderSecret(r.Context(), tenantID, providerKey, clientSecret); err != nil {
			s.logger.Error("update auth provider secret failed", "tenant_id", tenantID, "provider_key", providerKey, "error", err)
			http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/providers/%s/edit?error=%s", tenantID, providerKey, url.QueryEscape("Provider gespeichert, Secret konnte nicht gespeichert werden")), http.StatusSeeOther)
			return
		}
	}
	s.writeAudit(r, "auth_provider.upsert", "tenant", tenantID, fmt.Sprintf("provider=%s kind=%s", providerKey, kind))

	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/providers?notice=%s", tenantID, url.QueryEscape("Provider gespeichert")), http.StatusSeeOther)
}

func (s *Server) handleAdminProviderDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	providerKey := r.PathValue("providerKey")

	tenantID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	if err := s.controlStore.DeleteAuthProvider(r.Context(), tenantID, providerKey); err != nil {
		s.logger.Error("delete auth provider failed", "error", err)
		http.Error(w, "unable to delete provider", http.StatusInternalServerError)
		return
	}
	s.writeAudit(r, "auth_provider.deactivate", "tenant", tenantID, fmt.Sprintf("provider=%s", providerKey))

	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/providers?notice=%s", tenantID, url.QueryEscape("Provider deaktiviert")), http.StatusSeeOther)
}
