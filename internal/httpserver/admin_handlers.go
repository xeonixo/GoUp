package httpserver

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	store "goup/internal/store/sqlite"
)

func (s *Server) adminActor(r *http.Request) string {
	user := s.currentUser(r)
	if user == nil {
		return "anonymous"
	}
	if strings.TrimSpace(user.Email) != "" {
		return strings.TrimSpace(user.Email)
	}
	if strings.TrimSpace(user.Name) != "" {
		return strings.TrimSpace(user.Name)
	}
	return fmt.Sprintf("user:%d", user.UserID)
}

func (s *Server) writeAudit(r *http.Request, action, targetType string, targetID int64, details string) {
	if err := s.controlStore.InsertAuditEvent(r.Context(), s.adminActor(r), action, targetType, targetID, details); err != nil {
		s.logger.Warn("write audit event failed", "action", action, "target_type", targetType, "target_id", targetID, "error", err)
	}
}

func (s *Server) handleAdminAccess(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(s.cfg.ControlPlaneAdminKey)
	if key == "" {
		http.Error(w, "GOUP_CONTROL_PLANE_ADMIN_KEY is not configured", http.StatusForbidden)
		return
	}

	if strings.TrimSpace(r.URL.Query().Get("logout")) == "1" {
		s.clearControlPlaneAdminCookie(w)
		http.Redirect(w, r, "/admin/access?notice="+url.QueryEscape("Control-Plane-Admin abgemeldet"), http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/admin/access?error="+url.QueryEscape("Ungültiges Formular"), http.StatusSeeOther)
			return
		}
		provided := strings.TrimSpace(r.FormValue("access_key"))
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(key)) != 1 {
			http.Redirect(w, r, "/admin/access?error="+url.QueryEscape("Ungültiger Zugriffsschlüssel"), http.StatusSeeOther)
			return
		}
		s.setControlPlaneAdminCookie(w, key)
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.hasControlPlaneAdminCookie(r, key) {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	s.render(w, "admin_access", pageData{
		Title:  "Control-Plane Zugriff · GoUp",
		Error:  strings.TrimSpace(r.URL.Query().Get("error")),
		Notice: strings.TrimSpace(r.URL.Query().Get("notice")),
	})
}

// Admin Handlers

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/" {
		http.NotFound(w, r)
		return
	}

	user := s.currentUser(r)
	tenants, err := s.controlStore.GetAllTenants(r.Context())
	if err != nil {
		s.logger.Error("admin dashboard list tenants", "error", err)
		http.Error(w, "unable to load admin dashboard", http.StatusInternalServerError)
		return
	}

	smtpSettings, err := s.controlStore.GetGlobalSMTPSettings(r.Context())
	if err != nil {
		s.logger.Error("admin dashboard load smtp settings", "error", err)
		http.Error(w, "unable to load admin dashboard", http.StatusInternalServerError)
		return
	}

	auditAction := strings.TrimSpace(r.URL.Query().Get("audit_action"))
	auditActor := strings.TrimSpace(r.URL.Query().Get("audit_actor"))
	auditTargetType := strings.TrimSpace(r.URL.Query().Get("audit_target"))

	auditEvents, err := s.controlStore.ListAuditEventsFiltered(r.Context(), 50, auditAction, auditActor, auditTargetType)
	if err != nil {
		s.logger.Error("admin dashboard load audit events", "error", err)
		http.Error(w, "unable to load admin dashboard", http.StatusInternalServerError)
		return
	}

	auditActions, err := s.controlStore.ListAuditActionKeys(r.Context(), 100)
	if err != nil {
		s.logger.Error("admin dashboard load audit actions", "error", err)
		auditActions = []string{}
	}
	auditTargetTypes, err := s.controlStore.ListAuditTargetTypes(r.Context(), 50)
	if err != nil {
		s.logger.Error("admin dashboard load audit target types", "error", err)
		auditTargetTypes = []string{}
	}

	contains := func(items []string, value string) bool {
		for _, item := range items {
			if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(value)) {
				return true
			}
		}
		return false
	}
	if auditAction != "" && !contains(auditActions, auditAction) {
		auditActions = append([]string{auditAction}, auditActions...)
	}
	if auditTargetType != "" && !contains(auditTargetTypes, auditTargetType) {
		auditTargetTypes = append([]string{auditTargetType}, auditTargetTypes...)
	}

	s.render(w, "admin_dashboard", pageData{
		Title:            "Admin Dashboard · GoUp",
		User:             user,
		AdminTenants:     tenants,
		AdminAuditEvents: auditEvents,
		AuditAction:      auditAction,
		AuditActor:       auditActor,
		AuditTargetType:  auditTargetType,
		AuditActions:     auditActions,
		AuditTargetTypes: auditTargetTypes,
		GlobalSMTP:       smtpSettings,
		Notice:           strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:            strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleAdminSMTPSettingsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	port := 587
	if rawPort := strings.TrimSpace(r.FormValue("port")); rawPort != "" {
		parsedPort, err := strconv.Atoi(rawPort)
		if err != nil || parsedPort <= 0 || parsedPort > 65535 {
			http.Redirect(w, r, "/admin/?error="+url.QueryEscape("Ungültiger SMTP-Port"), http.StatusSeeOther)
			return
		}
		port = parsedPort
	}

	settings := store.GlobalSMTPSettings{
		Host:      strings.TrimSpace(r.FormValue("host")),
		Port:      port,
		Username:  strings.TrimSpace(r.FormValue("username")),
		FromEmail: strings.TrimSpace(r.FormValue("from_email")),
		FromName:  strings.TrimSpace(r.FormValue("from_name")),
		TLSMode:   strings.TrimSpace(r.FormValue("tls_mode")),
	}
	password := r.FormValue("password")

	if err := s.controlStore.UpsertGlobalSMTPSettings(r.Context(), settings, password); err != nil {
		s.logger.Error("save global smtp settings failed", "error", err)
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP-Einstellungen konnten nicht gespeichert werden"), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "smtp.settings.update", "system", 1, fmt.Sprintf("host=%s port=%d tls=%s", settings.Host, settings.Port, settings.TLSMode))

	http.Redirect(w, r, "/admin/?notice="+url.QueryEscape("SMTP-Einstellungen gespeichert"), http.StatusSeeOther)
}

func (s *Server) handleAdminTenantsList(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	tenants, err := s.controlStore.GetAllTenants(r.Context())
	if err != nil {
		s.logger.Error("get all tenants failed", "error", err)
		http.Error(w, "unable to load tenants", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_tenants", pageData{
		Title:        "Tenants verwalten · GoUp",
		User:         user,
		AdminTenants: tenants,
		Notice:       strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:        strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleAdminTenantForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	data := pageData{
		Title:      "Tenant · GoUp",
		User:       user,
		FormAction: "/admin/tenants/save",
		Notice:     strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:      strings.TrimSpace(r.URL.Query().Get("error")),
	}

	if tenantIDRaw != "" {
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

		data.Title = fmt.Sprintf("Tenant %s bearbeiten · GoUp", tenant.Name)
		data.AdminTenant = tenant
		data.IsEdit = true
	}

	s.render(w, "admin_tenant_form", data)
}

func (s *Server) handleAdminTenantSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	id := strings.TrimSpace(r.FormValue("id"))
	if id == "0" {
		id = ""
	}
	slug := strings.ToLower(strings.TrimSpace(r.FormValue("slug")))
	name := strings.TrimSpace(r.FormValue("name"))
	dbPath := strings.TrimSpace(r.FormValue("db_path"))
	active := r.FormValue("active") == "1"

	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if id == "" {
		if slug == "" {
			http.Error(w, "slug is required for new tenants", http.StatusBadRequest)
			return
		}
		if dbPath == "" {
			dbPath = "/data/" + slug + ".db"
		}

		// Create new tenant
		tenant, err := s.controlStore.CreateTenant(r.Context(), slug, name, dbPath)
		if err != nil {
			s.logger.Error("create tenant failed", "error", err)
			http.Redirect(w, r, "/admin/tenants/new?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
		s.writeAudit(r, "tenant.create", "tenant", tenant.ID, fmt.Sprintf("slug=%s name=%s", tenant.Slug, tenant.Name))
		http.Redirect(w, r, "/admin/tenants/"+fmt.Sprintf("%d", tenant.ID)+"/edit?notice="+url.QueryEscape("Tenant erstellt"), http.StatusSeeOther)
	} else {
		// Update existing tenant
		tenantID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			http.Error(w, "invalid tenant id", http.StatusBadRequest)
			return
		}
		if dbPath == "" {
			tenant, getErr := s.controlStore.GetTenantByID(r.Context(), tenantID)
			if getErr != nil {
				http.Error(w, "invalid tenant id", http.StatusBadRequest)
				return
			}
			dbPath = tenant.DBPath
		}
		_, err = s.controlStore.UpdateTenant(r.Context(), tenantID, name, dbPath, active)
		if err != nil {
			s.logger.Error("update tenant failed", "error", err)
			http.Redirect(w, r, "/admin/tenants/"+id+"/edit?error="+url.QueryEscape("Tenant konnte nicht gespeichert werden"), http.StatusSeeOther)
			return
		}
		s.writeAudit(r, "tenant.update", "tenant", tenantID, fmt.Sprintf("name=%s active=%t", name, active))
		http.Redirect(w, r, "/admin/tenants?notice="+url.QueryEscape("Tenant aktualisiert"), http.StatusSeeOther)
	}
}

func (s *Server) handleAdminTenantDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	tenantID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	if err := s.controlStore.DeactivateTenant(r.Context(), tenantID); err != nil {
		s.logger.Error("deactivate tenant failed", "error", err)
		http.Error(w, "unable to deactivate tenant", http.StatusInternalServerError)
		return
	}
	s.writeAudit(r, "tenant.deactivate", "tenant", tenantID, "")

	http.Redirect(w, r, "/admin/tenants?notice="+url.QueryEscape("Tenant deaktiviert"), http.StatusSeeOther)
}

func (s *Server) handleAdminTenantPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	tenantID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	if tenantID == s.defaultTenant.ID {
		http.Redirect(w, r, "/admin/tenants?error="+url.QueryEscape("Default-Tenant kann nicht restlos gelöscht werden"), http.StatusSeeOther)
		return
	}

	if err := s.controlStore.PurgeTenant(r.Context(), tenantID); err != nil {
		s.logger.Error("purge tenant failed", "tenant_id", tenantID, "error", err)
		http.Redirect(w, r, "/admin/tenants?error="+url.QueryEscape("Tenant konnte nicht restlos gelöscht werden"), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "tenant.purge", "tenant", tenantID, "permanent delete requested")

	http.Redirect(w, r, "/admin/tenants?notice="+url.QueryEscape("Tenant restlos gelöscht"), http.StatusSeeOther)
}

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
		Title:          fmt.Sprintf("Provider für %s · GoUp", tenant.Name),
		User:           user,
		AdminTenant:    tenant,
		AdminProviders: providers,
		Notice:         strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:          strings.TrimSpace(r.URL.Query().Get("error")),
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
		Title:       fmt.Sprintf("Provider für %s · GoUp", tenant.Name),
		User:        user,
		AdminTenant: tenant,
		FormAction:  fmt.Sprintf("/admin/tenants/%d/providers/save", tenant.ID),
		Notice:      strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:       strings.TrimSpace(r.URL.Query().Get("error")),
	}

	providerKey := strings.TrimSpace(r.PathValue("providerKey"))
	if providerKey != "" {
		provider, err := s.controlStore.GetAuthProvider(r.Context(), tenantID, providerKey)
		if err != nil {
			http.NotFound(w, r)
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

func (s *Server) handleAdminLocalUsersList(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	id := strings.TrimSpace(r.PathValue("id"))
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

	tenantUsers, err := s.controlStore.ListTenantUsers(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("list tenant users failed", "tenant_id", tenantID, "error", err)
		http.Error(w, "unable to load tenant users", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_local_users", pageData{
		Title:            fmt.Sprintf("Benutzer für %s · GoUp", tenant.Name),
		User:             user,
		AdminTenant:      tenant,
		AdminTenantUsers: tenantUsers,
		Notice:           strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:            strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleAdminLocalUserForm(w http.ResponseWriter, r *http.Request) {
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
		Title:       fmt.Sprintf("Lokaler Benutzer für %s · GoUp", tenant.Name),
		User:        user,
		AdminTenant: tenant,
		FormAction:  fmt.Sprintf("/admin/tenants/%d/local-users/save", tenant.ID),
		Notice:      strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:       strings.TrimSpace(r.URL.Query().Get("error")),
	}

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	if userIDRaw != "" {
		userID, err := strconv.ParseInt(userIDRaw, 10, 64)
		if err != nil {
			http.Error(w, "invalid user id", http.StatusBadRequest)
			return
		}
		localUser, err := s.controlStore.GetLocalUserByID(r.Context(), tenantID, userID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data.AdminLocalUser = localUser
		data.IsEdit = true
	}

	s.render(w, "admin_local_user_form", data)
}

func (s *Server) handleAdminLocalUserSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
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

	if _, err := s.controlStore.UpsertAuthProvider(r.Context(), tenantID, "local-primary", "local", "Local Login", "", ""); err != nil {
		s.logger.Error("ensure local auth provider failed", "tenant_id", tenantID, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?error=%s", tenantID, url.QueryEscape("Lokaler Provider konnte nicht angelegt werden")), http.StatusSeeOther)
		return
	}

	if userIDRaw == "" {
		if strings.TrimSpace(password) == "" {
			http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users/new?error=%s", tenantID, url.QueryEscape("Passwort ist erforderlich")), http.StatusSeeOther)
			return
		}
		_, err := s.controlStore.CreateLocalUserForTenant(r.Context(), tenantID, loginName, password, email, displayName, role)
		if err != nil {
			s.logger.Error("create local user failed", "tenant_id", tenantID, "error", err)
			http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users/new?error=%s", tenantID, url.QueryEscape("Lokaler Benutzer konnte nicht erstellt werden")), http.StatusSeeOther)
			return
		}
		s.writeAudit(r, "local_user.create", "tenant", tenantID, fmt.Sprintf("login=%s email=%s", loginName, email))
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?notice=%s", tenantID, url.QueryEscape("Lokaler Benutzer erstellt")), http.StatusSeeOther)
		return
	}

	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	_, err = s.controlStore.UpdateLocalUserForTenant(r.Context(), tenantID, userID, loginName, password, email, displayName, role)
	if err != nil {
		s.logger.Error("update local user failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users/%d/edit?error=%s", tenantID, userID, url.QueryEscape("Lokaler Benutzer konnte nicht gespeichert werden")), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "local_user.update", "tenant", tenantID, fmt.Sprintf("user_id=%d login=%s", userID, loginName))

	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?notice=%s", tenantID, url.QueryEscape("Lokaler Benutzer gespeichert")), http.StatusSeeOther)
}

func (s *Server) handleAdminLocalUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	if err := s.controlStore.DeleteLocalUserFromTenant(r.Context(), tenantID, userID); err != nil {
		s.logger.Error("delete local user failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?error=%s", tenantID, url.QueryEscape("Lokaler Benutzer konnte nicht entfernt werden")), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "local_user.delete", "tenant", tenantID, fmt.Sprintf("user_id=%d", userID))

	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?notice=%s", tenantID, url.QueryEscape("Lokaler Benutzer entfernt")), http.StatusSeeOther)
}

func (s *Server) handleAdminTenantUserRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	if err := s.controlStore.RemoveUserFromTenant(r.Context(), tenantID, userID); err != nil {
		s.logger.Error("remove tenant user failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?error=%s", tenantID, url.QueryEscape("Benutzer konnte nicht entfernt werden")), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "tenant_user.remove", "tenant", tenantID, fmt.Sprintf("user_id=%d", userID))

	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?notice=%s", tenantID, url.QueryEscape("Benutzer entfernt")), http.StatusSeeOther)
}

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
		if session, err := s.sessions.Get(r); err == nil {
			session.Role = strings.ToLower(strings.TrimSpace(role))
			_ = s.sessions.Set(w, *session)
		}
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
		if session, err := s.sessions.Get(r); err == nil {
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
