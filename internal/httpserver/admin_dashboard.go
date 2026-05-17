package httpserver

import (
	"context"
	"fmt"
	store "goup/internal/store/sqlite"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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

	monitorCount, remoteNodeCount := s.loadControlPlaneInstanceCounts(r.Context(), tenants)

	s.render(w, "admin_dashboard", pageData{
		Title:                "Allgemein · GoUp",
		User:                 user,
		AdminTenants:         tenants,
		AdminMonitorCount:    monitorCount,
		AdminRemoteNodeCount: remoteNodeCount,
		ControlPlaneAdmin:    true,
		AdminAuditEvents:     auditEvents,
		AuditAction:          auditAction,
		AuditActor:           auditActor,
		AuditTargetType:      auditTargetType,
		AuditActions:         auditActions,
		AuditTargetTypes:     auditTargetTypes,
		GlobalSMTP:           smtpSettings,
		Notice:               strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:                strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleAdminProvidersOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := s.loadAdminProviderOverviewRows(r.Context())
	if err != nil {
		s.logger.Error("admin providers overview load failed", "error", err)
		http.Error(w, "unable to load providers overview", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_providers_overview", pageData{
		Title:             "OCID-Provider · GoUp",
		User:              s.currentUser(r),
		ControlPlaneAdmin: true,
		AdminProviderRows: rows,
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleAdminUsersOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := s.loadAdminUserOverviewRows(r.Context())
	if err != nil {
		s.logger.Error("admin users overview load failed", "error", err)
		http.Error(w, "unable to load users overview", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_users_overview", pageData{
		Title:             "Benutzerverwaltung · GoUp",
		User:              s.currentUser(r),
		ControlPlaneAdmin: true,
		AdminUserRows:     rows,
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleAdminRemoteNodesOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := s.loadAdminRemoteNodeOverviewRows(r.Context())
	if err != nil {
		s.logger.Error("admin remote nodes overview load failed", "error", err)
		http.Error(w, "unable to load remote nodes overview", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_remote_nodes_overview", pageData{
		Title:               "Remote Nodes · GoUp",
		User:                s.currentUser(r),
		ControlPlaneAdmin:   true,
		AdminRemoteNodeRows: rows,
		Notice:              strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:               strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) loadControlPlaneInstanceCounts(ctx context.Context, tenants []store.Tenant) (int, int) {
	monitorCount := 0
	for _, tenant := range tenants {
		if strings.TrimSpace(tenant.DBPath) == "" {
			continue
		}

		var (
			tenantStore *store.Store
			err         error
			closeStore  bool
		)

		if tenant.Active {
			tenantStore, err = s.tenantStores.StoreForTenant(ctx, tenant.ID)
		} else {
			tenantStore, err = store.Open(ctx, tenant.DBPath)
			closeStore = err == nil
		}
		if err != nil {
			s.logger.Warn("admin dashboard monitor count skipped tenant", "tenant_id", tenant.ID, "error", err)
			continue
		}

		stats, statsErr := tenantStore.DashboardStats(ctx)
		if closeStore {
			_ = tenantStore.Close()
		}
		if statsErr != nil {
			s.logger.Warn("admin dashboard monitor count failed", "tenant_id", tenant.ID, "error", statsErr)
			continue
		}
		monitorCount += stats.MonitorCount
	}

	remoteNodes, err := s.controlStore.ListAllEnabledRemoteNodes(ctx)
	if err != nil {
		s.logger.Warn("admin dashboard remote node count failed", "error", err)
		return monitorCount, 0
	}
	return monitorCount, len(remoteNodes)
}

func (s *Server) loadAdminProviderOverviewRows(ctx context.Context) ([]adminProviderOverviewRow, error) {
	tenants, err := s.controlStore.GetAllTenants(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]adminProviderOverviewRow, 0)
	for _, tenant := range tenants {
		providers, providerErr := s.controlStore.GetAllAuthProvidersByTenant(ctx, tenant.ID)
		if providerErr != nil {
			s.logger.Warn("admin providers overview skip tenant", "tenant_id", tenant.ID, "error", providerErr)
			continue
		}
		for _, provider := range providers {
			rows = append(rows, adminProviderOverviewRow{
				TenantID:    tenant.ID,
				TenantName:  tenant.Name,
				TenantSlug:  tenant.Slug,
				ProviderKey: provider.ProviderKey,
				Kind:        provider.Kind,
				DisplayName: provider.DisplayName,
				Enabled:     provider.Enabled,
			})
		}
	}
	return rows, nil
}

func (s *Server) loadAdminUserOverviewRows(ctx context.Context) ([]adminUserOverviewRow, error) {
	tenants, err := s.controlStore.GetAllTenants(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]adminUserOverviewRow, 0)
	for _, tenant := range tenants {
		users, userErr := s.controlStore.ListTenantUsers(ctx, tenant.ID)
		if userErr != nil {
			s.logger.Warn("admin users overview skip tenant", "tenant_id", tenant.ID, "error", userErr)
			continue
		}
		for _, user := range users {
			row := adminUserOverviewRow{
				TenantID:            tenant.ID,
				TenantName:          tenant.Name,
				TenantSlug:          tenant.Slug,
				UserID:              user.UserID,
				LoginName:           user.LoginName,
				Email:               user.Email,
				DisplayName:         user.DisplayName,
				Role:                user.Role,
				HasLocalCredentials: user.HasLocalCredentials,
				HasOIDCIdentity:     user.HasOIDCIdentity,
			}
			if user.LastLoginAt != nil {
				row.LastLoginAtRaw = user.LastLoginAt.UTC().Format(time.RFC3339)
				row.LastLoginAt = row.LastLoginAtRaw
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func (s *Server) loadAdminRemoteNodeOverviewRows(ctx context.Context) ([]adminRemoteNodeOverviewRow, error) {
	tenants, err := s.controlStore.GetAllTenants(ctx)
	if err != nil {
		return nil, err
	}
	tenantByID := make(map[int64]store.Tenant, len(tenants))
	for _, tenant := range tenants {
		tenantByID[tenant.ID] = tenant
	}

	nodes, err := s.controlStore.ListAllEnabledRemoteNodes(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	rows := make([]adminRemoteNodeOverviewRow, 0, len(nodes))
	for _, node := range nodes {
		tenant := tenantByID[node.TenantID]
		row := adminRemoteNodeOverviewRow{
			TenantID:        node.TenantID,
			TenantName:      tenant.Name,
			TenantSlug:      tenant.Slug,
			NodeID:          node.NodeID,
			Name:            node.Name,
			Online:          node.IsOnline(now),
			HeartbeatWindow: fmt.Sprintf("%ds", node.HeartbeatTimeoutSeconds),
		}
		if node.LastSeenAt != nil {
			row.LastSeenAtRaw = node.LastSeenAt.UTC().Format(time.RFC3339)
			row.LastSeenAt = row.LastSeenAtRaw
		}
		rows = append(rows, row)
	}
	return rows, nil
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

	settings, err := parseSMTPSettingsForm(r)
	if err != nil {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
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

func (s *Server) handleAdminSMTPSettingsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	settings, err := parseSMTPSettingsForm(r)
	if err != nil {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	recipient := strings.TrimSpace(r.FormValue("test_recipient"))
	if recipient == "" {
		admin, adminErr := s.controlStore.GetControlPlaneAdmin(r.Context())
		if adminErr == nil && strings.Contains(strings.TrimSpace(admin.Username), "@") {
			recipient = strings.TrimSpace(admin.Username)
		}
	}
	if recipient == "" {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("Test-Empfänger ist erforderlich"), http.StatusSeeOther)
		return
	}

	password := strings.TrimSpace(r.FormValue("password"))
	if password == "" {
		currentCfg, cfgErr := s.controlStore.GetGlobalSMTPDeliveryConfig(r.Context())
		if cfgErr != nil {
			s.logger.Warn("load stored smtp password for test failed", "error", cfgErr)
			http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP-Test fehlgeschlagen: "+cfgErr.Error()), http.StatusSeeOther)
			return
		}
		password = strings.TrimSpace(currentCfg.Password)
	}
	cfg := store.GlobalSMTPDeliveryConfig{Settings: settings, Password: password}
	if strings.TrimSpace(cfg.Settings.Host) == "" || strings.TrimSpace(cfg.Settings.FromEmail) == "" {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP Host/Absender ist nicht konfiguriert"), http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(cfg.Password) == "" {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP Passwort ist nicht konfiguriert"), http.StatusSeeOther)
		return
	}

	body := "Dies ist eine Testnachricht aus der GoUp Control Plane.\n\nWenn diese Nachricht angekommen ist, funktioniert die globale SMTP-Konfiguration."
	if err := sendSMTPMail(cfg, recipient, "GoUp SMTP Test", body); err != nil {
		s.logger.Warn("smtp test failed", "recipient", recipient, "error", err)
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP-Test fehlgeschlagen: "+err.Error()), http.StatusSeeOther)
		return
	}

	s.writeAudit(r, "smtp.settings.test", "system", 1, fmt.Sprintf("recipient=%s host=%s port=%d tls=%s", recipient, settings.Host, settings.Port, settings.TLSMode))
	http.Redirect(w, r, "/admin/?notice="+url.QueryEscape("SMTP-Test erfolgreich versendet"), http.StatusSeeOther)
}

func parseSMTPSettingsForm(r *http.Request) (store.GlobalSMTPSettings, error) {
	port := 587
	if rawPort := strings.TrimSpace(r.FormValue("port")); rawPort != "" {
		parsedPort, err := strconv.Atoi(rawPort)
		if err != nil || parsedPort <= 0 || parsedPort > 65535 {
			return store.GlobalSMTPSettings{}, fmt.Errorf("Ungültiger SMTP-Port")
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
	return settings, nil
}
