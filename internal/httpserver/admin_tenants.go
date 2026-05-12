package httpserver

import (
	"fmt"
	store "goup/internal/store/sqlite"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (s *Server) ensureTenantStorage(slug string) error {
	if err := os.MkdirAll(s.uploadedIconsDir(slug), 0o755); err != nil {
		return fmt.Errorf("create tenant icon storage: %w", err)
	}
	if err := os.MkdirAll(s.persistedDashboardIconsDir(slug), 0o755); err != nil {
		return fmt.Errorf("create tenant dashboard icon storage: %w", err)
	}
	return nil
}

func (s *Server) removeTenantStorage(slug string) error {
	if err := os.RemoveAll(s.uploadedIconsDir(slug)); err != nil {
		return fmt.Errorf("remove tenant icon storage: %w", err)
	}
	return nil
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
		Title:             "Tenants verwalten · GoUp",
		User:              user,
		ControlPlaneAdmin: true,
		AdminTenants:      tenants,
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
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
		Title:             "Tenant · GoUp",
		User:              user,
		ControlPlaneAdmin: true,
		FormAction:        "/admin/tenants/save",
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
		AutoDBPath:        autoTenantDBPath(s.cfg.DataDir, "default"),
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
		data.AutoDBPath = tenant.DBPath
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
	active := r.FormValue("active") == "1"
	stateEventRetentionDays := parseTenantRetentionDays(r.FormValue("state_event_retention_days"))
	notificationEventRetentionDays := parseTenantRetentionDays(r.FormValue("notification_event_retention_days"))

	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if id == "" {
		if slug == "" {
			http.Error(w, "slug is required for new tenants", http.StatusBadRequest)
			return
		}
		dbPath := autoTenantDBPath(s.cfg.DataDir, slug)

		// Create new tenant
		tenant, err := s.controlStore.CreateTenantWithRetention(r.Context(), slug, name, dbPath, stateEventRetentionDays, notificationEventRetentionDays)
		if err != nil {
			s.logger.Error("create tenant failed", "error", err)
			http.Redirect(w, r, "/admin/tenants/new?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
		if err := s.ensureTenantStorage(tenant.Slug); err != nil {
			s.logger.Error("prepare tenant storage failed", "tenant", tenant.Slug, "error", err)
			if purgeErr := s.controlStore.PurgeTenant(r.Context(), tenant.ID); purgeErr != nil {
				s.logger.Error("rollback tenant create failed", "tenant_id", tenant.ID, "error", purgeErr)
			}
			http.Redirect(w, r, "/admin/tenants/new?error="+url.QueryEscape("Tenant-Speicher konnte nicht vorbereitet werden"), http.StatusSeeOther)
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
		tenant, getErr := s.controlStore.GetTenantByID(r.Context(), tenantID)
		if getErr != nil {
			http.Error(w, "invalid tenant id", http.StatusBadRequest)
			return
		}
		_, err = s.controlStore.UpdateTenantWithRetention(r.Context(), tenantID, name, tenant.DBPath, active, stateEventRetentionDays, notificationEventRetentionDays)
		if err != nil {
			s.logger.Error("update tenant failed", "error", err)
			http.Redirect(w, r, "/admin/tenants/"+id+"/edit?error="+url.QueryEscape("Tenant konnte nicht gespeichert werden"), http.StatusSeeOther)
			return
		}
		if active {
			if err := s.ensureTenantStorage(tenant.Slug); err != nil {
				s.logger.Error("prepare tenant storage failed", "tenant", tenant.Slug, "error", err)
				http.Redirect(w, r, "/admin/tenants/"+id+"/edit?error="+url.QueryEscape("Tenant-Speicher konnte nicht vorbereitet werden"), http.StatusSeeOther)
				return
			}
		}
		s.writeAudit(r, "tenant.update", "tenant", tenantID, fmt.Sprintf("name=%s active=%t state_event_retention_days=%d notification_event_retention_days=%d", name, active, stateEventRetentionDays, notificationEventRetentionDays))
		http.Redirect(w, r, "/admin/tenants?notice="+url.QueryEscape("Tenant aktualisiert"), http.StatusSeeOther)
	}
}

func parseTenantRetentionDays(value string) int {
	days, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return store.NormalizeEventRetentionDays(0)
	}
	return store.NormalizeEventRetentionDays(days)
}

func autoTenantDBPath(dataDir string, slug string) string {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" {
		slug = "tenant"
	}
	baseDir := strings.TrimSpace(dataDir)
	if baseDir == "" {
		baseDir = "./data"
	}
	if slug == "default" {
		return filepath.Join(baseDir, "goup.db")
	}
	return filepath.Join(baseDir, slug+".db")
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
	tenant, err := s.controlStore.GetTenantByID(r.Context(), tenantID)
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
	if err := s.removeTenantStorage(tenant.Slug); err != nil {
		s.logger.Error("purge tenant storage failed", "tenant", tenant.Slug, "error", err)
		http.Redirect(w, r, "/admin/tenants?error="+url.QueryEscape("Tenant wurde gelöscht, aber Icon-Speicher konnte nicht entfernt werden"), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "tenant.purge", "tenant", tenantID, "permanent delete requested")

	http.Redirect(w, r, "/admin/tenants?notice="+url.QueryEscape("Tenant restlos gelöscht"), http.StatusSeeOther)
}
