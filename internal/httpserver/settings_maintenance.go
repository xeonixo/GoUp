package httpserver

import (
	"database/sql"
	"errors"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maintenancePastLimit bounds the "past windows" list.
const maintenancePastLimit = 20

// Maintenance window times are exchanged as UTC instants. The browser converts the
// datetime-local inputs (user's local zone, DST aware) into RFC3339 UTC strings in the hidden
// fields starts_at/ends_at before submitting (web/static/settings-maintenance.js). Without
// JavaScript the datetime-local values (starts_local/ends_local) are interpreted as UTC.
const maintenanceLocalLayout = "2006-01-02T15:04"

func (s *Server) handleSettingsMaintenance(w http.ResponseWriter, r *http.Request) {
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
		s.logger.Error("settings maintenance load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}
	windows, err := appStore.ListMaintenanceWindows(r.Context())
	if err != nil {
		s.logger.Error("settings maintenance list failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load maintenance windows", http.StatusInternalServerError)
		return
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Error(w, "unable to load monitors", http.StatusInternalServerError)
		return
	}
	editID, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("edit")), 10, 64)
	view := buildMaintenanceAdminView(windows, snapshots, time.Now().UTC(), editID)
	s.render(w, "settings_maintenance", pageData{
		Title:          "Einstellungen · Wartungsfenster · GoUp",
		User:           user,
		AdminTenant:    tenant,
		AppBase:        s.tenantAppBase(r),
		Notice:         strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:          strings.TrimSpace(r.URL.Query().Get("error")),
		SettingsMode:   true,
		MaintenanceAdm: &view,
	})
}

// parseMaintenanceInstant reads a UTC instant from the RFC3339 field, falling back to the raw
// datetime-local value (interpreted as UTC) when JavaScript did not fill the hidden field.
func parseMaintenanceInstant(r *http.Request, utcField, localField string) time.Time {
	if raw := strings.TrimSpace(r.FormValue(utcField)); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t.UTC()
		}
		return time.Time{}
	}
	if raw := strings.TrimSpace(r.FormValue(localField)); raw != "" {
		if t, err := time.Parse(maintenanceLocalLayout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func (s *Server) maintenanceErrorMessage(r *http.Request, err error) string {
	key, fallback := "settings.maintenance.error_save", "Maintenance window could not be saved"
	switch {
	case errors.Is(err, store.ErrMaintenanceTitle):
		key, fallback = "settings.maintenance.error_title", "A title (max. 120 characters) is required"
	case errors.Is(err, store.ErrMaintenanceText):
		key, fallback = "settings.maintenance.error_description", "The description is too long"
	case errors.Is(err, store.ErrMaintenanceTimes):
		key, fallback = "settings.maintenance.error_times", "Start and end are required"
	case errors.Is(err, store.ErrMaintenanceOrder):
		key, fallback = "settings.maintenance.error_order", "The end must be after the start"
	case errors.Is(err, store.ErrMaintenanceTooLong):
		key, fallback = "settings.maintenance.error_too_long", "A recurring window must not be longer than its period (24 hours daily, 7 days weekly)"
	case errors.Is(err, store.ErrMaintenanceTargets):
		key, fallback = "settings.maintenance.error_targets", "Select at least one monitor or group"
	}
	return s.settingsFlash(r, key, fallback)
}

func (s *Server) handleSettingsMaintenanceSave(w http.ResponseWriter, r *http.Request) {
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
		s.maintenanceRedirect(w, r, "error", s.maintenanceErrorMessage(r, err))
		return
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		s.maintenanceRedirect(w, r, "error", s.maintenanceErrorMessage(r, err))
		return
	}

	window := monitor.MaintenanceWindow{
		Title:       strings.TrimSpace(r.FormValue("title")),
		Description: strings.TrimSpace(r.FormValue("description")),
		StartsAt:    parseMaintenanceInstant(r, "starts_at", "starts_local"),
		EndsAt:      parseMaintenanceInstant(r, "ends_at", "ends_local"),
		Recurrence:  monitor.NormalizeRecurrence(r.FormValue("recurrence")),
		Scope:       monitor.NormalizeMaintenanceScope(r.FormValue("scope")),
		CreatedBy:   user.UserID,
	}
	known := make(map[int64]bool, len(snapshots))
	groups := map[string]bool{}
	for _, snap := range snapshots {
		known[snap.Monitor.ID] = true
		groups[strings.TrimSpace(snap.Monitor.Group)] = true
	}
	switch window.Scope {
	case monitor.MaintenanceScopeMonitors:
		for _, raw := range r.Form["monitor_id"] {
			if id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil && known[id] {
				window.MonitorIDs = append(window.MonitorIDs, id)
			}
		}
	case monitor.MaintenanceScopeGroups:
		for _, raw := range r.Form["group"] {
			if g := strings.TrimSpace(raw); g != "" && groups[g] {
				window.Groups = append(window.Groups, g)
			}
		}
	}

	id, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	action := "tenant.maintenance.create"
	if id > 0 {
		window.ID = id
		action = "tenant.maintenance.update"
		err = appStore.UpdateMaintenanceWindow(r.Context(), window)
	} else {
		id, err = appStore.CreateMaintenanceWindow(r.Context(), window)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.maintenanceRedirect(w, r, "error", s.settingsFlash(r, "settings.maintenance.error_not_found", "Maintenance window not found"))
			return
		}
		s.logger.Warn("settings maintenance save failed", "tenant_id", user.TenantID, "error", err)
		s.maintenanceRedirect(w, r, "error", s.maintenanceErrorMessage(r, err))
		return
	}
	s.statusCache.invalidate()
	s.writeAudit(r, action, "tenant", user.TenantID, "window_id="+strconv.FormatInt(id, 10)+" scope="+window.Scope+" recurrence="+window.Recurrence)
	s.maintenanceRedirect(w, r, "notice", s.settingsFlash(r, "settings.maintenance.saved", "Maintenance window saved"))
}

func (s *Server) handleSettingsMaintenanceDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid maintenance id", http.StatusBadRequest)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}
	if err := appStore.DeleteMaintenanceWindow(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.maintenanceRedirect(w, r, "error", s.settingsFlash(r, "settings.maintenance.error_not_found", "Maintenance window not found"))
			return
		}
		s.logger.Warn("settings maintenance delete failed", "tenant_id", user.TenantID, "error", err)
		s.maintenanceRedirect(w, r, "error", s.settingsFlash(r, "settings.maintenance.error_save", "Maintenance window could not be deleted"))
		return
	}
	s.statusCache.invalidate()
	s.writeAudit(r, "tenant.maintenance.delete", "tenant", user.TenantID, "window_id="+strconv.FormatInt(id, 10))
	s.maintenanceRedirect(w, r, "notice", s.settingsFlash(r, "settings.maintenance.deleted", "Maintenance window deleted"))
}

// Rows lists active, upcoming and past windows in that order.
func (v maintenanceAdminView) Rows() []maintenanceRowView {
	rows := make([]maintenanceRowView, 0, len(v.Active)+len(v.Upcoming)+len(v.Past))
	rows = append(rows, v.Active...)
	rows = append(rows, v.Upcoming...)
	return append(rows, v.Past...)
}
