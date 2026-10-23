package httpserver

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

// maintenancePastLimit bounds the "past windows" list.
const maintenancePastLimit = 20

// Maintenance window times are exchanged as UTC instants. The browser converts the
// datetime-local inputs (user's local zone, DST aware) into RFC3339 UTC strings in the hidden
// fields starts_at/ends_at before submitting (web/static/settings-maintenance.js). Without
// JavaScript the datetime-local values (starts_local/ends_local) are interpreted as UTC.
const maintenanceLocalLayout = "2006-01-02T15:04"

type maintenanceRowView struct {
	ID          int64
	Title       string
	Description string
	// StartsRaw/EndsRaw are the UTC instants of the shown occurrence (active, next or last).
	StartsRaw   string
	EndsRaw     string
	StartsLabel string
	EndsLabel   string
	// FirstStartRaw/FirstEndRaw define the series and prefill the edit form.
	FirstStartRaw string
	FirstEndRaw   string
	Recurrence    string
	Scope         string
	Targets       string
	State         string // active, upcoming, past
}

type maintenanceMonitorOption struct {
	ID       int64
	Name     string
	Group    string
	Selected bool
}

type maintenanceGroupOption struct {
	Name     string
	Selected bool
}

type maintenanceFormView struct {
	ID          int64
	Title       string
	Description string
	StartsRaw   string
	EndsRaw     string
	Recurrence  string
	Scope       string
}

// maintenanceAdminView backs the "Maintenance windows" settings page.
type maintenanceAdminView struct {
	Active   []maintenanceRowView
	Upcoming []maintenanceRowView
	Past     []maintenanceRowView
	Monitors []maintenanceMonitorOption
	Groups   []maintenanceGroupOption
	Form     maintenanceFormView
	Editing  bool
}

func maintenanceLabel(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func (s *Server) maintenanceRedirect(w http.ResponseWriter, r *http.Request, kind, message string) {
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/maintenance?"+kind+"="+url.QueryEscape(message), http.StatusSeeOther)
}

func buildMaintenanceAdminView(windows []monitor.MaintenanceWindow, snapshots []monitor.Snapshot, now time.Time, editID int64) maintenanceAdminView {
	names := make(map[int64]string, len(snapshots))
	groupSet := map[string]struct{}{}
	view := maintenanceAdminView{Form: maintenanceFormView{Recurrence: monitor.RecurrenceNone, Scope: monitor.MaintenanceScopeAll}}
	for _, snap := range snapshots {
		names[snap.Monitor.ID] = snap.Monitor.Name
		if g := strings.TrimSpace(snap.Monitor.Group); g != "" {
			groupSet[g] = struct{}{}
		}
	}

	var editing *monitor.MaintenanceWindow
	for i := range windows {
		w := windows[i]
		if w.ID == editID {
			editing = &windows[i]
		}
		start, end, active, ok := w.Occurrence(now)
		row := maintenanceRowView{
			ID: w.ID, Title: w.Title, Description: w.Description,
			FirstStartRaw: w.StartsAt.UTC().Format(time.RFC3339),
			FirstEndRaw:   w.EndsAt.UTC().Format(time.RFC3339),
			Recurrence:    w.Recurrence, Scope: w.Scope,
		}
		switch w.Scope {
		case monitor.MaintenanceScopeMonitors:
			var parts []string
			for _, id := range w.MonitorIDs {
				if name, known := names[id]; known {
					parts = append(parts, name)
				}
			}
			row.Targets = strings.Join(parts, ", ")
		case monitor.MaintenanceScopeGroups:
			row.Targets = strings.Join(w.Groups, ", ")
		}
		if !ok {
			// Finished one-off window: show its own span.
			start, end = w.StartsAt, w.EndsAt
			row.State = "past"
		} else if active {
			row.State = "active"
		} else {
			row.State = "upcoming"
		}
		row.StartsRaw, row.EndsRaw = start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339)
		row.StartsLabel, row.EndsLabel = maintenanceLabel(start), maintenanceLabel(end)
		switch row.State {
		case "active":
			view.Active = append(view.Active, row)
		case "upcoming":
			view.Upcoming = append(view.Upcoming, row)
		default:
			view.Past = append(view.Past, row)
		}
	}
	sort.SliceStable(view.Upcoming, func(i, j int) bool { return view.Upcoming[i].StartsRaw < view.Upcoming[j].StartsRaw })
	sort.SliceStable(view.Past, func(i, j int) bool { return view.Past[i].StartsRaw > view.Past[j].StartsRaw })
	if len(view.Past) > maintenancePastLimit {
		view.Past = view.Past[:maintenancePastLimit]
	}

	selectedMonitors := map[int64]bool{}
	selectedGroups := map[string]bool{}
	if editing != nil {
		view.Editing = true
		view.Form = maintenanceFormView{
			ID: editing.ID, Title: editing.Title, Description: editing.Description,
			StartsRaw: editing.StartsAt.UTC().Format(time.RFC3339), EndsRaw: editing.EndsAt.UTC().Format(time.RFC3339),
			Recurrence: editing.Recurrence, Scope: editing.Scope,
		}
		for _, id := range editing.MonitorIDs {
			selectedMonitors[id] = true
		}
		for _, g := range editing.Groups {
			selectedGroups[g] = true
		}
	}
	for _, snap := range snapshots {
		view.Monitors = append(view.Monitors, maintenanceMonitorOption{
			ID: snap.Monitor.ID, Name: snap.Monitor.Name, Group: strings.TrimSpace(snap.Monitor.Group), Selected: selectedMonitors[snap.Monitor.ID],
		})
	}
	groups := make([]string, 0, len(groupSet))
	for g := range groupSet {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		view.Groups = append(view.Groups, maintenanceGroupOption{Name: g, Selected: selectedGroups[g]})
	}
	return view
}

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
