package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"goup/internal/monitor"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleSetMonitorEnabled(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"))
		return
	}

	if err := r.ParseForm(); err != nil {
		s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"))
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"))
		return
	}

	enabledRaw := strings.ToLower(strings.TrimSpace(r.FormValue("enabled")))
	enabled := enabledRaw == "1" || enabledRaw == "true" || enabledRaw == "on" || enabledRaw == "yes"

	if err := appStore.SetMonitorEnabled(r.Context(), id, enabled); err != nil {
		if err == sql.ErrNoRows {
			s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"))
			return
		}
		s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor konnte nicht aktualisiert werden"))
		return
	}

	message := "Monitor pausiert"
	if enabled {
		message = "Monitor aktiviert"
	}
	s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape(message))
}

// monitorMuteDurations are the mute presets offered in the dashboard.
var monitorMuteDurations = map[string]time.Duration{
	"mute_1h":  time.Hour,
	"mute_8h":  8 * time.Hour,
	"mute_24h": 24 * time.Hour,
}

// handleBulkMonitorAction applies one action (enable, pause, mute_*, unmute, maintenance_1h, delete) to one or
// more monitors. The single-monitor menu uses it as well, with a single id.
func (s *Server) handleBulkMonitorAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	base := s.tenantAppBase(r)
	appStore, err := s.appStore(r)
	if err != nil {
		s.dashboardActionRedirect(w, r, base+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.dashboardActionRedirect(w, r, base+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"))
		return
	}

	ids := make([]int64, 0, len(r.Form["id"]))
	for _, raw := range r.Form["id"] {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || id <= 0 {
			s.dashboardActionRedirect(w, r, base+"?error="+url.QueryEscape("Ungültige Monitor-ID"))
			return
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		s.dashboardActionRedirect(w, r, base+"?error="+url.QueryEscape("Keine Monitore ausgewählt"))
		return
	}

	action := strings.TrimSpace(r.FormValue("action"))
	var updated int64
	switch action {
	case "enable", "pause":
		for _, id := range ids {
			if err := appStore.SetMonitorEnabled(r.Context(), id, action == "enable"); err == nil {
				updated++
			}
		}
	case "delete":
		for _, id := range ids {
			if err := appStore.DeleteMonitor(r.Context(), id); err == nil {
				updated++
			}
		}
	case "unmute":
		updated, err = appStore.SetMonitorsMutedUntil(r.Context(), ids, nil)
	case "maintenance_1h":
		// Quick action: one-hour maintenance window for the selected monitors, starting now.
		var createdBy int64
		if user := s.currentUser(r); user != nil {
			createdBy = user.UserID
		}
		now := time.Now().UTC()
		_, err = appStore.CreateMaintenanceWindow(r.Context(), monitor.MaintenanceWindow{
			Title:      s.settingsFlash(r, "settings.maintenance.quick_title", "Quick maintenance (1 h)"),
			StartsAt:   now.Add(-time.Second),
			EndsAt:     now.Add(time.Hour),
			Recurrence: monitor.RecurrenceNone,
			Scope:      monitor.MaintenanceScopeMonitors,
			MonitorIDs: ids,
			CreatedBy:  createdBy,
		})
		if err == nil {
			updated = int64(len(ids))
			s.statusCache.invalidate()
		}
	default:
		duration, ok := monitorMuteDurations[action]
		if !ok {
			s.dashboardActionRedirect(w, r, base+"?error="+url.QueryEscape("Unbekannte Aktion"))
			return
		}
		until := time.Now().UTC().Add(duration)
		updated, err = appStore.SetMonitorsMutedUntil(r.Context(), ids, &until)
	}
	if err != nil {
		s.dashboardActionRedirect(w, r, base+"?error="+url.QueryEscape("Monitor konnte nicht aktualisiert werden"))
		return
	}
	s.writeAudit(r, "monitor.bulk."+action, "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_ids=%v updated=%d", ids, updated))
	s.dashboardActionRedirect(w, r, base+"?notice="+url.QueryEscape(fmt.Sprintf("%d Monitor(e) aktualisiert", updated)))
}

// dashboardActionRedirect finishes a dashboard action. Form posts get the usual redirect with
// notice/error query parameters; fetch requests (Accept: application/json) get the same outcome
// as localized JSON so the dashboard can update in place without a full page reload.
func (s *Server) dashboardActionRedirect(w http.ResponseWriter, r *http.Request, target string) {
	if !strings.Contains(r.Header.Get("Accept"), "application/json") {
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	query := url.Values{}
	if parsed, err := url.Parse(target); err == nil {
		query = parsed.Query()
	}
	translations := s.translationsForLanguage(s.requestLanguage(r))
	errText := localizeFlashMessage(translations, query.Get("error"))
	status := http.StatusOK
	if errText != "" {
		status = http.StatusUnprocessableEntity
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":     errText == "",
		"notice": localizeFlashMessage(translations, query.Get("notice")),
		"error":  errText,
	})
}

func checkerForMonitorKind(kind monitor.Kind) (monitor.Checker, bool) {
	switch kind {
	case monitor.KindHTTPS:
		return monitor.HTTPSChecker{}, true
	case monitor.KindTCP:
		return monitor.TCPChecker{}, true
	case monitor.KindICMP:
		return monitor.ICMPChecker{}, true
	case monitor.KindSMTP:
		return monitor.SMTPChecker{}, true
	case monitor.KindIMAP:
		return monitor.IMAPChecker{}, true
	case monitor.KindDNS:
		return monitor.DNSChecker{}, true
	case monitor.KindUDP:
		return monitor.UDPChecker{}, true
	case monitor.KindWhois:
		return monitor.WhoisChecker{}, true
	case monitor.KindHeartbeat:
		return monitor.HeartbeatChecker{}, true
	default:
		return nil, false
	}
}

func (s *Server) handleCheckMonitorNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form payload", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid monitor id", http.StatusBadRequest)
		return
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Error(w, "unable to load monitor", http.StatusInternalServerError)
		return
	}

	var selected *monitor.Snapshot
	for i := range snapshots {
		if snapshots[i].Monitor.ID == id {
			selected = &snapshots[i]
			break
		}
	}
	if selected == nil {
		http.Error(w, "monitor not found", http.StatusNotFound)
		return
	}
	if strings.EqualFold(strings.TrimSpace(selected.Monitor.ExecutorKind), "remote") {
		http.Error(w, "manual checks are disabled for remote-node monitors", http.StatusConflict)
		return
	}

	checker, ok := checkerForMonitorKind(selected.Monitor.Kind)
	if !ok {
		http.Error(w, "monitor kind is not supported", http.StatusBadRequest)
		return
	}

	runCtx, cancel := context.WithTimeout(r.Context(), selected.Monitor.Timeout+2*time.Second)
	result := checker.Check(runCtx, selected.Monitor)
	cancel()

	if err := appStore.SaveMonitorResult(r.Context(), result); err != nil {
		http.Error(w, "unable to store check result", http.StatusInternalServerError)
		return
	}
	if err := appStore.RecordMonitorState(r.Context(), selected.Monitor.ID, result.Status, result.Message, result.CheckedAt); err != nil {
		http.Error(w, "unable to store monitor state", http.StatusInternalServerError)
		return
	}
	s.writeAudit(r, "monitor.check_now", "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_id=%d", selected.Monitor.ID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK        bool   `json:"ok"`
		CheckedAt string `json:"checked_at"`
		Status    string `json:"status"`
		Message   string `json:"message"`
	}{
		OK:        true,
		CheckedAt: result.CheckedAt.UTC().Format(time.RFC3339),
		Status:    string(result.Status),
		Message:   strings.TrimSpace(result.Message),
	})
}
