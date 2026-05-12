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
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ungültige Monitor-ID"), http.StatusSeeOther)
		return
	}

	enabledRaw := strings.ToLower(strings.TrimSpace(r.FormValue("enabled")))
	enabled := enabledRaw == "1" || enabledRaw == "true" || enabledRaw == "on" || enabledRaw == "yes"

	if err := appStore.SetMonitorEnabled(r.Context(), id, enabled); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor konnte nicht aktualisiert werden"), http.StatusSeeOther)
		return
	}

	message := "Monitor pausiert"
	if enabled {
		message = "Monitor aktiviert"
	}
	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape(message), http.StatusSeeOther)
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
