package httpserver

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (s *Server) handleDeleteMonitor(w http.ResponseWriter, r *http.Request) {
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

	err = appStore.DeleteMonitor(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"))
			return
		}
		s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor konnte nicht gelöscht werden"))
		return
	}

	s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape("Monitor gelöscht"))
}

func (s *Server) handleUpdateMonitorTarget(w http.ResponseWriter, r *http.Request) {
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

	target := strings.TrimSpace(r.FormValue("target"))
	if target == "" {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Ziel darf nicht leer sein"), http.StatusSeeOther)
		return
	}

	err = appStore.UpdateMonitorTarget(r.Context(), id, target)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Monitor wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "monitor.target.update", "tenant", tenantIDFromRequest(r), fmt.Sprintf("monitor_id=%d", id))

	http.Redirect(w, r, s.tenantAppBase(r)+"?notice="+url.QueryEscape("Monitor-Ziel aktualisiert"), http.StatusSeeOther)
}
