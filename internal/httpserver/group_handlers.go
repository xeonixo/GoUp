package httpserver

import (
	"database/sql"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) handleSaveGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, groupIconUploadMaxBytes+(1<<20))
	if err := r.ParseMultipartForm(groupIconUploadMaxBytes + (256 << 10)); err != nil && err != http.ErrNotMultipart {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	newGroupName := strings.TrimSpace(r.FormValue("new_name"))
	if newGroupName == "" {
		newGroupName = groupName
	}
	if newGroupName != groupName {
		if err := appStore.RenameMonitorGroup(r.Context(), groupName, newGroupName); err != nil {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe konnte nicht umbenannt werden: "+err.Error()), http.StatusSeeOther)
			return
		}
		groupName = newGroupName
	}
	iconRef := normalizeGroupIconReference(strings.TrimSpace(r.FormValue("icon_slug")))
	uploadedIconRef, err := s.storeUploadedGroupIcon(r, groupName)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	if uploadedIconRef != "" {
		iconRef = uploadedIconRef
	} else if err := s.persistSelectedDashboardIcon(r.Context(), s.tenantSlugForRequest(r), iconRef); err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	if err := appStore.UpdateMonitorGroupIcon(r.Context(), groupName, iconRef); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe gespeichert", ""), http.StatusSeeOther)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	if err := appStore.DeleteMonitorGroup(r.Context(), groupName); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe konnte nicht gelöscht werden"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe inkl. Monitore gelöscht", ""), http.StatusSeeOther)
}

func (s *Server) handleReorderGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"), http.StatusSeeOther)
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	if draggedGroup := strings.TrimSpace(r.FormValue("dragged_group")); draggedGroup != "" {
		targetGroup := strings.TrimSpace(r.FormValue("target_group"))
		if err := appStore.ReorderMonitorGroups(r.Context(), draggedGroup, targetGroup); err != nil {
			if err == sql.ErrNoRows {
				http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe sortiert", ""), http.StatusSeeOther)
		return
	}
	if groupName == "" {
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Gruppe"), http.StatusSeeOther)
		return
	}
	direction := strings.TrimSpace(r.FormValue("direction"))
	if err := appStore.MoveMonitorGroup(r.Context(), groupName, direction); err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Gruppe wurde nicht gefunden"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Gruppe sortiert", ""), http.StatusSeeOther)
}
