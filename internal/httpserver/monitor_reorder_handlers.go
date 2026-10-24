package httpserver

import (
	"database/sql"
	"goup/internal/monitor"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleReorderMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Tenant konnte nicht aufgelöst werden"))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.dashboardActionRedirect(w, r, s.tenantAppBase(r)+"?error="+url.QueryEscape("Formular konnte nicht gelesen werden"))
		return
	}
	if draggedIDRaw := strings.TrimSpace(r.FormValue("dragged_id")); draggedIDRaw != "" {
		draggedID, parseErr := strconv.ParseInt(draggedIDRaw, 10, 64)
		targetID, targetErr := strconv.ParseInt(strings.TrimSpace(r.FormValue("target_id")), 10, 64)
		if parseErr != nil || targetErr != nil || draggedID <= 0 || targetID <= 0 {
			s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Drag&Drop-Monitor-ID"))
			return
		}
		snapshots, err := appStore.ListMonitorSnapshots(r.Context())
		if err != nil {
			s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitore konnten nicht geladen werden"))
			return
		}
		monitorViews := buildMonitorViews(snapshots, nil, time.Now().UTC(), supportedTrendRanges[0], nil, monitor.MaintenanceSet{})
		groupName := strings.TrimSpace(r.FormValue("group"))
		draggedGroupName := ""
		targetGroupName := ""
		orderedIDs := make([]int64, 0)
		for _, item := range monitorViews {
			trimmedGroup := monitorServiceLabel(item)
			if item.ID == draggedID {
				draggedGroupName = trimmedGroup
			}
			if item.ID == targetID {
				targetGroupName = trimmedGroup
			}
		}
		if draggedGroupName == "" || targetGroupName == "" {
			s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor wurde nicht gefunden"))
			return
		}
		if groupName == "" {
			groupName = draggedGroupName
		}
		if draggedGroupName != groupName || targetGroupName != groupName {
			s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitore müssen in derselben Gruppe liegen"))
			return
		}
		for _, item := range monitorViews {
			if monitorServiceLabel(item) == groupName {
				orderedIDs = append(orderedIDs, item.ID)
			}
		}
		reorderedIDs, ok := reorderMonitorIDs(orderedIDs, draggedID, targetID)
		if !ok {
			s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor konnte nicht neu einsortiert werden"))
			return
		}
		if err := appStore.ReorderMonitors(r.Context(), reorderedIDs); err != nil {
			s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()))
			return
		}
		s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Monitor sortiert", ""))
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("id")), 10, 64)
	if err != nil || id <= 0 {
		s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Monitor-ID"))
		return
	}
	groupName := strings.TrimSpace(r.FormValue("group"))
	direction := strings.TrimSpace(r.FormValue("direction"))
	if direction != "up" && direction != "down" {
		s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Ungültige Sortierrichtung"))
		return
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitore konnten nicht geladen werden"))
		return
	}
	monitorViews := buildMonitorViews(snapshots, nil, time.Now().UTC(), supportedTrendRanges[0], nil, monitor.MaintenanceSet{})
	groupItems := make([]monitorView, 0)
	for _, item := range monitorViews {
		if monitorServiceLabel(item) == groupName {
			groupItems = append(groupItems, item)
		}
	}
	sort.Slice(groupItems, func(i, j int) bool {
		if groupItems[i].SortOrder != groupItems[j].SortOrder {
			return groupItems[i].SortOrder < groupItems[j].SortOrder
		}
		return groupItems[i].ID < groupItems[j].ID
	})
	currentIndex := -1
	for idx, item := range groupItems {
		if item.ID == id {
			currentIndex = idx
			break
		}
	}
	if currentIndex == -1 {
		s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor wurde nicht gefunden"))
		return
	}
	targetIndex := currentIndex - 1
	if direction == "down" {
		targetIndex = currentIndex + 1
	}
	if targetIndex < 0 || targetIndex >= len(groupItems) {
		s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", ""))
		return
	}
	if err := appStore.SwapMonitors(r.Context(), id, groupItems[targetIndex].ID); err != nil {
		if err == sql.ErrNoRows {
			s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", "Monitor wurde nicht gefunden"))
			return
		}
		s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "", err.Error()))
		return
	}
	s.dashboardActionRedirect(w, r, s.redirectDashboardPath(r, strings.TrimSpace(r.FormValue("trend")), "Monitor sortiert", ""))
}
