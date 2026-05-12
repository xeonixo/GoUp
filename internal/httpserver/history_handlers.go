package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
)

func (s *Server) handleMonitorLatencyHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	monitorID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("monitor_id")), 10, 64)
	if err != nil || monitorID <= 0 {
		http.Error(w, "invalid monitor id", http.StatusBadRequest)
		return
	}

	rangeValue := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("range")))
	if rangeValue == "" {
		rangeValue = "1h"
	}

	now := time.Now().UTC()
	since := now.Add(-time.Hour)
	limit := 480
	switch rangeValue {
	case "6h":
		since = now.Add(-6 * time.Hour)
		limit = 2400
	case "24h":
		since = now.Add(-24 * time.Hour)
		limit = 6000
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
		limit = 24000
	default:
		rangeValue = "1h"
	}

	points, err := appStore.ListMonitorLatencyHistory(r.Context(), monitorID, since, limit)
	if err != nil {
		http.Error(w, "unable to load latency history", http.StatusInternalServerError)
		return
	}

	type latencyPointPayload struct {
		CheckedAt string `json:"checked_at"`
		LatencyMS int    `json:"latency_ms"`
		Status    string `json:"status"`
	}
	responsePoints := make([]latencyPointPayload, 0, len(points))
	latencySum := 0
	latencyCount := 0
	for _, point := range points {
		responsePoints = append(responsePoints, latencyPointPayload{
			CheckedAt: point.CheckedAt.UTC().Format(time.RFC3339),
			LatencyMS: point.LatencyMS,
			Status:    strings.TrimSpace(point.Status),
		})
		if !strings.EqualFold(strings.TrimSpace(point.Status), string(monitor.StatusDown)) && point.LatencyMS >= 0 {
			latencySum += point.LatencyMS
			latencyCount++
		}
	}

	averageMS := 0
	if latencyCount > 0 {
		averageMS = int(float64(latencySum)/float64(latencyCount) + 0.5)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK        bool                  `json:"ok"`
		MonitorID int64                 `json:"monitor_id"`
		Range     string                `json:"range"`
		AverageMS int                   `json:"average_ms"`
		Points    []latencyPointPayload `json:"points"`
	}{
		OK:        true,
		MonitorID: monitorID,
		Range:     rangeValue,
		AverageMS: averageMS,
		Points:    responsePoints,
	})
}

func (s *Server) handleStateEventsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	const pageSize = 50
	page := 1
	if p, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page"))); err == nil && p > 1 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := appStore.CountMonitorStateEvents(r.Context())
	if err != nil {
		s.logger.Warn("count monitor state events failed", "error", err)
		total = 0
	}

	events, err := appStore.ListMonitorStateEventsPaginated(r.Context(), pageSize, offset)
	if err != nil {
		s.logger.Warn("load monitor state events history failed", "error", err)
		events = nil
	}

	pageCount := 1
	if total > 0 {
		pageCount = int((total + pageSize - 1) / pageSize)
	}
	if page > pageCount {
		page = pageCount
	}

	baseURL := s.tenantAppBase(r) + "state-events"

	curUser := s.currentUser(r)
	lang := defaultUILanguage
	if curUser != nil {
		lang = normalizeUILanguage(curUser.PreferredLanguage)
	}
	translations := s.translationsForLanguage(lang)

	subtitle := strings.ReplaceAll(translations["dashboard.state_events.history_subtitle"], "{total}", fmt.Sprintf("%d", total))
	pageLabel := strings.ReplaceAll(strings.ReplaceAll(translations["dashboard.state_events.page_of"], "{page}", fmt.Sprintf("%d", page)), "{total}", fmt.Sprintf("%d", pageCount))

	data := pageData{
		Title:                      "Statusänderungen · GoUp",
		UILanguage:                 lang,
		Translations:               translations,
		AppBase:                    s.tenantAppBase(r),
		User:                       curUser,
		IsAdmin:                    curUser == nil || strings.EqualFold(strings.TrimSpace(curUser.Role), "admin"),
		StateEvents:                buildMonitorStateEventViews(events),
		StateEventHistorySubtitle:  subtitle,
		StateEventHistoryPageLabel: pageLabel,
		Pagination: paginationView{
			Page:      page,
			PageCount: pageCount,
			Total:     total,
			HasPrev:   page > 1,
			HasNext:   page < pageCount,
			PrevPage:  page - 1,
			NextPage:  page + 1,
			BaseURL:   baseURL,
		},
	}
	s.render(w, "state_events_history", data)
}

func (s *Server) handleNotificationEventsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	const pageSize = 50
	page := 1
	if p, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page"))); err == nil && p > 1 {
		page = p
	}
	offset := (page - 1) * pageSize

	total, err := appStore.CountNotificationEvents(r.Context())
	if err != nil {
		s.logger.Warn("count notification events failed", "error", err)
		total = 0
	}

	events, err := appStore.ListNotificationEventsPaginated(r.Context(), pageSize, offset)
	if err != nil {
		s.logger.Warn("load notification events history failed", "error", err)
		events = nil
	}

	pageCount := 1
	if total > 0 {
		pageCount = int((total + pageSize - 1) / pageSize)
	}
	if page > pageCount {
		page = pageCount
	}

	baseURL := s.tenantAppBase(r) + "notification-events"

	curUser := s.currentUser(r)
	lang := defaultUILanguage
	if curUser != nil {
		lang = normalizeUILanguage(curUser.PreferredLanguage)
	}
	translations := s.translationsForLanguage(lang)

	subtitle := strings.ReplaceAll(translations["dashboard.notification_events.history_subtitle"], "{total}", fmt.Sprintf("%d", total))
	pageLabel := strings.ReplaceAll(strings.ReplaceAll(translations["dashboard.notification_events.page_of"], "{page}", fmt.Sprintf("%d", page)), "{total}", fmt.Sprintf("%d", pageCount))

	data := pageData{
		Title:                             "Notification-Events · GoUp",
		UILanguage:                        lang,
		Translations:                      translations,
		AppBase:                           s.tenantAppBase(r),
		User:                              curUser,
		IsAdmin:                           curUser == nil || strings.EqualFold(strings.TrimSpace(curUser.Role), "admin"),
		Events:                            buildNotificationEventViews(events),
		NotificationEventHistorySubtitle:  subtitle,
		NotificationEventHistoryPageLabel: pageLabel,
		Pagination: paginationView{
			Page:      page,
			PageCount: pageCount,
			Total:     total,
			HasPrev:   page > 1,
			HasNext:   page < pageCount,
			PrevPage:  page - 1,
			NextPage:  page + 1,
			BaseURL:   baseURL,
		},
	}
	s.render(w, "notification_events_history", data)
}
