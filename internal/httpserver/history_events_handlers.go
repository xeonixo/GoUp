package httpserver

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

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
