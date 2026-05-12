package httpserver

import (
	"goup/internal/config"
	store "goup/internal/store/sqlite"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	data, err := s.loadDashboardPageData(r, appStore, strings.TrimSpace(r.URL.Query().Get("trend")), strings.TrimSpace(r.URL.Query().Get("notice")), strings.TrimSpace(r.URL.Query().Get("error")))
	if err != nil {
		http.Error(w, "unable to load dashboard", http.StatusInternalServerError)
		return
	}

	s.render(w, "dashboard", data)
}

func (s *Server) loadDashboardPageData(r *http.Request, appStore *store.Store, trendValue string, noticeText string, errorText string) (pageData, error) {
	stats, err := appStore.DashboardStats(r.Context())
	if err != nil {
		return pageData{}, err
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		return pageData{}, err
	}

	events, err := appStore.ListRecentNotificationEvents(r.Context(), 100)
	if err != nil {
		s.logger.Warn("load notification events failed", "error", err)
		events = nil
	}

	stateEvents, err := appStore.ListRecentMonitorStateEvents(r.Context(), 200)
	if err != nil {
		s.logger.Warn("load monitor state events failed", "error", err)
		stateEvents = nil
	}

	groupMetadata, err := appStore.ListMonitorGroupMetadata(r.Context())
	if err != nil {
		return pageData{}, err
	}

	now := time.Now().UTC()
	selectedTrend := parseTrendRange(strings.TrimSpace(trendValue))
	trendSince := trendRangeStart(now, selectedTrend)
	rollups, err := appStore.ListMonitorHourlyRollupsSince(r.Context(), trendSince)
	if err != nil {
		s.logger.Warn("load monitor trends failed", "error", err)
		rollups = nil
	}

	tenantID := tenantIDFromRequest(r)
	remoteNodes, err := s.controlStore.ListRemoteNodesByTenant(r.Context(), tenantID)
	if err != nil {
		s.logger.Warn("load remote nodes failed", "tenant_id", tenantID, "error", err)
		remoteNodes = nil
	}
	monitorViews := buildMonitorViews(snapshots, rollups, now, selectedTrend, buildRemoteNodeNameMap(remoteNodes))
	availableGroups := buildAvailableGroups(groupMetadata)
	availableGroups = mergeAvailableGroups(availableGroups, monitorViews)
	remoteNodeViews := buildRemoteNodeViews(remoteNodes, now, s.cfg.BaseURL, nil)
	executorOptions := buildMonitorExecutorOptions(remoteNodes)

	curUser := s.currentUser(r)
	preferredLanguage := defaultUILanguage
	if curUser != nil {
		preferredLanguage = normalizeUILanguage(curUser.PreferredLanguage)
		if strings.TrimSpace(curUser.PreferredLanguage) == "" {
			preferredLanguage = detectPreferredLanguage(r)
		}
	} else {
		preferredLanguage = detectPreferredLanguage(r)
	}
	translations := s.translationsForLanguage(preferredLanguage)
	noticeLocalized := localizeFlashMessage(translations, noticeText)
	errorLocalized := localizeFlashMessage(translations, errorText)

	return pageData{
		Title:            "Dashboard · GoUp",
		User:             curUser,
		UILanguage:       preferredLanguage,
		Translations:     translations,
		IsAdmin:          curUser == nil || strings.EqualFold(strings.TrimSpace(curUser.Role), "admin"),
		Stats:            stats,
		Notice:           noticeLocalized,
		Error:            errorLocalized,
		AuthEnabled:      s.cfg.Auth.Mode == config.AuthModeOIDC,
		AuthDisabled:     s.cfg.Auth.Mode != config.AuthModeOIDC,
		TrendValue:       selectedTrend.Value,
		TrendLabel:       selectedTrend.Label,
		TrendRanges:      buildTrendRangeOptions(selectedTrend),
		Monitors:         monitorViews,
		MonitorGroups:    buildMonitorGroups(s.tenantAppBase(r), monitorViews, groupMetadata),
		AvailableGroups:  availableGroups,
		RemoteNodes:      remoteNodeViews,
		HasRemoteNodes:   len(executorOptions) > 1,
		MonitorExecutors: executorOptions,
		Events:           buildNotificationEventViews(events),
		StateEvents:      buildMonitorStateEventViews(stateEvents),
		AppBase:          s.tenantAppBase(r),
	}, nil
}
