package httpserver

import (
	"encoding/csv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleSettingsReports(w http.ResponseWriter, r *http.Request) {
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
		s.logger.Error("settings reports load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}

	period := parseReportPeriod(r.URL.Query().Get("period"))
	view, err := s.loadSLAReport(r, period)
	if err != nil {
		s.logger.Error("settings reports load failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load report", http.StatusInternalServerError)
		return
	}

	s.render(w, "settings_reports", pageData{
		Title:        "Settings · Reports · GoUp",
		User:         user,
		IsAdmin:      sessionIsAdmin(user),
		CanWrite:     sessionCanWrite(user),
		AdminTenant:  tenant,
		AppBase:      s.tenantAppBase(r),
		SettingsMode: true,
		SLAReport:    &view,
	})
}

func (s *Server) handleSettingsReportsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	period := parseReportPeriod(r.URL.Query().Get("period"))
	view, err := s.loadSLAReport(r, period)
	if err != nil {
		s.logger.Error("settings reports export failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to export report", http.StatusInternalServerError)
		return
	}

	stamp := time.Now().UTC().Format("2006-01-02")
	filename := "goup-sla-report-" + period.Value + "-" + stamp + ".csv"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"scope", "name", "group", "uptime_percent", "incident_count", "mttr", "mttr_seconds", "monitor_count", "period", "from", "to",
	})
	writeReportCSVRow := func(row slaReportRowView) {
		mttrSeconds := ""
		if row.HasMTTR {
			mttrSeconds = strconv.FormatInt(row.MTTRSeconds, 10)
		}
		_ = cw.Write([]string{
			row.Scope,
			row.Name,
			row.Group,
			row.UptimePercent,
			strconv.Itoa(row.IncidentCount),
			row.MTTR,
			mttrSeconds,
			strconv.Itoa(row.MonitorCount),
			view.Period,
			view.FromLabel,
			view.ToLabel,
		})
	}
	writeReportCSVRow(view.Overall)
	for _, row := range view.Groups {
		writeReportCSVRow(row)
	}
	for _, row := range view.Monitors {
		writeReportCSVRow(row)
	}
	cw.Flush()
}

func (s *Server) loadSLAReport(r *http.Request, period reportPeriod) (slaReportView, error) {
	appStore, err := s.appStore(r)
	if err != nil {
		return slaReportView{}, err
	}
	now := time.Now().UTC()
	since := reportPeriodStart(now, period)

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		return slaReportView{}, err
	}
	rollups, err := appStore.ListMonitorHourlyRollupsSince(r.Context(), since.Truncate(time.Hour))
	if err != nil {
		return slaReportView{}, err
	}
	incidents, err := appStore.ListIncidentsStartedSince(r.Context(), since)
	if err != nil {
		return slaReportView{}, err
	}

	base := s.tenantAppBase(r)
	exportURL := base + "settings/reports/export?period=" + url.QueryEscape(period.Value)
	tr := s.translationsForRequest(r)
	ungrouped := strings.TrimSpace(tr["settings.reports.ungrouped"])
	if ungrouped == "" {
		ungrouped = "(ungrouped)"
	}
	overallLabel := strings.TrimSpace(tr["settings.reports.overall"])
	view := buildSLAReportView(snapshots, rollups, incidents, period, now, exportURL, ungrouped)
	if overallLabel != "" {
		view.Overall.Name = overallLabel
	}
	return view, nil
}

func (s *Server) translationsForRequest(r *http.Request) map[string]string {
	return s.translationsForLanguage(s.requestLanguage(r))
}
