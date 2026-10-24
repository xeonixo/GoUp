package httpserver

import (
	"bytes"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"goup/internal/version"
	"net/http"
	"strings"
	"time"
)

const (
	statusPageCacheTTL    = 30 * time.Second
	statusPageHistoryDays = 90
)

var statusPageTrendRange = trendRange{Value: "90d", Label: "90d", BucketSize: 24 * time.Hour, Buckets: statusPageHistoryDays, Step: "day"}

// statusPageBarView is one day in the 90-day uptime bar.
type statusPageBarView struct {
	Class string
	Label string
}

type statusPageMonitorView struct {
	Name        string
	StatusClass string
	StatusLabel string
	UptimeLabel string
	Bars        []statusPageBarView
}

type statusPageGroupView struct {
	Name     string
	Monitors []statusPageMonitorView
}

// statusPageMaintenanceView describes an announced or running maintenance window.
type statusPageMaintenanceView struct {
	Title    string
	StartsAt string
	EndsAt   string
}

// statusPageView is the public view model. It deliberately has no field for targets, hosts,
// URLs, error messages or latencies.
type statusPageView struct {
	Title        string
	Description  string
	OverallClass string
	OverallLabel string
	UpdatedAt    string
	Groups       []statusPageGroupView
	// MaintenanceNotices lists running and upcoming (next 7 days) maintenance windows that
	// affect at least one shown monitor. Only title and time range are public.
	MaintenanceNotices []statusPageMaintenanceView
}

func statusPageLanguage(r *http.Request) string {
	header := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language")))
	if strings.HasPrefix(header, "de") {
		return "de"
	}
	if strings.HasPrefix(header, "en") {
		return "en"
	}
	return defaultUILanguage
}

// handleStatusPage serves the public, login-free status page of a tenant at /{slug}/status.
func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID <= 0 {
		http.NotFound(w, r)
		return
	}
	lang := statusPageLanguage(r)
	key := statusPageCacheKey(tenantID, lang)
	now := time.Now()

	entry, ok := s.statusCache.get(key, now)
	if !ok {
		body, err := s.buildStatusPage(r, tenantID, lang, now)
		if err != nil {
			s.logger.Error("render status page failed", "tenant_id", tenantID, "error", err)
			http.Error(w, "status page unavailable", http.StatusInternalServerError)
			return
		}
		entry = statusPageCacheEntry{body: body, expiresAt: now.Add(statusPageCacheTTL)}
		s.statusCache.put(key, entry, now)
	}
	if entry.body == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=30")
	w.Header().Set("Vary", "Accept-Language")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(entry.body)
}

// buildStatusPage renders the page; it returns a nil body when the page is not enabled.
func (s *Server) buildStatusPage(r *http.Request, tenantID int64, lang string, now time.Time) ([]byte, error) {
	appStore, err := s.appStore(r)
	if err != nil {
		return nil, err
	}
	settings, err := appStore.GetStatusPageSettings(r.Context())
	if err != nil {
		return nil, err
	}
	if !settings.Enabled {
		return nil, nil
	}
	selected, err := appStore.ListStatusPageMonitors(r.Context())
	if err != nil {
		return nil, err
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		return nil, err
	}
	rollups, err := appStore.ListMonitorHourlyRollupsSince(r.Context(), trendRangeStart(now, statusPageTrendRange))
	if err != nil {
		s.logger.Warn("load status page rollups failed", "tenant_id", tenantID, "error", err)
		rollups = nil
	}

	tenantName := ""
	if tenant, err := s.controlStore.GetTenantByID(r.Context(), tenantID); err == nil {
		tenantName = tenant.Name
	}
	translations := s.translationsForLanguage(lang)
	view := buildStatusPageView(settings, selected, snapshots, rollups, tenantName, translations, now, appStore.MaintenanceSet(r.Context()))

	data := pageData{
		Title:        view.Title,
		UILanguage:   lang,
		Translations: translations,
		HideTopbar:   true,
		StatusPage:   &view,
		Version:      version.Version,
		AssetVersion: assetVersion(),
		ManifestURL:  "/site.webmanifest",
		AppTitle:     "GoUp",
	}
	tmpl, ok := s.templates["status_page"]
	if !ok {
		return nil, http.ErrNotSupported
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildStatusPageView(settings store.StatusPageSettings, selected []store.StatusPageMonitor, snapshots []monitor.Snapshot, rollups []store.MonitorHourlyRollup, tenantName string, tr map[string]string, now time.Time, maintenance monitor.MaintenanceSet) statusPageView {
	byID := make(map[int64]monitor.Snapshot, len(snapshots))
	for _, snap := range snapshots {
		byID[snap.Monitor.ID] = snap
	}
	rollupsByMonitor := groupRollupsByMonitor(rollups)

	view := statusPageView{
		Title:       strings.TrimSpace(settings.Title),
		Description: strings.TrimSpace(settings.Description),
		UpdatedAt:   now.UTC().Format("2006-01-02 15:04 UTC"),
	}
	if view.Title == "" {
		view.Title = strings.TrimSpace(tenantName)
	}
	if view.Title == "" {
		view.Title = "Status"
	}

	groupIndex := make(map[string]int)
	active, down, impaired, underMaintenance := 0, 0, 0, 0
	for _, item := range selected {
		snap, ok := byID[item.MonitorID]
		if !ok {
			continue
		}
		status := publicMonitorStatus(snap)
		if _, inMaintenance := maintenance.Active(snap.Monitor.ID, snap.Monitor.Group, now); inMaintenance && snap.Monitor.Enabled {
			status = "maintenance"
		}
		name := strings.TrimSpace(item.DisplayName)
		if name == "" {
			name = strings.TrimSpace(snap.Monitor.Name)
		}
		points := buildTrendPoints(rollupsByMonitor[item.MonitorID], now, statusPageTrendRange)
		mv := statusPageMonitorView{
			Name:        name,
			StatusClass: "status-" + strings.ToUpper(status),
			StatusLabel: statusPageTr(tr, "status_page.status."+status, status),
			UptimeLabel: statusPageTr(tr, "status_page.no_data", "No data"),
			Bars:        make([]statusPageBarView, 0, len(points)),
		}
		up, effective := 0, 0
		for _, p := range points {
			day := p.BucketRaw
			if len(day) >= 10 {
				day = day[:10]
			}
			label := day + " · " + statusPageTr(tr, "status_page.no_data", "No data")
			if p.Class != "trend-none" {
				label = day + " · " + formatUptimePercent(p.UpChecks, p.EffectiveChecks)
				up += p.UpChecks
				effective += p.EffectiveChecks
			}
			mv.Bars = append(mv.Bars, statusPageBarView{Class: p.Class, Label: label})
		}
		if effective > 0 {
			mv.UptimeLabel = formatUptimePercent(up, effective)
		}

		switch status {
		case "down":
			active++
			down++
		case "degraded":
			active++
			impaired++
		case "up", "unknown":
			active++
		case "maintenance":
			underMaintenance++
		}

		group := strings.TrimSpace(snap.Monitor.Group)
		idx, exists := groupIndex[group]
		if !exists {
			idx = len(view.Groups)
			groupIndex[group] = idx
			view.Groups = append(view.Groups, statusPageGroupView{Name: group})
		}
		view.Groups[idx].Monitors = append(view.Groups[idx].Monitors, mv)
	}

	switch {
	case len(view.Groups) == 0:
		view.OverallClass = "is-none"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.empty", "No services to display")
	case active == 0 && underMaintenance > 0:
		view.OverallClass = "is-maintenance"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.maintenance", "Scheduled maintenance")
	case active > 0 && down == active:
		view.OverallClass = "is-down"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.down", "Outage")
	case down > 0 || impaired > 0:
		view.OverallClass = "is-partial"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.partial", "Partial outage")
	default:
		view.OverallClass = "is-ok"
		view.OverallLabel = statusPageTr(tr, "status_page.overall.ok", "All systems operational")
	}
	view.MaintenanceNotices = buildStatusPageMaintenance(maintenance, selected, byID, now)
	return view
}

// statusPageMaintenanceHorizon is how far ahead upcoming maintenance is announced.
const statusPageMaintenanceHorizon = 7 * 24 * time.Hour

// buildStatusPageMaintenance lists the running and the next-7-days windows that cover at least
// one monitor shown on the page. Descriptions and targets are never exposed.
func buildStatusPageMaintenance(set monitor.MaintenanceSet, selected []store.StatusPageMonitor, byID map[int64]monitor.Snapshot, now time.Time) []statusPageMaintenanceView {
	var notices []statusPageMaintenanceView
	for _, occ := range set.Upcoming(now, now.Add(statusPageMaintenanceHorizon)) {
		affects := false
		for _, item := range selected {
			if snap, ok := byID[item.MonitorID]; ok && occ.Window.Covers(snap.Monitor.ID, snap.Monitor.Group) {
				affects = true
				break
			}
		}
		if !affects {
			continue
		}
		notices = append(notices, statusPageMaintenanceView{
			Title:    strings.TrimSpace(occ.Window.Title),
			StartsAt: occ.Start.UTC().Format("2006-01-02 15:04 UTC"),
			EndsAt:   occ.End.UTC().Format("2006-01-02 15:04 UTC"),
		})
	}
	return notices
}

// publicMonitorStatus maps a snapshot to up, degraded, down, unknown or paused.
func publicMonitorStatus(snap monitor.Snapshot) string {
	if !snap.Monitor.Enabled {
		return "paused"
	}
	if snap.LastResult == nil {
		return "unknown"
	}
	switch snap.LastResult.Status {
	case monitor.StatusUp:
		return "up"
	case monitor.StatusDegraded:
		return "degraded"
	case monitor.StatusDown:
		return "down"
	}
	return "unknown"
}

func statusPageTr(tr map[string]string, key, fallback string) string {
	if value := strings.TrimSpace(tr[key]); value != "" {
		return value
	}
	return fallback
}
