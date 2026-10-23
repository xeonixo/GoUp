package httpserver

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type uptimeTileView struct {
	Label      string
	Percent    string
	Checks     int
	AvgLatency string
	Class      string
}

type latencyChartView struct {
	HasData    bool
	Polyline   string
	Width      int
	Height     int
	MaxLabel   string
	MidLabel   string
	StartLabel string
	EndLabel   string
}

type incidentView struct {
	Started  string
	Resolved string
	Duration string
	Cause    string
	Open     bool
}

type monitorDetailView struct {
	Monitor   monitorView
	Uptime    []uptimeTileView
	DayBars   []trendPointView
	Latency   latencyChartView
	Incidents []incidentView
}

// detailDayRange drives the 90-day uptime bars on the monitor detail page.
var detailDayRange = trendRange{Value: "90d", Label: "90d", BucketSize: 24 * time.Hour, Buckets: 90, Step: "day"}

func (s *Server) handleMonitorDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	monitorID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || monitorID <= 0 {
		http.NotFound(w, r)
		return
	}
	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Error(w, "unable to load monitor", http.StatusInternalServerError)
		return
	}
	var snapshot *monitor.Snapshot
	for i := range snapshots {
		if snapshots[i].Monitor.ID == monitorID {
			snapshot = &snapshots[i]
			break
		}
	}
	if snapshot == nil {
		http.NotFound(w, r)
		return
	}

	now := time.Now().UTC()
	rollups, err := appStore.ListMonitorHourlyRollupsForMonitorSince(r.Context(), monitorID, now.Truncate(24*time.Hour).AddDate(0, 0, -365))
	if err != nil {
		http.Error(w, "unable to load monitor history", http.StatusInternalServerError)
		return
	}
	incidents, err := appStore.ListMonitorIncidents(r.Context(), monitorID, 20)
	if err != nil {
		s.logger.Warn("load monitor incidents failed", "monitor_id", monitorID, "error", err)
	}

	lang := s.requestLanguage(r)
	translations := s.translationsForLanguage(lang)
	curUser := s.currentUser(r)
	views := buildMonitorViews([]monitor.Snapshot{*snapshot}, rollups, now, supportedTrendRanges[0], nil)

	detail := &monitorDetailView{
		Monitor:   views[0],
		Uptime:    buildUptimeTiles(rollups, now, translations),
		DayBars:   buildTrendPoints(rollups, now, detailDayRange),
		Latency:   buildLatencyChart(aggregateDailyLatency(rollups)),
		Incidents: buildIncidentViews(incidents, now),
	}
	for i := range detail.DayBars {
		if day, err := time.Parse(time.RFC3339, detail.DayBars[i].BucketRaw); err == nil {
			detail.DayBars[i].Label = day.Format("2006-01-02") + " · " + detail.DayBars[i].Label
		}
	}

	s.render(w, "monitor_detail", pageData{
		Title:         detail.Monitor.Name + " · GoUp",
		UILanguage:    lang,
		Translations:  translations,
		AppBase:       s.tenantAppBase(r),
		User:          curUser,
		IsAdmin:       curUser == nil || strings.EqualFold(strings.TrimSpace(curUser.Role), "admin"),
		MonitorDetail: detail,
	})
}

// buildUptimeTiles sums the hourly rollups (oldest first) over the usual reporting windows.
func buildUptimeTiles(rollups []store.MonitorHourlyRollup, now time.Time, translations map[string]string) []uptimeTileView {
	windows := []struct {
		key      string
		fallback string
		since    time.Time
	}{
		{"monitor_detail.window_24h", "24 hours", now.Add(-24 * time.Hour)},
		{"monitor_detail.window_7d", "7 days", now.AddDate(0, 0, -7)},
		{"monitor_detail.window_30d", "30 days", now.AddDate(0, 0, -30)},
		{"monitor_detail.window_365d", "365 days", now.AddDate(0, 0, -365)},
	}
	tiles := make([]uptimeTileView, 0, len(windows))
	for _, window := range windows {
		total, up, latencyChecks, latencySum := 0, 0, 0, 0
		for _, rollup := range rollups {
			if rollup.HourBucket.Before(window.since.Truncate(time.Hour)) {
				continue
			}
			total += rollup.TotalChecks
			up += rollup.UpChecks
			latencyChecks += rollup.UpChecks + rollup.DegradedChecks
			latencySum += rollup.LatencySumMS
		}
		label := strings.TrimSpace(translations[window.key])
		if label == "" {
			label = window.fallback
		}
		tile := uptimeTileView{Label: label, Percent: "—", AvgLatency: "—", Class: "uptime-none", Checks: total}
		if total > 0 {
			percent := float64(up) / float64(total) * 100
			tile.Percent = strconv.FormatFloat(percent, 'f', 2, 64) + "%"
			switch {
			case percent >= 99.9:
				tile.Class = "uptime-good"
			case percent >= 95:
				tile.Class = "uptime-warn"
			default:
				tile.Class = "uptime-bad"
			}
		}
		if latencyChecks > 0 {
			tile.AvgLatency = fmt.Sprintf("%d ms", latencySum/latencyChecks)
		}
		tiles = append(tiles, tile)
	}
	return tiles
}

// buildLatencyChart turns daily latency points into an SVG polyline (x = day, y = average latency).
func buildLatencyChart(points []aggregatedLatencyPoint) latencyChartView {
	chart := latencyChartView{Width: 730, Height: 160}
	maxMS := 0
	withLatency := make([]aggregatedLatencyPoint, 0, len(points))
	for _, point := range points {
		if point.LatencyChecks == 0 {
			continue
		}
		withLatency = append(withLatency, point)
		if point.LatencyMS > maxMS {
			maxMS = point.LatencyMS
		}
	}
	if len(withLatency) < 2 || maxMS == 0 {
		return chart
	}

	first, errFirst := time.Parse(time.RFC3339, withLatency[0].CheckedAt)
	last, errLast := time.Parse(time.RFC3339, withLatency[len(withLatency)-1].CheckedAt)
	if errFirst != nil || errLast != nil || !last.After(first) {
		return chart
	}
	span := last.Sub(first).Hours()
	coords := make([]string, 0, len(withLatency))
	for _, point := range withLatency {
		at, err := time.Parse(time.RFC3339, point.CheckedAt)
		if err != nil {
			continue
		}
		x := at.Sub(first).Hours() / span * float64(chart.Width)
		y := float64(chart.Height) - float64(point.LatencyMS)/float64(maxMS)*float64(chart.Height-8)
		coords = append(coords, fmt.Sprintf("%.1f,%.1f", x, y))
	}
	chart.HasData = true
	chart.Polyline = strings.Join(coords, " ")
	chart.MaxLabel = fmt.Sprintf("%d ms", maxMS)
	chart.MidLabel = fmt.Sprintf("%d ms", maxMS/2)
	chart.StartLabel = first.Format("2006-01-02")
	chart.EndLabel = last.Format("2006-01-02")
	return chart
}

func buildIncidentViews(items []store.MonitorIncident, now time.Time) []incidentView {
	views := make([]incidentView, 0, len(items))
	for _, item := range items {
		end := now
		view := incidentView{
			Started: item.StartedAt.UTC().Format("2006-01-02 15:04 UTC"),
			Cause:   strings.TrimSpace(item.Cause),
			Open:    item.ResolvedAt == nil,
		}
		if item.ResolvedAt != nil {
			end = *item.ResolvedAt
			view.Resolved = item.ResolvedAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		view.Duration = formatIncidentDuration(end.Sub(item.StartedAt))
		views = append(views, view)
	}
	return views
}

func formatIncidentDuration(d time.Duration) string {
	d = d.Truncate(time.Minute)
	if d < time.Minute {
		return "<1m"
	}
	days := int(d / (24 * time.Hour))
	hours := int(d % (24 * time.Hour) / time.Hour)
	minutes := int(d % time.Hour / time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	default:
		return fmt.Sprintf("%dm", minutes)
	}
}
