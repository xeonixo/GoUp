package httpserver

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type reportPeriod struct {
	Value string
	Days  int
	Label string
}

var supportedReportPeriods = []reportPeriod{
	{Value: "7d", Days: 7, Label: "7d"},
	{Value: "30d", Days: 30, Label: "30d"},
	{Value: "90d", Days: 90, Label: "90d"},
}

func parseReportPeriod(value string) reportPeriod {
	value = strings.TrimSpace(strings.ToLower(value))
	for _, item := range supportedReportPeriods {
		if item.Value == value {
			return item
		}
	}
	return supportedReportPeriods[1] // 30d default
}

func reportPeriodStart(now time.Time, period reportPeriod) time.Time {
	return now.UTC().AddDate(0, 0, -period.Days)
}

func buildReportPeriodOptions(selected reportPeriod) []trendRangeOptionView {
	items := make([]trendRangeOptionView, 0, len(supportedReportPeriods))
	for _, item := range supportedReportPeriods {
		items = append(items, trendRangeOptionView{
			Value:    item.Value,
			Label:    item.Label,
			Selected: item.Value == selected.Value,
		})
	}
	return items
}

// sumRollupUptime totals up and effective checks from hourly rollups (unknown/maintenance excluded).
func sumRollupUptime(rollups []store.MonitorHourlyRollup) (up, effective int) {
	for _, item := range rollups {
		up += item.UpChecks
		effective += item.EffectiveChecks()
	}
	return up, effective
}

type incidentDuration struct {
	StartedAt  time.Time
	ResolvedAt *time.Time
}

// averageMTTR is the mean time-to-resolve over resolved incidents. Open incidents are ignored.
// Returns ok=false when there are no resolved incidents.
func averageMTTR(incidents []incidentDuration) (time.Duration, bool) {
	var total time.Duration
	count := 0
	for _, item := range incidents {
		if item.ResolvedAt == nil || item.ResolvedAt.IsZero() || item.StartedAt.IsZero() {
			continue
		}
		d := item.ResolvedAt.Sub(item.StartedAt)
		if d < 0 {
			continue
		}
		total += d
		count++
	}
	if count == 0 {
		return 0, false
	}
	return total / time.Duration(count), true
}

func formatReportDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		m, s := int(d.Minutes()), int(d.Seconds())%60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	case d < 48*time.Hour:
		h, m := int(d.Hours()), int(d.Minutes())%60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	default:
		days := int(d.Hours()) / 24
		h := int(d.Hours()) % 24
		if h == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd %dh", days, h)
	}
}

func formatReportMTTR(d time.Duration, ok bool) string {
	if !ok {
		return "—"
	}
	return formatReportDuration(d)
}

func formatReportUptime(up, effective int) string {
	if effective <= 0 {
		return "—"
	}
	return formatUptimePercent(up, effective)
}

func reportUptimeClass(up, effective int) string {
	if effective <= 0 {
		return "uptime-none"
	}
	percent := float64(uptimeBasisPoints(up, effective)) / 100
	switch {
	case percent >= 99.9:
		return "uptime-good"
	case percent >= 95:
		return "uptime-warn"
	default:
		return "uptime-bad"
	}
}

type slaReportRowView struct {
	Scope         string
	Name          string
	Group         string
	UptimePercent string
	UptimeClass   string
	IncidentCount int
	MTTR          string
	MonitorCount  int
	UpChecks      int
	Effective     int
	MTTRSeconds   int64
	HasMTTR       bool
}

type slaReportView struct {
	Period        string
	PeriodOptions []trendRangeOptionView
	PeriodLabel   string
	FromLabel     string
	ToLabel       string
	Monitors      []slaReportRowView
	Groups        []slaReportRowView
	Overall       slaReportRowView
	ExportURL     string
	HasData       bool
}

func buildSLAReportView(
	snapshots []monitor.Snapshot,
	rollups []store.MonitorHourlyRollup,
	incidents []store.IncidentReportRow,
	period reportPeriod,
	now time.Time,
	exportURL string,
	ungroupedLabel string,
) slaReportView {
	since := reportPeriodStart(now, period)
	rollupsByMonitor := groupRollupsByMonitor(rollups)
	incidentsByMonitor := make(map[int64][]incidentDuration)
	for _, item := range incidents {
		incidentsByMonitor[item.MonitorID] = append(incidentsByMonitor[item.MonitorID], incidentDuration{
			StartedAt:  item.StartedAt,
			ResolvedAt: item.ResolvedAt,
		})
	}

	type monitorMeta struct {
		ID    int64
		Name  string
		Group string
	}
	monitors := make([]monitorMeta, 0, len(snapshots))
	for _, snap := range snapshots {
		monitors = append(monitors, monitorMeta{
			ID:    snap.Monitor.ID,
			Name:  strings.TrimSpace(snap.Monitor.Name),
			Group: strings.TrimSpace(snap.Monitor.Group),
		})
	}
	sort.SliceStable(monitors, func(i, j int) bool {
		if monitors[i].Group != monitors[j].Group {
			return monitors[i].Group < monitors[j].Group
		}
		if monitors[i].Name != monitors[j].Name {
			return monitors[i].Name < monitors[j].Name
		}
		return monitors[i].ID < monitors[j].ID
	})

	if strings.TrimSpace(ungroupedLabel) == "" {
		ungroupedLabel = "(ungrouped)"
	}

	monitorRows := make([]slaReportRowView, 0, len(monitors))
	type groupAgg struct {
		up, effective, incidents int
		durations                []incidentDuration
		count                    int
	}
	groups := make(map[string]*groupAgg)
	var overallUp, overallEffective, overallIncidents int
	var overallDurations []incidentDuration

	for _, meta := range monitors {
		up, effective := sumRollupUptime(rollupsByMonitor[meta.ID])
		durs := incidentsByMonitor[meta.ID]
		mttr, hasMTTR := averageMTTR(durs)
		groupName := meta.Group
		displayGroup := groupName
		if displayGroup == "" {
			displayGroup = ungroupedLabel
		}
		row := slaReportRowView{
			Scope:         "monitor",
			Name:          meta.Name,
			Group:         displayGroup,
			UptimePercent: formatReportUptime(up, effective),
			UptimeClass:   reportUptimeClass(up, effective),
			IncidentCount: len(durs),
			MTTR:          formatReportMTTR(mttr, hasMTTR),
			MonitorCount:  1,
			UpChecks:      up,
			Effective:     effective,
			HasMTTR:       hasMTTR,
		}
		if hasMTTR {
			row.MTTRSeconds = int64(mttr / time.Second)
		}
		monitorRows = append(monitorRows, row)

		key := groupName
		agg := groups[key]
		if agg == nil {
			agg = &groupAgg{}
			groups[key] = agg
		}
		agg.up += up
		agg.effective += effective
		agg.incidents += len(durs)
		agg.durations = append(agg.durations, durs...)
		agg.count++

		overallUp += up
		overallEffective += effective
		overallIncidents += len(durs)
		overallDurations = append(overallDurations, durs...)
	}

	groupNames := make([]string, 0, len(groups))
	for name := range groups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)

	groupRows := make([]slaReportRowView, 0, len(groupNames))
	for _, name := range groupNames {
		agg := groups[name]
		mttr, hasMTTR := averageMTTR(agg.durations)
		display := name
		if display == "" {
			display = ungroupedLabel
		}
		row := slaReportRowView{
			Scope:         "group",
			Name:          display,
			Group:         display,
			UptimePercent: formatReportUptime(agg.up, agg.effective),
			UptimeClass:   reportUptimeClass(agg.up, agg.effective),
			IncidentCount: agg.incidents,
			MTTR:          formatReportMTTR(mttr, hasMTTR),
			MonitorCount:  agg.count,
			UpChecks:      agg.up,
			Effective:     agg.effective,
			HasMTTR:       hasMTTR,
		}
		if hasMTTR {
			row.MTTRSeconds = int64(mttr / time.Second)
		}
		groupRows = append(groupRows, row)
	}

	overallMTTR, overallHasMTTR := averageMTTR(overallDurations)
	overall := slaReportRowView{
		Scope:         "overall",
		Name:          "Overall",
		UptimePercent: formatReportUptime(overallUp, overallEffective),
		UptimeClass:   reportUptimeClass(overallUp, overallEffective),
		IncidentCount: overallIncidents,
		MTTR:          formatReportMTTR(overallMTTR, overallHasMTTR),
		MonitorCount:  len(monitors),
		UpChecks:      overallUp,
		Effective:     overallEffective,
		HasMTTR:       overallHasMTTR,
	}
	if overallHasMTTR {
		overall.MTTRSeconds = int64(overallMTTR / time.Second)
	}

	return slaReportView{
		Period:        period.Value,
		PeriodOptions: buildReportPeriodOptions(period),
		PeriodLabel:   period.Label,
		FromLabel:     since.UTC().Format("2006-01-02"),
		ToLabel:       now.UTC().Format("2006-01-02"),
		Monitors:      monitorRows,
		Groups:        groupRows,
		Overall:       overall,
		ExportURL:     exportURL,
		HasData:       len(monitors) > 0,
	}
}
