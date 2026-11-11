package httpserver

import (
	"testing"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

func TestSumRollupUptimeExcludesUnknownAndMaintenance(t *testing.T) {
	rollups := []store.MonitorHourlyRollup{
		{UpChecks: 90, DownChecks: 5, UnknownChecks: 3, MaintenanceChecks: 2, TotalChecks: 100},
		{UpChecks: 10, DownChecks: 0, UnknownChecks: 0, MaintenanceChecks: 0, TotalChecks: 10},
	}
	up, effective := sumRollupUptime(rollups)
	if up != 100 {
		t.Fatalf("up = %d, want 100", up)
	}
	if effective != 105 {
		t.Fatalf("effective = %d, want 105", effective)
	}
}

func TestAverageMTTRIgnoresOpenAndUsesResolvedOnly(t *testing.T) {
	start := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	resolved1 := start.Add(10 * time.Minute)
	r2start := start.Add(time.Hour)
	r2end := r2start.Add(30 * time.Minute)
	negativeEnd := start.Add(-time.Minute)
	incidents := []incidentDuration{
		{StartedAt: start, ResolvedAt: &resolved1},
		{StartedAt: r2start, ResolvedAt: &r2end},
		{StartedAt: start, ResolvedAt: nil},
		{StartedAt: start, ResolvedAt: &negativeEnd},
	}

	got, ok := averageMTTR(incidents)
	if !ok {
		t.Fatal("expected MTTR")
	}
	if got != 20*time.Minute {
		t.Fatalf("MTTR = %v, want 20m", got)
	}
}

func TestAverageMTTREmpty(t *testing.T) {
	if _, ok := averageMTTR(nil); ok {
		t.Fatal("expected no MTTR")
	}
	if _, ok := averageMTTR([]incidentDuration{{StartedAt: time.Now()}}); ok {
		t.Fatal("open-only should not yield MTTR")
	}
}

func TestFormatReportDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{45 * time.Second, "45s"},
		{3 * time.Minute, "3m"},
		{3*time.Minute + 15*time.Second, "3m 15s"},
		{2 * time.Hour, "2h"},
		{2*time.Hour + 5*time.Minute, "2h 5m"},
		{72 * time.Hour, "3d"},
		{75 * time.Hour, "3d 3h"},
	}
	for _, tc := range cases {
		if got := formatReportDuration(tc.d); got != tc.want {
			t.Errorf("formatReportDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestFormatReportUptimeAndMTTR(t *testing.T) {
	if got := formatReportUptime(0, 0); got != "—" {
		t.Errorf("empty uptime = %q", got)
	}
	if got := formatReportUptime(9995, 10000); got != "99.95%" {
		t.Errorf("uptime = %q", got)
	}
	if got := formatReportMTTR(0, false); got != "—" {
		t.Errorf("empty mttr = %q", got)
	}
	if got := formatReportMTTR(5*time.Minute, true); got != "5m" {
		t.Errorf("mttr = %q", got)
	}
}

func TestParseReportPeriod(t *testing.T) {
	if got := parseReportPeriod("7d"); got.Value != "7d" || got.Days != 7 {
		t.Fatalf("7d = %+v", got)
	}
	if got := parseReportPeriod("90D"); got.Value != "90d" {
		t.Fatalf("90D = %+v", got)
	}
	if got := parseReportPeriod("bogus"); got.Value != "30d" {
		t.Fatalf("default = %+v", got)
	}
}

func TestBuildSLAReportViewPerMonitorAndGroup(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	hour := now.Truncate(time.Hour)
	resolved := hour.Add(20 * time.Minute)

	snapshots := []monitor.Snapshot{
		{Monitor: monitor.Monitor{ID: 1, Name: "api", Group: "edge"}},
		{Monitor: monitor.Monitor{ID: 2, Name: "web", Group: "edge"}},
		{Monitor: monitor.Monitor{ID: 3, Name: "db", Group: ""}},
	}
	rollups := []store.MonitorHourlyRollup{
		{MonitorID: 1, HourBucket: hour, TotalChecks: 100, UpChecks: 99, DownChecks: 1},
		{MonitorID: 2, HourBucket: hour, TotalChecks: 100, UpChecks: 100},
		{MonitorID: 3, HourBucket: hour, TotalChecks: 50, UpChecks: 45, DownChecks: 5},
	}
	incidents := []store.IncidentReportRow{
		{ID: 1, MonitorID: 1, StartedAt: hour, ResolvedAt: &resolved},
		{ID: 2, MonitorID: 3, StartedAt: hour.Add(time.Hour), ResolvedAt: nil},
	}

	view := buildSLAReportView(snapshots, rollups, incidents, parseReportPeriod("7d"), now, "/export", "(ungrouped)")

	if !view.HasData {
		t.Fatal("expected data")
	}
	if len(view.Monitors) != 3 {
		t.Fatalf("monitors = %d", len(view.Monitors))
	}
	if len(view.Groups) != 2 {
		t.Fatalf("groups = %d", len(view.Groups))
	}
	if view.Overall.IncidentCount != 2 {
		t.Fatalf("overall incidents = %d", view.Overall.IncidentCount)
	}
	if view.Overall.MTTR != "20m" {
		t.Fatalf("overall mttr = %q", view.Overall.MTTR)
	}

	var edge *slaReportRowView
	for i := range view.Groups {
		if view.Groups[i].Name == "edge" {
			edge = &view.Groups[i]
			break
		}
	}
	if edge == nil {
		t.Fatal("missing edge group")
	}
	if edge.IncidentCount != 1 || edge.MonitorCount != 2 {
		t.Fatalf("edge = %+v", *edge)
	}
	if edge.UptimePercent != "99.50%" {
		t.Fatalf("edge uptime = %q", edge.UptimePercent)
	}
}
