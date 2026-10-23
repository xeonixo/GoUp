package httpserver

import (
	"testing"
	"time"

	store "goup/internal/store/sqlite"
)

func TestAggregateDailyLatency(t *testing.T) {
	day1 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	day2 := day1.Add(24 * time.Hour)
	rollups := []store.MonitorHourlyRollup{
		{HourBucket: day1.Add(1 * time.Hour), TotalChecks: 60, UpChecks: 60, LatencySumMS: 6000, LatencyMinMS: 50, LatencyMaxMS: 300},
		// One down check drags the stored minimum to 0 ms; it must not become the daily minimum.
		{HourBucket: day1.Add(2 * time.Hour), TotalChecks: 60, UpChecks: 59, DownChecks: 1, LatencySumMS: 5900, LatencyMinMS: 0, LatencyMaxMS: 120},
		{HourBucket: day2.Add(5 * time.Hour), TotalChecks: 60, DownChecks: 60},
	}

	points := aggregateDailyLatency(rollups)
	if len(points) != 2 {
		t.Fatalf("expected 2 daily points, got %d", len(points))
	}

	first := points[0]
	if first.CheckedAt != "2026-03-01T12:00:00Z" {
		t.Fatalf("unexpected day stamp %q", first.CheckedAt)
	}
	if first.TotalChecks != 120 || first.UpChecks != 119 || first.DownChecks != 1 || first.LatencyChecks != 119 {
		t.Fatalf("unexpected check counts: %+v", first)
	}
	if first.LatencyMS != 100 || first.LatencyMinMS != 50 || first.LatencyMaxMS != 300 {
		t.Fatalf("unexpected latency aggregate: %+v", first)
	}
	if first.Status != "degraded" {
		t.Fatalf("expected degraded day, got %q", first.Status)
	}

	second := points[1]
	if second.Status != "down" || second.LatencyChecks != 0 || second.LatencyMS != 0 {
		t.Fatalf("unexpected fully down day: %+v", second)
	}
}

func TestAppMuxRegistersMonitorDetailRoute(t *testing.T) {
	// Registering "/monitors/{id}" next to the literal /monitors/... routes must not panic.
	s := &Server{}
	if s.buildAppMux() == nil {
		t.Fatalf("expected app mux")
	}
}

func TestFormatIncidentDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second:              "<1m",
		61 * time.Second:              "1m",
		2*time.Hour + 5*time.Minute:   "2h 5m",
		26*time.Hour + 10*time.Minute: "1d 2h",
	} {
		if got := formatIncidentDuration(d); got != want {
			t.Errorf("formatIncidentDuration(%s) = %q, want %q", d, got, want)
		}
	}
}
