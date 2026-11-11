package httpserver

import (
	"testing"
	"time"

	store "goup/internal/store/sqlite"
)

func TestBuildTrendPointsFromDailyRollups(t *testing.T) {
	now := time.Date(2026, 3, 20, 15, 0, 0, 0, time.UTC)
	trend := parseTrendRange("7d")
	start := trendRangeStart(now, trend)

	rollups := []store.MonitorHourlyRollup{
		{
			MonitorID: 1, HourBucket: start, TotalChecks: 10, UpChecks: 10,
			FirstCheckedAt: start, LastCheckedAt: start.Add(time.Hour),
		},
		{
			MonitorID: 1, HourBucket: start.AddDate(0, 0, 1), TotalChecks: 10, UpChecks: 8, DownChecks: 2,
			FirstCheckedAt: start.AddDate(0, 0, 1), LastCheckedAt: start.AddDate(0, 0, 1).Add(time.Hour),
		},
	}

	points := buildTrendPoints(rollups, now, trend)
	if len(points) != 7 {
		t.Fatalf("want 7 daily points, got %d", len(points))
	}
	if points[0].Class != "trend-up" || points[0].EffectiveChecks != 10 {
		t.Fatalf("day0 = %+v", points[0])
	}
	if points[1].Class != "trend-degraded" || points[1].UpChecks != 8 {
		t.Fatalf("day1 = %+v", points[1])
	}
	if points[2].Class != "trend-none" {
		t.Fatalf("empty day should be trend-none, got %s", points[2].Class)
	}
}

func TestBuildTrendPointsFromDailyRollupsMonthly(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	trend := parseTrendRange("12m")
	start := trendRangeStart(now, trend)

	rollups := []store.MonitorHourlyRollup{
		{MonitorID: 1, HourBucket: start, TotalChecks: 5, UpChecks: 5, FirstCheckedAt: start, LastCheckedAt: start},
		{MonitorID: 1, HourBucket: start.AddDate(0, 0, 10), TotalChecks: 5, UpChecks: 5, FirstCheckedAt: start.AddDate(0, 0, 10), LastCheckedAt: start.AddDate(0, 0, 10)},
		{MonitorID: 1, HourBucket: start.AddDate(0, 1, 2), TotalChecks: 4, UpChecks: 2, DownChecks: 2, FirstCheckedAt: start.AddDate(0, 1, 2), LastCheckedAt: start.AddDate(0, 1, 2)},
	}

	points := buildTrendPoints(rollups, now, trend)
	if len(points) != 12 {
		t.Fatalf("want 12 monthly points, got %d", len(points))
	}
	if points[0].EffectiveChecks != 10 || points[0].Class != "trend-up" {
		t.Fatalf("month0 aggregated daily rows incorrectly: %+v", points[0])
	}
	if points[1].EffectiveChecks != 4 || points[1].Class != "trend-degraded" {
		t.Fatalf("month1 = %+v", points[1])
	}
}
