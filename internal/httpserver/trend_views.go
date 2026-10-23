package httpserver

import (
	"fmt"
	store "goup/internal/store/sqlite"
	"strconv"
	"time"
)

// uptimeBasisPoints returns up/effective in hundredths of a percent, rounded down so a monitor
// that missed a single check never displays as 100.00%.
func uptimeBasisPoints(up, effective int) int {
	if effective <= 0 {
		return 0
	}
	return int(int64(up) * 10000 / int64(effective))
}

// formatUptimePercent renders an uptime ratio with two decimals, e.g. "99.95%".
func formatUptimePercent(up, effective int) string {
	value := uptimeBasisPoints(up, effective)
	return fmt.Sprintf("%d.%02d%%", value/100, value%100)
}

type trendRangeOptionView struct {
	Value    string
	Label    string
	Selected bool
}

type trendPointView struct {
	BucketRaw string
	// Percent is the uptime in percent (two decimals of precision), see UpChecks/EffectiveChecks.
	Percent float64
	Class   string
	Label   string
	Format  string
	// Checks is the number of checks in the bucket; EffectiveChecks excludes unknown and
	// maintenance checks and is the uptime denominator.
	Checks          int
	UpChecks        int
	EffectiveChecks int
	LatencyChecks   int
	LatencySumMS    int
	AvgMS           int
	MinMS           int
	MaxMS           int
}

type trendRange struct {
	Value      string
	Label      string
	BucketSize time.Duration
	Buckets    int
	Step       string
}

var supportedTrendRanges = []trendRange{
	{Value: "24h", Label: "24h", BucketSize: time.Hour, Buckets: 24, Step: "hour"},
	{Value: "7d", Label: "7d", BucketSize: 24 * time.Hour, Buckets: 7, Step: "day"},
	{Value: "30d", Label: "30d", BucketSize: 24 * time.Hour, Buckets: 30, Step: "day"},
	{Value: "12m", Label: "12M", BucketSize: 24 * time.Hour, Buckets: 12, Step: "month"},
}

func groupRollupsByMonitor(items []store.MonitorHourlyRollup) map[int64][]store.MonitorHourlyRollup {
	grouped := make(map[int64][]store.MonitorHourlyRollup)
	for _, item := range items {
		grouped[item.MonitorID] = append(grouped[item.MonitorID], item)
	}
	return grouped
}

func buildTrendPoints(items []store.MonitorHourlyRollup, now time.Time, selectedTrend trendRange) []trendPointView {
	type aggregate struct {
		totalChecks     int
		effectiveChecks int
		upChecks        int
		downChecks      int
		degradedChecks  int
		latencyChecks   int
		latencySumMS    int
		hasLatencyMin   bool
		latencyMinMS    int
		latencyMaxMS    int
	}

	start := trendRangeStart(now, selectedTrend)
	buckets := make(map[string]*aggregate, selectedTrend.Buckets)
	for idx := 0; idx < selectedTrend.Buckets; idx++ {
		bucketStart := trendBucketAt(start, selectedTrend, idx)
		buckets[bucketStart.Format(time.RFC3339)] = &aggregate{}
	}

	for _, item := range items {
		bucketStart := bucketStartFor(item.HourBucket.UTC(), start, selectedTrend)
		if bucketStart.IsZero() {
			continue
		}
		entry := buckets[bucketStart.Format(time.RFC3339)]
		if entry == nil {
			continue
		}
		entry.totalChecks += item.TotalChecks
		entry.effectiveChecks += item.EffectiveChecks()
		entry.upChecks += item.UpChecks
		entry.downChecks += item.DownChecks
		entry.degradedChecks += item.DegradedChecks
		currentLatencyChecks := item.UpChecks + item.DegradedChecks
		entry.latencyChecks += currentLatencyChecks
		entry.latencySumMS += item.LatencySumMS
		if currentLatencyChecks > 0 && (!entry.hasLatencyMin || item.LatencyMinMS < entry.latencyMinMS) {
			entry.hasLatencyMin = true
			entry.latencyMinMS = item.LatencyMinMS
		}
		if currentLatencyChecks > 0 && item.LatencyMaxMS > entry.latencyMaxMS {
			entry.latencyMaxMS = item.LatencyMaxMS
		}
	}

	points := make([]trendPointView, 0, selectedTrend.Buckets)
	for idx := 0; idx < selectedTrend.Buckets; idx++ {
		bucket := trendBucketAt(start, selectedTrend, idx)
		key := bucket.Format(time.RFC3339)
		agg := buckets[key]
		point := trendPointView{
			BucketRaw: key,
			Class:     "trend-none",
			Label:     "Keine Daten",
			Format:    trendPointFormat(selectedTrend),
		}
		if agg != nil && agg.effectiveChecks > 0 {
			basisPoints := uptimeBasisPoints(agg.upChecks, agg.effectiveChecks)
			point.Percent = float64(basisPoints) / 100
			point.Checks = agg.totalChecks
			point.UpChecks = agg.upChecks
			point.EffectiveChecks = agg.effectiveChecks
			point.LatencyChecks = agg.latencyChecks
			point.LatencySumMS = agg.latencySumMS
			if agg.latencyChecks > 0 {
				point.AvgMS = agg.latencySumMS / agg.latencyChecks
			}
			point.MinMS = agg.latencyMinMS
			point.MaxMS = agg.latencyMaxMS
			point.Label = formatUptimePercent(agg.upChecks, agg.effectiveChecks) + " Uptime · " + strconv.Itoa(agg.effectiveChecks) + " Checks"
			switch {
			case agg.downChecks > 0 && agg.upChecks == 0 && agg.degradedChecks == 0:
				point.Class = "trend-down"
			case agg.downChecks > 0 || agg.degradedChecks > 0 || agg.upChecks < agg.effectiveChecks:
				point.Class = "trend-degraded"
			default:
				point.Class = "trend-up"
			}
		}
		points = append(points, point)
	}
	return points
}

func trendPointFormat(selected trendRange) string {
	if selected.Step == "hour" {
		return "hour"
	}
	if selected.Step == "month" {
		return "month"
	}
	return "date"
}

func summarizeTrend(points []trendPointView, selectedTrend trendRange) string {
	if len(points) == 0 {
		return "Keine Daten"
	}
	up, effective := 0, 0
	for _, point := range points {
		if point.Class == "trend-none" {
			continue
		}
		up += point.UpChecks
		effective += point.EffectiveChecks
	}
	if effective == 0 {
		return "Keine Daten"
	}
	return formatUptimePercent(up, effective) + " Uptime / " + selectedTrend.Label
}

func parseTrendRange(value string) trendRange {
	for _, item := range supportedTrendRanges {
		if item.Value == value {
			return item
		}
	}
	return supportedTrendRanges[0]
}

func buildTrendRangeOptions(selected trendRange) []trendRangeOptionView {
	items := make([]trendRangeOptionView, 0, len(supportedTrendRanges))
	for _, item := range supportedTrendRanges {
		items = append(items, trendRangeOptionView{
			Value:    item.Value,
			Label:    item.Label,
			Selected: item.Value == selected.Value,
		})
	}
	return items
}

func trendRangeStart(now time.Time, selected trendRange) time.Time {
	if selected.Step == "hour" {
		return now.UTC().Truncate(time.Hour).Add(-time.Duration(selected.Buckets-1) * time.Hour)
	}
	if selected.Step == "month" {
		startOfMonth := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
		return startOfMonth.AddDate(0, -(selected.Buckets - 1), 0)
	}
	startOfDay := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return startOfDay.AddDate(0, 0, -(selected.Buckets - 1))
}

func bucketStartFor(checkedAt time.Time, rangeStart time.Time, selected trendRange) time.Time {
	if checkedAt.Before(rangeStart) {
		return time.Time{}
	}
	if selected.Step == "hour" {
		return checkedAt.Truncate(time.Hour)
	}
	if selected.Step == "month" {
		return time.Date(checkedAt.Year(), checkedAt.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return time.Date(checkedAt.Year(), checkedAt.Month(), checkedAt.Day(), 0, 0, 0, 0, time.UTC)
}

func trendBucketAt(start time.Time, selected trendRange, idx int) time.Time {
	if selected.Step == "month" {
		return start.AddDate(0, idx, 0)
	}
	return start.Add(time.Duration(idx) * selected.BucketSize)
}
