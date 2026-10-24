package httpserver

import (
	"encoding/json"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleMonitorLatencyHistory(w http.ResponseWriter, r *http.Request) {
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

	monitorID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("monitor_id")), 10, 64)
	if err != nil || monitorID <= 0 {
		http.Error(w, "invalid monitor id", http.StatusBadRequest)
		return
	}

	rangeValue := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("range")))
	if rangeValue == "" {
		rangeValue = "1h"
	}
	if days, ok := aggregatedLatencyRangeDays[rangeValue]; ok {
		s.writeAggregatedLatencyHistory(w, r, appStore, monitorID, rangeValue, days)
		return
	}

	now := time.Now().UTC()
	since := now.Add(-time.Hour)
	limit := 480
	switch rangeValue {
	case "6h":
		since = now.Add(-6 * time.Hour)
		limit = 2400
	case "24h":
		since = now.Add(-24 * time.Hour)
		limit = 6000
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
		limit = 24000
	default:
		rangeValue = "1h"
	}

	points, err := appStore.ListMonitorLatencyHistory(r.Context(), monitorID, since, limit)
	if err != nil {
		http.Error(w, "unable to load latency history", http.StatusInternalServerError)
		return
	}

	type latencyPointPayload struct {
		CheckedAt string `json:"checked_at"`
		LatencyMS int    `json:"latency_ms"`
		Status    string `json:"status"`
	}
	responsePoints := make([]latencyPointPayload, 0, len(points))
	latencySum := 0
	latencyCount := 0
	for _, point := range points {
		responsePoints = append(responsePoints, latencyPointPayload{
			CheckedAt: point.CheckedAt.UTC().Format(time.RFC3339),
			LatencyMS: point.LatencyMS,
			Status:    strings.TrimSpace(point.Status),
		})
		if !strings.EqualFold(strings.TrimSpace(point.Status), string(monitor.StatusDown)) && point.LatencyMS >= 0 {
			latencySum += point.LatencyMS
			latencyCount++
		}
	}

	averageMS := 0
	if latencyCount > 0 {
		averageMS = int(float64(latencySum)/float64(latencyCount) + 0.5)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK        bool                  `json:"ok"`
		MonitorID int64                 `json:"monitor_id"`
		Range     string                `json:"range"`
		AverageMS int                   `json:"average_ms"`
		Points    []latencyPointPayload `json:"points"`
	}{
		OK:        true,
		MonitorID: monitorID,
		Range:     rangeValue,
		AverageMS: averageMS,
		Points:    responsePoints,
	})
}

// Ranges beyond the raw result retention are served from hourly rollups, one point per day.
var aggregatedLatencyRangeDays = map[string]int{
	"30d":  30,
	"90d":  90,
	"365d": 365,
}

type aggregatedLatencyPoint struct {
	CheckedAt      string `json:"checked_at"`
	LatencyMS      int    `json:"latency_ms"`
	Status         string `json:"status"`
	TotalChecks    int    `json:"total_checks"`
	UpChecks       int    `json:"up_checks"`
	DownChecks     int    `json:"down_checks"`
	DegradedChecks int    `json:"degraded_checks"`
	// UnknownChecks and MaintenanceChecks are part of TotalChecks but not of the uptime denominator.
	UnknownChecks     int `json:"unknown_checks"`
	MaintenanceChecks int `json:"maintenance_checks"`
	LatencyChecks     int `json:"latency_checks"`
	LatencySumMS      int `json:"latency_sum_ms"`
	LatencyMinMS      int `json:"latency_min_ms"`
	LatencyMaxMS      int `json:"latency_max_ms"`
}

func (s *Server) writeAggregatedLatencyHistory(w http.ResponseWriter, r *http.Request, appStore *store.Store, monitorID int64, rangeValue string, days int) {
	now := time.Now().UTC()
	since := now.Truncate(24*time.Hour).AddDate(0, 0, -days)
	rollups, err := appStore.ListMonitorHourlyRollupsForMonitorSince(r.Context(), monitorID, since)
	if err != nil {
		http.Error(w, "unable to load latency history", http.StatusInternalServerError)
		return
	}

	points := aggregateDailyLatency(rollups)
	latencySum, latencyCount := 0, 0
	for _, point := range points {
		latencySum += point.LatencySumMS
		latencyCount += point.LatencyChecks
	}
	averageMS := 0
	if latencyCount > 0 {
		averageMS = int(float64(latencySum)/float64(latencyCount) + 0.5)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		OK         bool                     `json:"ok"`
		MonitorID  int64                    `json:"monitor_id"`
		Range      string                   `json:"range"`
		Aggregated bool                     `json:"aggregated"`
		AverageMS  int                      `json:"average_ms"`
		Points     []aggregatedLatencyPoint `json:"points"`
	}{
		OK:         true,
		MonitorID:  monitorID,
		Range:      rangeValue,
		Aggregated: true,
		AverageMS:  averageMS,
		Points:     points,
	})
}

// aggregateDailyLatency folds hourly rollups (sorted oldest first) into one point per UTC day.
func aggregateDailyLatency(rollups []store.MonitorHourlyRollup) []aggregatedLatencyPoint {
	points := make([]aggregatedLatencyPoint, 0, 32)
	var current *aggregatedLatencyPoint
	var currentDay time.Time
	for _, rollup := range rollups {
		day := rollup.HourBucket.UTC().Truncate(24 * time.Hour)
		if current == nil || !day.Equal(currentDay) {
			// Stamp the point at noon UTC so browsers within ±12h place it on the same calendar day.
			points = append(points, aggregatedLatencyPoint{CheckedAt: day.Add(12 * time.Hour).Format(time.RFC3339)})
			current = &points[len(points)-1]
			currentDay = day
		}
		current.TotalChecks += rollup.TotalChecks
		current.UpChecks += rollup.UpChecks
		current.DownChecks += rollup.DownChecks
		current.DegradedChecks += rollup.DegradedChecks
		current.UnknownChecks += rollup.UnknownChecks
		current.MaintenanceChecks += rollup.MaintenanceChecks
		latencyChecks := rollup.UpChecks + rollup.DegradedChecks
		if latencyChecks == 0 {
			continue
		}
		// Down checks enter the rollup minimum as 0 ms, so that minimum is not a real latency.
		minIsReal := rollup.DownChecks == 0 || rollup.LatencyMinMS > 0
		if minIsReal && (current.LatencyMinMS == 0 || rollup.LatencyMinMS < current.LatencyMinMS) {
			current.LatencyMinMS = rollup.LatencyMinMS
		}
		if rollup.LatencyMaxMS > current.LatencyMaxMS {
			current.LatencyMaxMS = rollup.LatencyMaxMS
		}
		current.LatencyChecks += latencyChecks
		current.LatencySumMS += rollup.LatencySumMS
	}

	for i := range points {
		point := &points[i]
		if point.LatencyChecks > 0 {
			point.LatencyMS = int(float64(point.LatencySumMS)/float64(point.LatencyChecks) + 0.5)
		}
		switch {
		case point.DownChecks > 0 && point.UpChecks == 0 && point.DegradedChecks == 0:
			point.Status = string(monitor.StatusDown)
		case point.DownChecks > 0 || point.DegradedChecks > 0:
			point.Status = string(monitor.StatusDegraded)
		default:
			point.Status = string(monitor.StatusUp)
		}
	}
	return points
}
