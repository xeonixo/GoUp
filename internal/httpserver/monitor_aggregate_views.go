package httpserver

import (
	"goup/internal/monitor"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func aggregateServiceStatus(items []monitorView) (label string, class string, info string) {
	if len(items) == 0 {
		return "UNKNOWN", "status-UNKNOWN", "No monitors"
	}
	hasDown := false
	hasDegraded := false
	hasUnknown := false
	hasPaused := false
	hasUp := false
	for _, item := range items {
		switch item.StatusLabel {
		case "DOWN":
			hasDown = true
		case "DEGRADED":
			hasDegraded = true
		case "UP":
			hasUp = true
		case "PAUSED":
			hasPaused = true
		default:
			hasUnknown = true
		}
	}
	hasOnlyDown := hasDown && !hasUp && !hasDegraded && !hasUnknown && !hasPaused
	hasOnlyUnknown := hasUnknown && !hasUp && !hasDown && !hasDegraded && !hasPaused
	switch {
	case hasOnlyDown:
		return "DOWN", "status-DOWN", "Ausfall erkannt"
	case hasOnlyUnknown:
		return "UNKNOWN", "status-UNKNOWN", "Status unbekannt"
	case hasDown:
		return "DEGRADED", "status-DEGRADED", "Ausfall erkannt"
	case hasDegraded:
		return "DEGRADED", "status-DEGRADED", "Eingeschränkt"
	case hasUp && !hasUnknown && !hasPaused:
		return "UP", "status-UP", "Alle erreichbar"
	case hasPaused && !hasUp && !hasUnknown:
		return "PAUSED", "status-PAUSED", "Pausiert"
	default:
		return "DEGRADED", "status-DEGRADED", "Gemischter Zustand"
	}
}

func aggregateServiceTrendPoints(items []monitorView) []trendPointView {
	if len(items) == 0 {
		return nil
	}
	buckets := make([]trendPointView, len(items[0].TrendPoints))
	type aggregate struct {
		totalChecks   int
		upChecks      int
		latencyChecks int
		latencySum    int
		hasMinMS      bool
		minMS         int
		maxMS         int
	}
	agg := make([]aggregate, len(items[0].TrendPoints))
	for i, point := range items[0].TrendPoints {
		buckets[i] = trendPointView{
			BucketRaw: point.BucketRaw,
			Format:    point.Format,
			Class:     "trend-none",
			Label:     "Keine Daten",
		}
	}
	for _, item := range items {
		for i, point := range item.TrendPoints {
			if i >= len(agg) || point.Checks <= 0 {
				continue
			}
			agg[i].totalChecks += point.Checks
			agg[i].upChecks += int(float64(point.Percent) / 100.0 * float64(point.Checks))
			agg[i].latencyChecks += point.LatencyChecks
			agg[i].latencySum += point.AvgMS * point.LatencyChecks
			if point.LatencyChecks > 0 && (!agg[i].hasMinMS || point.MinMS < agg[i].minMS) {
				agg[i].hasMinMS = true
				agg[i].minMS = point.MinMS
			}
			if point.LatencyChecks > 0 && point.MaxMS > agg[i].maxMS {
				agg[i].maxMS = point.MaxMS
			}
		}
	}
	for i := range buckets {
		if agg[i].totalChecks <= 0 {
			continue
		}
		percent := int(float64(agg[i].upChecks) / float64(agg[i].totalChecks) * 100)
		buckets[i].Percent = percent
		buckets[i].Checks = agg[i].totalChecks
		buckets[i].LatencyChecks = agg[i].latencyChecks
		if agg[i].latencyChecks > 0 {
			buckets[i].AvgMS = agg[i].latencySum / agg[i].latencyChecks
		}
		buckets[i].MinMS = agg[i].minMS
		buckets[i].MaxMS = agg[i].maxMS
		buckets[i].Label = strconv.Itoa(percent) + "% Uptime · " + strconv.Itoa(agg[i].totalChecks) + " Checks"
		switch {
		case percent == 100:
			buckets[i].Class = "trend-up"
		case percent == 0:
			buckets[i].Class = "trend-down"
		default:
			buckets[i].Class = "trend-degraded"
		}
	}
	return buckets
}

func summarizeTrendPoints(points []trendPointView) string {
	totalPercent := 0
	counted := 0
	for _, point := range points {
		if point.Checks <= 0 {
			continue
		}
		totalPercent += point.Percent
		counted++
	}
	if counted == 0 {
		return "Keine Daten"
	}
	return strconv.Itoa(totalPercent/counted) + "% Uptime"
}

func (s *Server) redirectDashboardPath(r *http.Request, trend string, notice string, errText string) string {
	base := s.tenantAppBase(r)
	values := url.Values{}
	if strings.TrimSpace(trend) != "" {
		values.Set("trend", strings.TrimSpace(trend))
	}
	if strings.TrimSpace(notice) != "" {
		values.Set("notice", strings.TrimSpace(notice))
	}
	if strings.TrimSpace(errText) != "" {
		values.Set("error", strings.TrimSpace(errText))
	}
	encoded := values.Encode()
	if encoded == "" {
		return base
	}
	return base + "?" + encoded
}

func reorderMonitorIDs(items []int64, draggedID int64, targetID int64) ([]int64, bool) {
	if draggedID == targetID {
		return items, true
	}
	draggedIndex := -1
	targetIndex := -1
	for idx, item := range items {
		if item == draggedID {
			draggedIndex = idx
		}
		if item == targetID {
			targetIndex = idx
		}
	}
	if draggedIndex == -1 || targetIndex == -1 {
		return nil, false
	}
	reordered := make([]int64, 0, len(items))
	for idx, item := range items {
		if idx == draggedIndex {
			continue
		}
		reordered = append(reordered, item)
	}
	if draggedIndex < targetIndex {
		targetIndex--
	}
	updated := make([]int64, 0, len(items))
	updated = append(updated, reordered[:targetIndex]...)
	updated = append(updated, draggedID)
	updated = append(updated, reordered[targetIndex:]...)
	return updated, true
}

func monitorGroupingTokens(value string) []string {
	replacer := strings.NewReplacer("-", " ", "_", " ", "/", " ", ".", " ", "(", " ", ")", " ", ":", " ")
	normalized := strings.ToLower(strings.TrimSpace(replacer.Replace(value)))
	if normalized == "" {
		return nil
	}

	stopWords := map[string]struct{}{
		"https":      {},
		"http":       {},
		"tcp":        {},
		"icmp":       {},
		"smtp":       {},
		"imap":       {},
		"dns":        {},
		"udp":        {},
		"whois":      {},
		"tls":        {},
		"starttls":   {},
		"monitor":    {},
		"check":      {},
		"health":     {},
		"status":     {},
		"server":     {},
		"service":    {},
		"prod":       {},
		"production": {},
		"staging":    {},
		"stage":      {},
		"test":       {},
		"validation": {},
	}

	parts := strings.Fields(normalized)
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if _, blocked := stopWords[part]; blocked {
			continue
		}
		filtered = append(filtered, part)
	}
	return filtered
}

func monitorTargetHost(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		parsed, err := url.Parse(trimmed)
		if err == nil {
			return parsed.Hostname()
		}
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		return host
	}
	return trimmed
}

func monitorKindLabel(kind monitor.Kind) string {
	switch kind {
	case monitor.KindHTTPS:
		return "HTTP(S)"
	case monitor.KindTCP:
		return "TCP"
	case monitor.KindICMP:
		return "ICMP"
	case monitor.KindSMTP:
		return "SMTP"
	case monitor.KindIMAP:
		return "IMAP"
	case monitor.KindDNS:
		return "DNS"
	case monitor.KindUDP:
		return "UDP"
	case monitor.KindWhois:
		return "WHOIS"
	default:
		return strings.ToUpper(string(kind))
	}
}
