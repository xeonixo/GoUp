package httpserver

import (
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type monitorGroupView struct {
	Title       string
	Subtitle    string
	EmptyText   string
	AccentClass string
	Monitors    []monitorView
	Services    []monitorServiceGroupView
	Count       int
	ServiceHint string
}

type monitorServiceGroupView struct {
	Title       string
	Subtitle    string
	StatusLabel string
	StatusClass string
	StatusInfo  string
	TrendLabel  string
	UptimeLabel string
	TrendPoints []trendPointView
	IconSlug    string
	IconURL     string
	Monitors    []monitorView
	Open        bool
	CanMoveUp   bool
	CanMoveDown bool
}

type monitorView struct {
	ID                   int64
	Name                 string
	Group                string
	SortOrder            int
	CanMoveUp            bool
	CanMoveDown          bool
	KindValue            string
	Kind                 string
	TLSMode              string
	TLSModeValue         string
	Target               string
	TargetLabel          string
	Interval             string
	IntervalSeconds      int
	Timeout              string
	TimeoutSeconds       int
	Enabled              bool
	ExecutorKind         string
	ExecutorRef          string
	ExecutorValue        string
	ExecutorLabel        string
	NotifyOnRecovery     bool
	RetryCount           int
	RetryIntervalSeconds int
	ExpectedStatus       string
	ExpectedText         string
	TrendLabel           string
	StatusLabel          string
	StatusClass          string
	StatusSummary        string
	LastCheckedAt        string
	LastCheckedAtRaw     string
	LastStatus           string
	LastMessage          string
	LastLatency          string
	TrendPoints          []trendPointView
	UptimeLabel          string
	HTTPStatusCode       string
	TLSDaysRemaining     string
	TLSNotAfter          string
	TLSNotAfterRaw       string
}

func buildMonitorViews(items []monitor.Snapshot, rollups []store.MonitorHourlyRollup, now time.Time, selectedTrend trendRange, remoteNodeNames map[string]string) []monitorView {
	rollupsByMonitor := groupRollupsByMonitor(rollups)
	views := make([]monitorView, 0, len(items))
	for _, item := range items {
		kindLabel := monitorKindLabel(item.Monitor.Kind)
		tlsLabel := monitorTLSModeLabel(item.Monitor)
		if item.Monitor.Kind == monitor.KindHTTPS {
			kindLabel = monitorHTTPKindLabel(item.Monitor.Target, item.Monitor.TLSMode)
			tlsLabel = ""
		}

		view := monitorView{
			ID:                   item.Monitor.ID,
			Name:                 item.Monitor.Name,
			Group:                effectiveMonitorGroup(strings.TrimSpace(item.Monitor.Group), item.Monitor.Name, item.Monitor.Target),
			SortOrder:            item.Monitor.SortOrder,
			ExecutorKind:         strings.TrimSpace(item.Monitor.ExecutorKind),
			ExecutorRef:          strings.TrimSpace(item.Monitor.ExecutorRef),
			KindValue:            string(item.Monitor.Kind),
			Kind:                 kindLabel,
			TLSMode:              tlsLabel,
			TLSModeValue:         string(item.Monitor.TLSMode),
			Target:               item.Monitor.Target,
			TargetLabel:          monitorTargetLabel(item.Monitor),
			Interval:             item.Monitor.Interval.String(),
			IntervalSeconds:      int(item.Monitor.Interval / time.Second),
			Timeout:              item.Monitor.Timeout.String(),
			TimeoutSeconds:       int(item.Monitor.Timeout / time.Second),
			Enabled:              item.Monitor.Enabled,
			NotifyOnRecovery:     item.Monitor.NotifyOnRecovery,
			RetryCount:           item.Monitor.RetryCount,
			RetryIntervalSeconds: int(item.Monitor.RetryInterval / time.Second),
			TrendLabel:           selectedTrend.Label,
			TrendPoints:          buildTrendPoints(rollupsByMonitor[item.Monitor.ID], now, selectedTrend),
		}
		if view.ExecutorKind == "" {
			view.ExecutorKind = "local"
		}
		if view.ExecutorKind == "remote" && view.ExecutorRef != "" {
			view.ExecutorValue = "remote:" + view.ExecutorRef
			view.ExecutorLabel = "Remote: " + view.ExecutorRef
			if remoteNodeNames != nil {
				if remoteName := strings.TrimSpace(remoteNodeNames[view.ExecutorRef]); remoteName != "" {
					view.ExecutorLabel = "Remote: " + remoteName + " (" + view.ExecutorRef + ")"
				}
			}
		} else {
			view.ExecutorKind = "local"
			view.ExecutorRef = ""
			view.ExecutorValue = "local"
			view.ExecutorLabel = "Control-Plane (lokal)"
		}
		view.UptimeLabel = summarizeTrend(view.TrendPoints, selectedTrend)
		view.StatusLabel = "UNKNOWN"
		view.StatusClass = "status-UNKNOWN"
		view.StatusSummary = "No successful check yet"
		if item.Monitor.ExpectedStatusCode != nil {
			view.ExpectedStatus = strconv.Itoa(*item.Monitor.ExpectedStatusCode)
		}
		view.ExpectedText = strings.TrimSpace(item.Monitor.ExpectedText)
		if item.LastResult != nil {
			view.LastCheckedAt = item.LastResult.CheckedAt.UTC().Format(time.RFC3339)
			view.LastCheckedAtRaw = item.LastResult.CheckedAt.UTC().Format(time.RFC3339)
			view.LastStatus = strings.ToUpper(string(item.LastResult.Status))
			view.StatusLabel = view.LastStatus
			view.StatusClass = "status-" + view.LastStatus
			view.StatusSummary = item.LastResult.Message
			view.LastMessage = item.LastResult.Message
			view.LastLatency = formatLatencyLabel(item.LastResult.Latency)
			if isTimeoutMessage(item.LastResult.Message) {
				view.LastLatency = ""
			}
			if item.Monitor.Kind == monitor.KindICMP {
				if dualLatency := icmpDualStackLatencyLabel(item.LastResult.Message); dualLatency != "" {
					view.LastLatency = dualLatency
				}
			}
			if item.LastResult.HTTPStatusCode != nil {
				view.HTTPStatusCode = strconv.Itoa(*item.LastResult.HTTPStatusCode)
			}
			if item.LastResult.TLSDaysRemaining != nil {
				view.TLSDaysRemaining = strconv.Itoa(*item.LastResult.TLSDaysRemaining) + " Tage"
			}
			if item.LastResult.TLSNotAfter != nil {
				view.TLSNotAfter = item.LastResult.TLSNotAfter.UTC().Format(time.RFC3339)
				view.TLSNotAfterRaw = item.LastResult.TLSNotAfter.UTC().Format(time.RFC3339)
			}
		}
		if !item.Monitor.Enabled {
			view.StatusLabel = "PAUSED"
			view.StatusClass = "status-PAUSED"
			view.StatusSummary = "Monitor is paused"
		}
		views = append(views, view)
	}
	return views
}

func buildAvailableGroups(items []store.MonitorGroup) []string {
	groups := make([]string, 0, len(items))
	for _, item := range items {
		groups = append(groups, item.Name)
	}
	return groups
}

func mergeAvailableGroups(existing []string, monitors []monitorView) []string {
	seen := make(map[string]struct{}, len(existing)+len(monitors))
	groups := make([]string, 0, len(existing)+len(monitors))
	for _, item := range existing {
		group := strings.TrimSpace(item)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	for _, item := range monitors {
		group := strings.TrimSpace(item.Group)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	return groups
}

func buildMonitorGroups(appBase string, monitors []monitorView, metadata []store.MonitorGroup) []monitorGroupView {
	groupSortOrder := make(map[string]int, len(metadata))
	groupIcons := make(map[string]string, len(metadata))
	for idx, item := range metadata {
		name := strings.TrimSpace(item.Name)
		groupSortOrder[name] = idx
		groupIcons[name] = normalizeGroupIconReference(item.IconSlug)
	}

	services := buildMonitorServiceGroups(appBase, monitors, groupSortOrder, groupIcons, len(metadata))
	serviceHint := "Keine Dienstgruppen"
	if len(services) == 1 {
		serviceHint = "1 Dienstgruppe"
	} else if len(services) > 1 {
		serviceHint = strconv.Itoa(len(services)) + " Dienstgruppen"
	}

	return []monitorGroupView{
		{
			Title:       "Dienste",
			Subtitle:    "Gesamtsicht aller Monitore",
			EmptyText:   "Noch keine Monitore vorhanden.",
			AccentClass: "group-healthy",
			Monitors:    monitors,
			Services:    services,
			Count:       len(monitors),
			ServiceHint: serviceHint,
		},
	}
}

func buildMonitorStatusGroup(title string, subtitle string, emptyText string, accentClass string, monitors []monitorView, groupSortOrder map[string]int, groupIcons map[string]string, totalGroups int, appBase string) monitorGroupView {
	services := buildMonitorServiceGroups(appBase, monitors, groupSortOrder, groupIcons, totalGroups)
	serviceHint := "Einzelne Dienste"
	if len(services) > 1 {
		serviceHint = strconv.Itoa(len(services)) + " Dienstgruppen"
	}
	if len(services) == 1 {
		serviceHint = "1 Dienstgruppe"
	}
	return monitorGroupView{
		Title:       title,
		Subtitle:    subtitle,
		EmptyText:   emptyText,
		AccentClass: accentClass,
		Monitors:    monitors,
		Services:    services,
		Count:       len(monitors),
		ServiceHint: serviceHint,
	}
}

func buildMonitorServiceGroups(appBase string, monitors []monitorView, groupSortOrder map[string]int, groupIcons map[string]string, totalGroups int) []monitorServiceGroupView {
	if len(monitors) == 0 && len(groupSortOrder) == 0 {
		return nil
	}

	grouped := make(map[string][]monitorView)
	for _, item := range monitors {
		label := monitorServiceLabel(item)
		grouped[label] = append(grouped[label], item)
	}
	for label := range groupSortOrder {
		if _, ok := grouped[label]; !ok {
			grouped[label] = nil
		}
	}

	labels := make([]string, 0, len(grouped))
	for label := range grouped {
		labels = append(labels, label)
	}
	sort.Slice(labels, func(i, j int) bool {
		leftOrder, leftKnown := groupSortOrder[labels[i]]
		rightOrder, rightKnown := groupSortOrder[labels[j]]
		if leftKnown && rightKnown && leftOrder != rightOrder {
			return leftOrder < rightOrder
		}
		if leftKnown != rightKnown {
			return leftKnown
		}
		left := grouped[labels[i]]
		right := grouped[labels[j]]
		if len(left) == len(right) {
			return labels[i] < labels[j]
		}
		return len(left) > len(right)
	})

	services := make([]monitorServiceGroupView, 0, len(labels))
	for _, label := range labels {
		items := grouped[label]
		sort.Slice(items, func(i, j int) bool {
			if items[i].SortOrder != items[j].SortOrder {
				return items[i].SortOrder < items[j].SortOrder
			}
			if items[i].Name == items[j].Name {
				return items[i].Kind < items[j].Kind
			}
			return items[i].Name < items[j].Name
		})
		for idx := range items {
			items[idx].CanMoveUp = idx > 0
			items[idx].CanMoveDown = idx < len(items)-1
		}
		subtitle := strconv.Itoa(len(items)) + " Monitor"
		if len(items) != 1 {
			subtitle += "e"
		}
		statusLabel, statusClass, statusInfo := aggregateServiceStatus(items)
		aggregatePoints := aggregateServiceTrendPoints(items)
		uptimeLabel := summarizeTrendPoints(aggregatePoints)
		trendLabel := ""
		if len(items) > 0 {
			trendLabel = items[0].TrendLabel
		}
		orderIndex := len(groupSortOrder)
		if knownIndex, ok := groupSortOrder[label]; ok {
			orderIndex = knownIndex
		}
		iconRef := effectiveGroupIconReference(label, groupIcons[label])
		services = append(services, monitorServiceGroupView{
			Title:       label,
			Subtitle:    subtitle,
			StatusLabel: statusLabel,
			StatusClass: statusClass,
			StatusInfo:  statusInfo,
			TrendLabel:  trendLabel,
			UptimeLabel: uptimeLabel,
			TrendPoints: aggregatePoints,
			IconSlug:    iconRef,
			IconURL:     localIconURL(appBase, iconRef),
			Monitors:    items,
			Open:        false,
			CanMoveUp:   orderIndex > 0,
			CanMoveDown: orderIndex >= 0 && orderIndex < totalGroups-1,
		})
	}

	return services
}

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

func monitorServiceLabel(item monitorView) string {
	if group := strings.TrimSpace(item.Group); group != "" {
		return group
	}
	return effectiveMonitorGroup("", item.Name, item.Target)

}

func effectiveMonitorGroup(group string, name string, target string) string {
	if group = strings.TrimSpace(group); group != "" {
		return group
	}

	name = strings.TrimSpace(name)
	for _, token := range monitorGroupingTokens(name) {
		if token == "" {
			continue
		}
		return strings.ToUpper(token[:1]) + token[1:]
	}

	host := monitorTargetHost(target)
	for _, token := range monitorGroupingTokens(host) {
		if token == "" {
			continue
		}
		return strings.ToUpper(token[:1]) + token[1:]
	}

	return "Sonstige"
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
