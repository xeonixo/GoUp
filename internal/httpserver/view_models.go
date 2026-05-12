package httpserver

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type paginationView struct {
	Page      int
	PageCount int
	Total     int64
	HasPrev   bool
	HasNext   bool
	PrevPage  int
	NextPage  int
	BaseURL   string
}

type languageOptionView struct {
	Code     string
	Label    string
	Selected bool
}

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

type trendRangeOptionView struct {
	Value    string
	Label    string
	Selected bool
}

type remoteNodeView struct {
	NodeID          string
	Name            string
	LastSeenAt      string
	LastSeenAtRaw   string
	Online          bool
	HeartbeatWindow string
	ProvisionURL    string
	Events          []remoteNodeEventView
}

type remoteNodeEventView struct {
	EventLabel    string
	SourceIP      string
	UserAgent     string
	Details       string
	OccurredAt    string
	OccurredAtRaw string
}

type adminProviderOverviewRow struct {
	TenantID    int64
	TenantName  string
	TenantSlug  string
	ProviderKey string
	Kind        string
	DisplayName string
	Enabled     bool
}

type adminUserOverviewRow struct {
	TenantID            int64
	TenantName          string
	TenantSlug          string
	UserID              int64
	LoginName           string
	Email               string
	DisplayName         string
	Role                string
	LastLoginAt         string
	LastLoginAtRaw      string
	HasLocalCredentials bool
	HasOIDCIdentity     bool
}

type adminRemoteNodeOverviewRow struct {
	TenantID        int64
	TenantName      string
	TenantSlug      string
	NodeID          string
	Name            string
	Online          bool
	LastSeenAt      string
	LastSeenAtRaw   string
	HeartbeatWindow string
}

type monitorExecutorOptionView struct {
	Value    string
	Label    string
	Selected bool
}

type trendPointView struct {
	BucketRaw     string
	Percent       int
	Class         string
	Label         string
	Format        string
	Checks        int
	LatencyChecks int
	AvgMS         int
	MinMS         int
	MaxMS         int
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

type notificationEventView struct {
	ID             int64
	When           string
	WhenRaw        string
	Monitor        string
	EventType      string
	Endpoint       string
	Result         string
	Error          string
	DeliveredAt    string
	DeliveredAtRaw string
}

type monitorStateEventView struct {
	ID        int64
	When      string
	WhenRaw   string
	Group     string
	Monitor   string
	From      string
	FromClass string
	To        string
	ToClass   string
	Message   string
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

func icmpDualStackLatencyLabel(message string) string {
	trimmed := strings.TrimSpace(message)
	if !strings.HasPrefix(trimmed, "ICMP dual stack") {
		return ""
	}
	parts := strings.Split(trimmed, " · ")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[1:], " · ")
}

func formatLatencyLabel(duration time.Duration) string {
	if duration <= 0 {
		return "0ms"
	}
	if duration < time.Millisecond {
		return "<1ms"
	}
	if duration < time.Second {
		return strconv.FormatInt(duration.Milliseconds(), 10) + "ms"
	}
	seconds := duration.Seconds()
	formatted := strconv.FormatFloat(seconds, 'f', 2, 64)
	formatted = strings.TrimRight(strings.TrimRight(formatted, "0"), ".")
	return formatted + "s"
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

func buildRemoteNodeViews(items []store.RemoteNode, now time.Time, baseURL string, eventsByNode map[string][]store.RemoteNodeEvent) []remoteNodeView {
	views := make([]remoteNodeView, 0, len(items))
	bootstrapURL := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/node/bootstrap"
	for _, item := range items {
		view := remoteNodeView{
			NodeID:          item.NodeID,
			Name:            item.Name,
			Online:          item.IsOnline(now),
			HeartbeatWindow: fmt.Sprintf("%ds", item.HeartbeatTimeoutSeconds),
			ProvisionURL:    bootstrapURL,
		}
		if item.LastSeenAt != nil {
			view.LastSeenAtRaw = item.LastSeenAt.UTC().Format(time.RFC3339)
			view.LastSeenAt = view.LastSeenAtRaw
		}
		if eventsByNode != nil {
			events := eventsByNode[item.NodeID]
			if len(events) > 0 {
				view.Events = make([]remoteNodeEventView, 0, len(events))
				for _, event := range events {
					eventTime := event.CreatedAt.UTC().Format(time.RFC3339)
					view.Events = append(view.Events, remoteNodeEventView{
						EventLabel:    remoteNodeEventLabel(event.EventType),
						SourceIP:      strings.TrimSpace(event.RemoteIP),
						UserAgent:     strings.TrimSpace(event.UserAgent),
						Details:       strings.TrimSpace(event.Details),
						OccurredAt:    eventTime,
						OccurredAtRaw: eventTime,
					})
				}
			}
		}
		views = append(views, view)
	}
	return views
}

func buildRemoteNodeNameMap(nodes []store.RemoteNode) map[string]string {
	if len(nodes) == 0 {
		return nil
	}
	result := make(map[string]string, len(nodes))
	for _, node := range nodes {
		nodeID := strings.TrimSpace(node.NodeID)
		if nodeID == "" {
			continue
		}
		result[nodeID] = strings.TrimSpace(node.Name)
	}
	return result
}

func groupRemoteNodeEventsByNode(items []store.RemoteNodeEvent, perNodeLimit int) map[string][]store.RemoteNodeEvent {
	if len(items) == 0 {
		return nil
	}
	if perNodeLimit <= 0 {
		perNodeLimit = 6
	}
	grouped := make(map[string][]store.RemoteNodeEvent)
	for _, item := range items {
		nodeID := strings.TrimSpace(item.NodeID)
		if nodeID == "" {
			continue
		}
		if len(grouped[nodeID]) >= perNodeLimit {
			continue
		}
		grouped[nodeID] = append(grouped[nodeID], item)
	}
	return grouped
}

func remoteNodeEventLabel(eventType string) string {
	switch strings.TrimSpace(strings.ToLower(eventType)) {
	case "bootstrap":
		return "Bootstrap"
	case "poll":
		return "Poll"
	case "report":
		return "Report"
	default:
		return strings.TrimSpace(eventType)
	}
}

func buildMonitorExecutorOptions(nodes []store.RemoteNode) []monitorExecutorOptionView {
	options := make([]monitorExecutorOptionView, 0, len(nodes)+1)
	options = append(options, monitorExecutorOptionView{Value: "local", Label: "Control-Plane (lokal)", Selected: true})
	for _, node := range nodes {
		options = append(options, monitorExecutorOptionView{
			Value: "remote:" + node.NodeID,
			Label: strings.TrimSpace(node.Name),
		})
	}
	return options
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

func buildNotificationEventViews(items []store.NotificationEvent) []notificationEventView {
	views := make([]notificationEventView, 0, len(items))
	for _, item := range items {
		view := notificationEventView{
			ID:        item.ID,
			When:      item.CreatedAt.UTC().Format(time.RFC3339),
			WhenRaw:   item.CreatedAt.UTC().Format(time.RFC3339),
			Monitor:   item.MonitorName,
			EventType: strings.ToUpper(strings.TrimSpace(item.EventType)),
			Endpoint:  item.Endpoint,
			Result:    "FAILED",
			Error:     item.Error,
		}
		if view.Monitor == "" {
			view.Monitor = strconv.FormatInt(item.MonitorID, 10)
		}
		if view.Endpoint == "" {
			view.Endpoint = strconv.FormatInt(item.EndpointID, 10)
		}
		if item.DeliveredAt != nil {
			view.Result = "DELIVERED"
			view.DeliveredAt = item.DeliveredAt.UTC().Format(time.RFC3339)
			view.DeliveredAtRaw = item.DeliveredAt.UTC().Format(time.RFC3339)
		}
		if strings.TrimSpace(view.Error) == "" {
			view.Error = "—"
		}
		views = append(views, view)
	}
	return views
}

func buildMonitorStateEventViews(items []store.MonitorStateEvent) []monitorStateEventView {
	views := make([]monitorStateEventView, 0, len(items))
	for _, item := range items {
		view := monitorStateEventView{
			ID:      item.ID,
			When:    item.CheckedAt.UTC().Format(time.RFC3339),
			WhenRaw: item.CheckedAt.UTC().Format(time.RFC3339),
			Group:   item.GroupName,
			Monitor: item.MonitorName,
			From:    strings.ToUpper(strings.TrimSpace(item.FromStatus)),
			To:      strings.ToUpper(strings.TrimSpace(item.ToStatus)),
			Message: strings.TrimSpace(item.Message),
		}
		if view.Monitor == "" {
			view.Monitor = strconv.FormatInt(item.MonitorID, 10)
		}
		if view.Message == "" {
			view.Message = "—"
		}
		if view.From == "" {
			view.From = "UNKNOWN"
		}
		if view.To == "" {
			view.To = "UNKNOWN"
		}
		view.FromClass = "status-" + view.From
		view.ToClass = "status-" + view.To
		views = append(views, view)
	}
	return views
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
		totalChecks    int
		upChecks       int
		downChecks     int
		degradedChecks int
		latencyChecks  int
		latencySumMS   int
		hasLatencyMin  bool
		latencyMinMS   int
		latencyMaxMS   int
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
		if agg != nil && agg.totalChecks > 0 {
			percent := int(float64(agg.upChecks) / float64(agg.totalChecks) * 100)
			point.Percent = percent
			point.Checks = agg.totalChecks
			point.LatencyChecks = agg.latencyChecks
			if agg.latencyChecks > 0 {
				point.AvgMS = agg.latencySumMS / agg.latencyChecks
			}
			point.MinMS = agg.latencyMinMS
			point.MaxMS = agg.latencyMaxMS
			point.Label = strconv.Itoa(percent) + "% Uptime · " + strconv.Itoa(agg.totalChecks) + " Checks"
			switch {
			case agg.downChecks > 0 && agg.upChecks == 0 && agg.degradedChecks == 0:
				point.Class = "trend-down"
			case agg.downChecks > 0 || agg.degradedChecks > 0 || percent < 100:
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
	counted := 0
	total := 0
	for _, point := range points {
		if point.Class == "trend-none" {
			continue
		}
		counted++
		total += point.Percent
	}
	if counted == 0 {
		return "Keine Daten"
	}
	return strconv.Itoa(total/counted) + "% Uptime / " + selectedTrend.Label
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

func defaultTLSMode(kind monitor.Kind) monitor.TLSMode {
	switch kind {
	case monitor.KindHTTPS, monitor.KindIMAP:
		return monitor.TLSModeTLS
	case monitor.KindSMTP:
		return monitor.TLSModeSTARTTLS
	default:
		return monitor.TLSModeNone
	}
}

func normalizeTLSMode(kind monitor.Kind, requested monitor.TLSMode) monitor.TLSMode {
	switch kind {
	case monitor.KindHTTPS:
		return monitor.NormalizeHTTPSTLSSecurityMode(requested)
	case monitor.KindTCP:
		return monitor.NormalizeTCPTLSSecurityMode(requested)
	case monitor.KindICMP:
		if requested == monitor.TLSModeNone || requested == monitor.TLSModeTLS || requested == monitor.TLSModeSTARTTLS {
			return requested
		}
		return monitor.TLSModeNone
	case monitor.KindSMTP:
		if monitor.IsValidMailTLSMode(requested) {
			return requested
		}
		return monitor.TLSModeSTARTTLS
	case monitor.KindIMAP:
		if monitor.IsValidMailTLSMode(requested) {
			return requested
		}
		return monitor.TLSModeTLS
	case monitor.KindUDP:
		if monitor.IsValidUDPMode(requested) {
			return requested
		}
		return monitor.TLSModeNone
	case monitor.KindDNS, monitor.KindWhois:
		return monitor.TLSModeNone
	default:
		return requested
	}
}

func parseMonitorExecutorSelection(raw string) (executorKind string, executorRef string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "local") {
		return "local", ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "remote:") {
		ref := strings.TrimSpace(raw[len("remote:"):])
		if ref == "" {
			return "local", ""
		}
		return "remote", ref
	}
	return "local", ""
}

func monitorTargetLabel(item monitor.Monitor) string {
	if item.Kind == monitor.KindDNS {
		parsed := monitor.ParseDNSTarget(item.Target)
		parts := make([]string, 0, 3)
		if parsed.Host != "" {
			parts = append(parts, parsed.Host)
		}
		switch monitor.NormalizeDNSRecordType(string(parsed.RecordType)) {
		case monitor.DNSRecordTypeA:
			parts = append(parts, "A")
		case monitor.DNSRecordTypeAAAA:
			parts = append(parts, "AAAA")
		case monitor.DNSRecordTypeCNAME:
			parts = append(parts, "CNAME")
		case monitor.DNSRecordTypeMX:
			parts = append(parts, "MX")
		case monitor.DNSRecordTypeTXT:
			parts = append(parts, "TXT")
		case monitor.DNSRecordTypeNS:
			parts = append(parts, "NS")
		case monitor.DNSRecordTypeSRV:
			parts = append(parts, "SRV")
		case monitor.DNSRecordTypeCAA:
			parts = append(parts, "CAA")
		case monitor.DNSRecordTypeSOA:
			parts = append(parts, "SOA")
		default:
			parts = append(parts, "A+AAAA")
		}
		if parsed.Server != "" {
			parts = append(parts, "via "+parsed.Server)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " · ")
		}
		return item.Target
	}
	if item.Kind != monitor.KindTCP {
		return item.Target
	}
	host, port, err := net.SplitHostPort(item.Target)
	if err != nil {
		return item.Target
	}
	if host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

func monitorTLSModeLabel(item monitor.Monitor) string {
	switch item.Kind {
	case monitor.KindHTTPS:
		return ""
	case monitor.KindSMTP, monitor.KindIMAP:
		securityMode, verifyCertificate, family := monitor.ParseMailTLSMode(item.TLSMode)
		parts := make([]string, 0, 2)
		switch securityMode {
		case monitor.TLSModeNone:
			parts = append(parts, "Plaintext")
		case monitor.TLSModeSTARTTLS:
			if verifyCertificate {
				parts = append(parts, "STARTTLS")
			} else {
				parts = append(parts, "STARTTLS (selfsigned)")
			}
		default:
			if verifyCertificate {
				parts = append(parts, "TLS")
			} else {
				parts = append(parts, "TLS (selfsigned)")
			}
		}
		host := ""
		if parsedHost, _, err := net.SplitHostPort(strings.TrimSpace(item.Target)); err == nil {
			host = strings.TrimSpace(strings.Trim(parsedHost, "[]"))
		}
		if host != "" && !isLiteralIPAddress(host) {
			switch family {
			case monitor.TCPAddressFamilyIPv4:
				parts = append(parts, "IPv4")
			case monitor.TCPAddressFamilyIPv6:
				parts = append(parts, "IPv6")
			default:
				parts = append(parts, "Dual Stack")
			}
		}
		return strings.Join(parts, " · ")
	case monitor.KindTCP:
		securityMode, _, family := monitor.ParseTCPTLSMode(item.TLSMode)
		parts := make([]string, 0, 2)
		switch securityMode {
		case monitor.TLSModeTLS:
			parts = append(parts, "TLS")
		case monitor.TLSModeSTARTTLS:
			parts = append(parts, "TLS (selfsigned)")
		}
		switch family {
		case monitor.TCPAddressFamilyIPv4:
			parts = append(parts, "IPv4")
		case monitor.TCPAddressFamilyIPv6:
			parts = append(parts, "IPv6")
		}
		return strings.Join(parts, " · ")
	case monitor.KindICMP:
		switch item.TLSMode {
		case monitor.TLSModeTLS:
			return "IPv4"
		case monitor.TLSModeSTARTTLS:
			return "IPv6"
		case monitor.TLSModeNone:
			if !isLiteralIPAddress(item.Target) {
				return "Dual Stack"
			}
			return ""
		default:
			return ""
		}
	case monitor.KindUDP:
		probeKind, family := monitor.ParseUDPMode(item.TLSMode)
		kindLabel := "WireGuard"
		switch probeKind {
		case monitor.UDPProbeKindDNS:
			kindLabel = "DNS"
		case monitor.UDPProbeKindNTP:
			kindLabel = "NTP"
		}
		if monitor.IsExplicitUDPFamilyMode(item.TLSMode) {
			switch family {
			case monitor.TCPAddressFamilyIPv4:
				return kindLabel + " · IPv4"
			case monitor.TCPAddressFamilyIPv6:
				return kindLabel + " · IPv6"
			default:
				return kindLabel + " · Dual Stack"
			}
		}
		return kindLabel
	default:
		return ""
	}
}

func isTimeoutMessage(message string) bool {
	text := strings.ToLower(strings.TrimSpace(message))
	if text == "" {
		return false
	}
	return strings.Contains(text, "timeout") ||
		strings.Contains(text, "timed out") ||
		strings.Contains(text, "deadline exceeded") ||
		strings.Contains(text, "i/o timeout")
}

func normalizeHTTPMonitorTarget(raw string, mode monitor.TLSMode) string {
	target := strings.TrimSpace(raw)
	if target == "" {
		return target
	}
	if strings.Contains(target, "://") {
		return target
	}
	target = strings.TrimPrefix(target, "//")
	if mode == monitor.TLSModeNone {
		return "http://" + target
	}
	return "https://" + target
}

func isLiteralIPAddress(raw string) bool {
	target := strings.TrimSpace(raw)
	target = strings.Trim(target, "[]")
	if target == "" {
		return false
	}
	return net.ParseIP(target) != nil
}

func monitorHTTPKindLabel(target string, mode monitor.TLSMode) string {
	securityMode, _, family := monitor.ParseHTTPSTLSMode(mode)
	base := "HTTPS"
	switch securityMode {
	case monitor.TLSModeNone:
		base = "HTTP"
	case monitor.TLSModeSTARTTLS:
		base = "HTTPS (selfsigned)"
	}

	parsed, err := url.Parse(strings.TrimSpace(target))
	hasLiteralIPHost := false
	if err == nil && parsed != nil {
		hostname := strings.TrimSpace(parsed.Hostname())
		hasLiteralIPHost = isLiteralIPAddress(hostname)
	}

	switch family {
	case monitor.TCPAddressFamilyIPv4:
		return base + " · IPv4"
	case monitor.TCPAddressFamilyIPv6:
		return base + " · IPv6"
	case monitor.TCPAddressFamilyDual:
		if !hasLiteralIPHost {
			return base + " · Dual Stack"
		}
		return base
	default:
		return base
	}
}

func buildHTTPMonitorTarget(host string, port string, path string, mode monitor.TLSMode) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return normalizeHTTPMonitorTarget(path, mode)
	}
	port = strings.TrimSpace(port)
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	path = strings.TrimSpace(path)
	if path != "" && !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "?") {
		path = "/" + path
	}

	scheme := "https://"
	if mode == monitor.TLSModeNone {
		scheme = "http://"
	}
	return scheme + host + path
}

// ========== Tenant-Specific Login Handlers (Multi-Tenant SSO) ==========
