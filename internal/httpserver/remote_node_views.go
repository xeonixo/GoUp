package httpserver

import (
	"fmt"
	store "goup/internal/store/sqlite"
	"strings"
	"time"
)

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

type monitorExecutorOptionView struct {
	Value    string
	Label    string
	Selected bool
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
