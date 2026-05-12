package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	store "goup/internal/store/sqlite"

	"github.com/gorilla/websocket"
)

var dashboardLiveUpgraderBase = websocket.Upgrader{
	ReadBufferSize:    1024,
	WriteBufferSize:   1024,
	EnableCompression: true,
}

type dashboardLiveSnapshotResponse struct {
	StatsHTML              string            `json:"stats_html,omitempty"`
	BoardHTML              string            `json:"board_html,omitempty"`
	BoardGroupsHTML        map[string]string `json:"board_groups_html,omitempty"`
	StateEventsHTML        string            `json:"state_events_html,omitempty"`
	NotificationEventsHTML string            `json:"notification_events_html,omitempty"`
	GroupOptionsHTML       string            `json:"group_options_html,omitempty"`
	StatsHash              string            `json:"stats_hash,omitempty"`
	BoardHash              string            `json:"board_hash,omitempty"`
	BoardGroupsHash        map[string]string `json:"board_groups_hash,omitempty"`
	StateEventsHash        string            `json:"state_events_hash,omitempty"`
	NotificationEventsHash string            `json:"notification_events_hash,omitempty"`
	GroupOptionsHash       string            `json:"group_options_hash,omitempty"`
	BoardGroupHashes       map[string]string `json:"-"`
	BoardGroupOrder        []string          `json:"-"`
}

type dashboardLiveRefreshMessage struct {
	Type        string   `json:"type"`
	Parts       []string `json:"parts,omitempty"`
	BoardGroups []string `json:"board_groups,omitempty"`
}

func (s *Server) dashboardLiveUpgrader() websocket.Upgrader {
	upgrader := dashboardLiveUpgraderBase
	upgrader.CheckOrigin = s.websocketOriginAllowed
	return upgrader
}

func (s *Server) dashboardLiveSignature(ctx context.Context, appStore *store.Store) (string, error) {
	stats, err := appStore.DashboardStats(ctx)
	if err != nil {
		return "", err
	}

	snapshots, err := appStore.ListMonitorSnapshots(ctx)
	if err != nil {
		return "", err
	}

	groups, err := appStore.ListMonitorGroupMetadata(ctx)
	if err != nil {
		return "", err
	}

	stateEvents, stateErr := appStore.ListRecentMonitorStateEvents(ctx, 5)
	if stateErr != nil {
		s.logger.Warn("load state events for live signature failed", "error", stateErr)
		stateEvents = nil
	}

	notificationEvents, notifErr := appStore.ListRecentNotificationEvents(ctx, 5)
	if notifErr != nil {
		s.logger.Warn("load notification events for live signature failed", "error", notifErr)
		notificationEvents = nil
	}

	h := sha256.New()
	_, _ = fmt.Fprintf(h, "stats:%d:%d:%d\n", stats.MonitorCount, stats.EnabledMonitorCount, stats.OpenIncidentCount)
	for _, snapshot := range snapshots {
		item := snapshot.Monitor
		_, _ = fmt.Fprintf(h,
			"m:%d|%s|%s|%d|%s|%s|%t|%s|%d|%d|%s\n",
			item.ID,
			strings.TrimSpace(item.Name),
			strings.TrimSpace(item.Group),
			item.SortOrder,
			item.Kind,
			strings.TrimSpace(item.Target),
			item.Enabled,
			item.TLSMode,
			int(item.Interval.Seconds()),
			int(item.Timeout.Seconds()),
			item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		)
		if snapshot.LastResult != nil {
			last := snapshot.LastResult
			_, _ = fmt.Fprintf(h,
				"r:%d|%s|%s|%s|%d\n",
				item.ID,
				last.CheckedAt.UTC().Format(time.RFC3339Nano),
				last.Status,
				strings.TrimSpace(last.Message),
				last.Latency.Milliseconds(),
			)
		}
	}

	for _, group := range groups {
		_, _ = fmt.Fprintf(h, "g:%s|%s|%d\n", strings.TrimSpace(group.Name), strings.TrimSpace(group.IconSlug), group.SortOrder)
	}

	for _, event := range stateEvents {
		_, _ = fmt.Fprintf(h,
			"se:%d|%d|%s|%s|%s|%s\n",
			event.ID,
			event.MonitorID,
			event.CheckedAt.UTC().Format(time.RFC3339Nano),
			strings.TrimSpace(event.FromStatus),
			strings.TrimSpace(event.ToStatus),
			strings.TrimSpace(event.Message),
		)
	}

	for _, event := range notificationEvents {
		_, _ = fmt.Fprintf(h,
			"ne:%d|%d|%d|%s|%s|%s\n",
			event.ID,
			event.MonitorID,
			event.EndpointID,
			strings.TrimSpace(event.EventType),
			event.CreatedAt.UTC().Format(time.RFC3339Nano),
			strings.TrimSpace(event.Error),
		)
		if event.DeliveredAt != nil {
			_, _ = fmt.Fprintf(h, "ned:%d|%s\n", event.ID, event.DeliveredAt.UTC().Format(time.RFC3339Nano))
		}
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
