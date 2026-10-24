package httpserver

import (
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
