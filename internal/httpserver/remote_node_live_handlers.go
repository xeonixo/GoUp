package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	store "goup/internal/store/sqlite"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type settingsRemoteNodesLiveSnapshotResponse struct {
	Nodes []settingsRemoteNodeLiveNode `json:"nodes"`
}

type settingsRemoteNodeLiveNode struct {
	NodeID        string                            `json:"node_id"`
	Online        bool                              `json:"online"`
	LastSeenAtRaw string                            `json:"last_seen_at_raw,omitempty"`
	Events        []settingsRemoteNodeLiveNodeEvent `json:"events,omitempty"`
}

type settingsRemoteNodeLiveNodeEvent struct {
	EventLabel    string `json:"event_label"`
	SourceIP      string `json:"source_ip,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
	Details       string `json:"details,omitempty"`
	OccurredAtRaw string `json:"occurred_at_raw"`
}

func (s *Server) handleSettingsRemoteNodesLiveSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID := tenantIDFromRequest(r)
	if tenantID <= 0 {
		if user := s.currentUser(r); user != nil {
			tenantID = user.TenantID
		}
	}
	snapshot, _, err := s.loadRemoteNodesLiveSnapshot(r.Context(), tenantID, "settings")
	if err != nil {
		http.Error(w, "unable to load remote nodes snapshot", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, "unable to encode remote nodes snapshot", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleAdminRemoteNodesLiveSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID, err := parseAdminRemoteNodesTenantID(r)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	snapshot, _, err := s.loadRemoteNodesLiveSnapshot(r.Context(), tenantID, "admin")
	if err != nil {
		http.Error(w, "unable to load remote nodes snapshot", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, "unable to encode remote nodes snapshot", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleSettingsRemoteNodesLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.websocketOriginAllowed(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}

	tenantID := tenantIDFromRequest(r)
	if tenantID <= 0 {
		if user := s.currentUser(r); user != nil {
			tenantID = user.TenantID
		}
	}
	s.handleRemoteNodesLive(w, r, tenantID, "settings", func() bool {
		_, err := s.sessionForRequest(r)
		return err == nil
	})
}

func (s *Server) handleAdminRemoteNodesLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.websocketOriginAllowed(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}

	tenantID, err := parseAdminRemoteNodesTenantID(r)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	s.handleRemoteNodesLive(w, r, tenantID, "admin", func() bool {
		return s.hasControlPlaneAdminCookie(r)
	})
}

func (s *Server) handleRemoteNodesLive(w http.ResponseWriter, r *http.Request, tenantID int64, logScope string, sessionValid func() bool) {
	_, previousSignature, err := s.loadRemoteNodesLiveSnapshot(r.Context(), tenantID, logScope)
	if err != nil {
		http.Error(w, "unable to initialize live updates", http.StatusInternalServerError)
		return
	}

	upgrader := s.dashboardLiveUpgrader()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.EnableWriteCompression(true)

	const readTimeout = 120 * time.Second
	const writeTimeout = 10 * time.Second

	conn.SetReadLimit(1024)
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		return nil
	})

	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err == nil {
		_ = conn.WriteJSON(struct {
			Type string `json:"type"`
		}{Type: "connected"})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, readErr := conn.ReadMessage(); readErr != nil {
				return
			}
		}
	}()

	pingTicker := time.NewTicker(25 * time.Second)
	pollTicker := time.NewTicker(4 * time.Second)
	defer pingTicker.Stop()
	defer pollTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case <-pingTicker.C:
			if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.PingMessage, []byte("ping")); err != nil {
				return
			}
		case <-pollTicker.C:
			if sessionValid != nil && !sessionValid() {
				_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				_ = conn.WriteJSON(map[string]string{"type": "session_expired"})
				return
			}
			_, nextSignature, snapshotErr := s.loadRemoteNodesLiveSnapshot(r.Context(), tenantID, logScope)
			if snapshotErr != nil {
				s.logger.Warn("load remote nodes live data failed", "scope", logScope, "tenant_id", tenantID, "error", snapshotErr)
				continue
			}
			if nextSignature == previousSignature {
				continue
			}
			previousSignature = nextSignature

			if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return
			}
			if err := conn.WriteJSON(struct {
				Type string `json:"type"`
			}{Type: "refresh"}); err != nil {
				return
			}
		}
	}
}

func (s *Server) loadSettingsRemoteNodesLiveSnapshot(r *http.Request) (settingsRemoteNodesLiveSnapshotResponse, string, error) {
	tenantID := tenantIDFromRequest(r)
	if tenantID <= 0 {
		if user := s.currentUser(r); user != nil {
			tenantID = user.TenantID
		}
	}
	if tenantID <= 0 {
		return settingsRemoteNodesLiveSnapshotResponse{}, "", fmt.Errorf("tenant not resolved")
	}

	return s.loadRemoteNodesLiveSnapshot(r.Context(), tenantID, "settings")
}

func (s *Server) loadRemoteNodesLiveSnapshot(ctx context.Context, tenantID int64, logScope string) (settingsRemoteNodesLiveSnapshotResponse, string, error) {
	if tenantID <= 0 {
		return settingsRemoteNodesLiveSnapshotResponse{}, "", fmt.Errorf("tenant not resolved")
	}
	nodes, err := s.controlStore.ListRemoteNodesByTenant(ctx, tenantID)
	if err != nil {
		return settingsRemoteNodesLiveSnapshotResponse{}, "", err
	}

	var events []store.RemoteNodeEvent
	if len(nodes) > 0 {
		events, err = s.controlStore.ListRecentRemoteNodeEventsByTenant(ctx, tenantID, 200)
		if err != nil {
			s.logger.Warn("remote node events list failed", "scope", logScope, "tenant_id", tenantID, "error", err)
			events = nil
		}
	}

	views := buildRemoteNodeViews(nodes, time.Now().UTC(), s.cfg.BaseURL, groupRemoteNodeEventsByNode(events, 8))
	snapshot := settingsRemoteNodesLiveSnapshotResponse{
		Nodes: make([]settingsRemoteNodeLiveNode, 0, len(views)),
	}
	for _, view := range views {
		node := settingsRemoteNodeLiveNode{
			NodeID:        view.NodeID,
			Online:        view.Online,
			LastSeenAtRaw: view.LastSeenAtRaw,
		}
		if len(view.Events) > 0 {
			node.Events = make([]settingsRemoteNodeLiveNodeEvent, 0, len(view.Events))
			for _, event := range view.Events {
				node.Events = append(node.Events, settingsRemoteNodeLiveNodeEvent{
					EventLabel:    event.EventLabel,
					SourceIP:      event.SourceIP,
					UserAgent:     event.UserAgent,
					Details:       event.Details,
					OccurredAtRaw: event.OccurredAtRaw,
				})
			}
		}
		snapshot.Nodes = append(snapshot.Nodes, node)
	}

	return snapshot, settingsRemoteNodesLiveSignature(snapshot), nil
}

func parseAdminRemoteNodesTenantID(r *http.Request) (int64, error) {
	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	if tenantIDRaw == "" {
		return 0, fmt.Errorf("missing tenant id")
	}
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil || tenantID <= 0 {
		return 0, fmt.Errorf("invalid tenant id")
	}
	return tenantID, nil
}

func settingsRemoteNodesLiveSignature(snapshot settingsRemoteNodesLiveSnapshotResponse) string {
	h := sha256.New()
	for _, node := range snapshot.Nodes {
		_, _ = fmt.Fprintf(h, "n:%s|%t|%s\n", strings.TrimSpace(node.NodeID), node.Online, strings.TrimSpace(node.LastSeenAtRaw))
		for _, event := range node.Events {
			_, _ = fmt.Fprintf(h, "e:%s|%s|%s|%s|%s\n",
				strings.TrimSpace(event.EventLabel),
				strings.TrimSpace(event.OccurredAtRaw),
				strings.TrimSpace(event.SourceIP),
				strings.TrimSpace(event.UserAgent),
				strings.TrimSpace(event.Details),
			)
		}
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}
