package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	store "goup/internal/store/sqlite"

	"github.com/gorilla/websocket"
	"golang.org/x/net/html"
)

const (
	dashboardIconsBaseURL     = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons"
	dashboardIconsMetadataURL = "https://raw.githubusercontent.com/homarr-labs/dashboard-icons/refs/heads/main/metadata.json"
	dashboardIconSearchLimit  = 24
	groupIconUploadPrefix     = "upload:"
	groupIconUploadMaxBytes   = 2 << 20
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

func (s *Server) handleDashboardLiveSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	data, err := s.loadDashboardPageData(r, appStore, strings.TrimSpace(r.URL.Query().Get("trend")), "", "")
	if err != nil {
		http.Error(w, "unable to load dashboard snapshot", http.StatusInternalServerError)
		return
	}

	snapshot, err := s.renderDashboardLiveSnapshotResponse(data)
	if err != nil {
		http.Error(w, "unable to render dashboard snapshot", http.StatusInternalServerError)
		return
	}

	parts := parseDashboardLiveRequestedParts(strings.TrimSpace(r.URL.Query().Get("parts")))
	boardGroups := parseDashboardLiveRequestedBoardGroups(strings.TrimSpace(r.URL.Query().Get("board_groups")))
	if len(parts) > 0 {
		snapshot = filterDashboardLiveSnapshotParts(snapshot, parts)
	}
	if len(boardGroups) > 0 && (parts == nil || hasDashboardLivePart(parts, "board")) {
		snapshot = filterDashboardLiveSnapshotBoardGroups(snapshot, boardGroups)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, "unable to encode dashboard snapshot", http.StatusInternalServerError)
		return
	}
}

func (s *Server) renderDashboardTemplateFragment(name string, data pageData) (string, error) {
	tmpl, ok := s.templates["dashboard"]
	if !ok {
		return "", fmt.Errorf("dashboard template not found")
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, name, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

func (s *Server) renderDashboardLiveSnapshotResponse(data pageData) (dashboardLiveSnapshotResponse, error) {
	tmpl, ok := s.templates["dashboard"]
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard template not found")
	}

	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "layout", data); err != nil {
		return dashboardLiveSnapshotResponse{}, err
	}

	doc, err := html.Parse(strings.NewReader(out.String()))
	if err != nil {
		return dashboardLiveSnapshotResponse{}, err
	}

	statsHTML, ok := outerHTMLByID(doc, "dashboard-live-stats")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard stats fragment not found")
	}
	boardHTML, ok := outerHTMLByID(doc, "dashboard-live-board")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard board fragment not found")
	}
	boardNode := htmlNodeByID(doc, "dashboard-live-board")
	boardGroupsHTML, boardGroupOrder := boardClustersByGroup(boardNode)
	boardGroupHashes := make(map[string]string, len(boardGroupsHTML))
	for group, fragment := range boardGroupsHTML {
		boardGroupHashes[group] = hashDashboardFragment(fragment)
	}
	stateEventsHTML, ok := outerHTMLByID(doc, "dashboard-live-state-events")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard state events fragment not found")
	}
	notificationEventsHTML, ok := outerHTMLByID(doc, "dashboard-live-notification-events")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard notification events fragment not found")
	}
	groupOptionsHTML, ok := innerHTMLByID(doc, "monitor-group-options")
	if !ok {
		groupOptionsHTML = ""
	}

	return dashboardLiveSnapshotResponse{
		StatsHTML:              statsHTML,
		BoardHTML:              boardHTML,
		BoardGroupsHTML:        boardGroupsHTML,
		StateEventsHTML:        stateEventsHTML,
		NotificationEventsHTML: notificationEventsHTML,
		GroupOptionsHTML:       groupOptionsHTML,
		StatsHash:              hashDashboardFragment(statsHTML),
		BoardHash:              hashDashboardFragment(boardHTML),
		BoardGroupsHash:        boardGroupHashes,
		StateEventsHash:        hashDashboardFragment(stateEventsHTML),
		NotificationEventsHash: hashDashboardFragment(notificationEventsHTML),
		GroupOptionsHash:       hashDashboardFragment(groupOptionsHTML),
		BoardGroupHashes:       boardGroupHashes,
		BoardGroupOrder:        boardGroupOrder,
	}, nil
}

func hashDashboardFragment(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func parseDashboardLiveRequestedParts(raw string) map[string]struct{} {
	if raw == "" {
		return nil
	}
	allowed := map[string]struct{}{
		"stats":               {},
		"board":               {},
		"state_events":        {},
		"notification_events": {},
		"group_options":       {},
	}
	parts := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		part := strings.TrimSpace(strings.ToLower(item))
		if part == "" {
			continue
		}
		if _, ok := allowed[part]; ok {
			parts[part] = struct{}{}
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return parts
}

func parseDashboardLiveRequestedBoardGroups(raw string) []string {
	if raw == "" {
		return nil
	}
	groups := make([]string, 0, 8)
	seen := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		group := strings.TrimSpace(item)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
		if len(groups) >= 64 {
			break
		}
	}
	if len(groups) == 0 {
		return nil
	}
	return groups
}

func hasDashboardLivePart(parts map[string]struct{}, part string) bool {
	_, ok := parts[part]
	return ok
}

func filterDashboardLiveSnapshotParts(snapshot dashboardLiveSnapshotResponse, parts map[string]struct{}) dashboardLiveSnapshotResponse {
	if _, ok := parts["stats"]; !ok {
		snapshot.StatsHTML = ""
		snapshot.StatsHash = ""
	}
	if _, ok := parts["board"]; !ok {
		snapshot.BoardHTML = ""
		snapshot.BoardHash = ""
		snapshot.BoardGroupsHTML = nil
		snapshot.BoardGroupsHash = nil
	}
	if _, ok := parts["state_events"]; !ok {
		snapshot.StateEventsHTML = ""
		snapshot.StateEventsHash = ""
	}
	if _, ok := parts["notification_events"]; !ok {
		snapshot.NotificationEventsHTML = ""
		snapshot.NotificationEventsHash = ""
	}
	if _, ok := parts["group_options"]; !ok {
		snapshot.GroupOptionsHTML = ""
		snapshot.GroupOptionsHash = ""
	}
	return snapshot
}

func filterDashboardLiveSnapshotBoardGroups(snapshot dashboardLiveSnapshotResponse, groups []string) dashboardLiveSnapshotResponse {
	if len(groups) == 0 {
		return snapshot
	}
	if len(snapshot.BoardGroupsHTML) == 0 {
		return snapshot
	}

	filteredHTML := make(map[string]string)
	filteredHashes := make(map[string]string)
	for _, group := range groups {
		fragment, ok := snapshot.BoardGroupsHTML[group]
		if !ok {
			continue
		}
		filteredHTML[group] = fragment
		hash := snapshot.BoardGroupsHash[group]
		if hash == "" {
			hash = hashDashboardFragment(fragment)
		}
		filteredHashes[group] = hash
	}

	snapshot.BoardHTML = ""
	snapshot.BoardGroupsHTML = filteredHTML
	snapshot.BoardGroupsHash = filteredHashes
	return snapshot
}

func dashboardLiveChangedParts(previous dashboardLiveSnapshotResponse, next dashboardLiveSnapshotResponse) []string {
	parts := make([]string, 0, 5)
	if previous.StatsHash != next.StatsHash {
		parts = append(parts, "stats")
	}
	if previous.BoardHash != next.BoardHash {
		parts = append(parts, "board")
	}
	if previous.StateEventsHash != next.StateEventsHash {
		parts = append(parts, "state_events")
	}
	if previous.NotificationEventsHash != next.NotificationEventsHash {
		parts = append(parts, "notification_events")
	}
	if previous.GroupOptionsHash != next.GroupOptionsHash {
		parts = append(parts, "group_options")
	}
	return parts
}

func dashboardLiveChangedBoardGroups(previous dashboardLiveSnapshotResponse, next dashboardLiveSnapshotResponse) []string {
	if len(previous.BoardGroupOrder) == 0 || len(next.BoardGroupOrder) == 0 {
		return nil
	}
	if !equalStringSlices(previous.BoardGroupOrder, next.BoardGroupOrder) {
		return nil
	}
	if len(previous.BoardGroupHashes) != len(next.BoardGroupHashes) {
		return nil
	}

	changed := make([]string, 0, len(next.BoardGroupOrder))
	for _, group := range next.BoardGroupOrder {
		nextHash, nextOK := next.BoardGroupHashes[group]
		prevHash, prevOK := previous.BoardGroupHashes[group]
		if !nextOK || !prevOK {
			return nil
		}
		if nextHash != prevHash {
			changed = append(changed, group)
		}
	}

	if len(changed) == 0 {
		return nil
	}
	return changed
}

func equalStringSlices(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func boardClustersByGroup(boardNode *html.Node) (map[string]string, []string) {
	if boardNode == nil {
		return nil, nil
	}

	groups := make(map[string]string)
	order := make([]string, 0, 16)
	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node == nil {
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "details") && htmlHasClass(node, "service-cluster") {
			group := htmlAttr(node, "data-group")
			if group != "" {
				var buf bytes.Buffer
				if err := html.Render(&buf, node); err == nil {
					groups[group] = buf.String()
					order = append(order, group)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(boardNode)
	if len(groups) == 0 {
		return nil, nil
	}
	return groups, order
}

func htmlHasClass(node *html.Node, className string) bool {
	if node == nil || className == "" {
		return false
	}
	for _, attr := range node.Attr {
		if attr.Key != "class" {
			continue
		}
		for _, value := range strings.Fields(attr.Val) {
			if value == className {
				return true
			}
		}
	}
	return false
}

func htmlAttr(node *html.Node, key string) string {
	if node == nil || key == "" {
		return ""
	}
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func outerHTMLByID(root *html.Node, id string) (string, bool) {
	node := htmlNodeByID(root, id)
	if node == nil {
		return "", false
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, node); err != nil {
		return "", false
	}
	return buf.String(), true
}

func innerHTMLByID(root *html.Node, id string) (string, bool) {
	node := htmlNodeByID(root, id)
	if node == nil {
		return "", false
	}
	var buf bytes.Buffer
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if err := html.Render(&buf, child); err != nil {
			return "", false
		}
	}
	return buf.String(), true
}

func htmlNodeByID(node *html.Node, id string) *html.Node {
	if node == nil {
		return nil
	}
	if node.Type == html.ElementNode {
		for _, attr := range node.Attr {
			if attr.Key == "id" && attr.Val == id {
				return node
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if match := htmlNodeByID(child, id); match != nil {
			return match
		}
	}
	return nil
}

func (s *Server) handleDashboardLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.websocketOriginAllowed(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		http.Error(w, "unable to resolve tenant", http.StatusInternalServerError)
		return
	}

	trendValue := strings.TrimSpace(r.URL.Query().Get("trend"))
	initialData, err := s.loadDashboardPageData(r, appStore, trendValue, "", "")
	if err != nil {
		http.Error(w, "unable to initialize live updates", http.StatusInternalServerError)
		return
	}
	previousSnapshot, err := s.renderDashboardLiveSnapshotResponse(initialData)
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
			if _, sessErr := s.sessionForRequest(r); sessErr != nil {
				_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				_ = conn.WriteJSON(map[string]string{"type": "session_expired"})
				return
			}
			nextData, dataErr := s.loadDashboardPageData(r, appStore, trendValue, "", "")
			if dataErr != nil {
				s.logger.Warn("load dashboard live data failed", "error", dataErr)
				continue
			}
			nextSnapshot, snapshotErr := s.renderDashboardLiveSnapshotResponse(nextData)
			if snapshotErr != nil {
				s.logger.Warn("render dashboard live snapshot failed", "error", snapshotErr)
				continue
			}

			changedParts := dashboardLiveChangedParts(previousSnapshot, nextSnapshot)
			if len(changedParts) == 0 {
				continue
			}
			changedBoardGroups := make([]string, 0, 8)
			for _, part := range changedParts {
				if part == "board" {
					changedBoardGroups = dashboardLiveChangedBoardGroups(previousSnapshot, nextSnapshot)
					break
				}
			}
			previousSnapshot = nextSnapshot

			if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return
			}
			if err := conn.WriteJSON(dashboardLiveRefreshMessage{Type: "refresh", Parts: changedParts, BoardGroups: changedBoardGroups}); err != nil {
				return
			}
		}
	}
}

func (s *Server) websocketOriginAllowed(r *http.Request) bool {
	origin := normalizeOrigin(strings.TrimSpace(r.Header.Get("Origin")))
	if origin == "" {
		return true
	}

	expected, err := url.Parse(strings.TrimSpace(s.cfg.BaseURL))
	if err != nil || strings.TrimSpace(expected.Scheme) == "" || strings.TrimSpace(expected.Host) == "" {
		return true
	}

	allowed := make(map[string]struct{})
	for _, value := range buildAllowedOrigins(
		strings.ToLower(strings.TrimSpace(expected.Scheme)),
		strings.ToLower(strings.TrimSpace(expected.Hostname())),
		strings.TrimSpace(expected.Port()),
		r,
	) {
		allowed[value] = struct{}{}
	}
	_, ok := allowed[origin]
	return ok
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
