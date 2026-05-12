package httpserver

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

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
