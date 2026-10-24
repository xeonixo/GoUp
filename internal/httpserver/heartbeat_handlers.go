package httpserver

import (
	"context"
	"errors"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// heartbeatBodyLimit bounds ping bodies; only the first heartbeatMessageMaxRunes are kept.
	heartbeatBodyLimit       = 10 << 10
	heartbeatMessageMaxRunes = 200
	// heartbeatMinSpacing is the shortest gap between two recorded pings of one monitor with
	// the same outcome; faster repeats are acknowledged but not stored again.
	heartbeatMinSpacing = 2 * time.Second
	// heartbeatProcessTimeout bounds storing and dispatching one ping.
	heartbeatProcessTimeout = 30 * time.Second
)

// isHeartbeatPath reports whether path is a public heartbeat ping URL.
func isHeartbeatPath(path string) bool {
	return strings.HasPrefix(path, "/hb/")
}

// handleHeartbeatPing is the public endpoint cron jobs call: GET|POST|HEAD /hb/{tenantSlug}/{token}
// records a successful run. Unknown slugs and tokens get the same 404; repeated misses lock the
// client IP out for a while. A paused monitor answers 200 and only remembers the ping time, so
// resuming it does not flag the silence of the pause.
func (s *Server) handleHeartbeatPing(w http.ResponseWriter, r *http.Request) {
	s.serveHeartbeat(w, r, true)
}

// handleHeartbeatFail is the same URL with /fail: the job reports a failed run (DOWN).
func (s *Server) handleHeartbeatFail(w http.ResponseWriter, r *http.Request) {
	s.serveHeartbeat(w, r, false)
}

func (s *Server) serveHeartbeat(w http.ResponseWriter, r *http.Request, success bool) {
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodHead:
	default:
		w.Header().Set("Allow", "GET, POST, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now()
	key := "heartbeat|" + s.rateLimitIP(r)
	if allowed, _ := s.bootstrapAllowed(key, now); !allowed {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	snapshot, appStore, tenantID, ok := s.lookupHeartbeatMonitor(r)
	if !ok {
		s.registerBootstrapFailure(key, now)
		http.NotFound(w, r)
		return
	}

	message, err := readHeartbeatMessage(w, r)
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Detached from the request: a script that hangs up early must not lose its ping.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), heartbeatProcessTimeout)
	defer cancel()
	item := snapshot.Monitor
	if err := appStore.RecordHeartbeat(ctx, item.ID, now, success); err != nil {
		s.logger.Error("record heartbeat failed", "monitor_id", item.ID, "error", err)
		http.Error(w, "unable to record heartbeat", http.StatusInternalServerError)
		return
	}

	repeat := item.LastHeartbeatAt != nil && now.Sub(*item.LastHeartbeatAt) < heartbeatMinSpacing && item.LastHeartbeatFailed == !success
	if item.Enabled && !repeat {
		result := monitor.Result{MonitorID: item.ID, CheckedAt: now.UTC(), Status: monitor.StatusUp, Message: message}
		if success && result.Message == "" {
			result.Message = monitor.HeartbeatMessageReceived
		}
		if !success {
			result.Status = monitor.StatusDown
			if result.Message == "" {
				result.Message = monitor.HeartbeatMessageFailed
			}
		}
		dispatcher := s.remoteNodeDispatcher(ctx, appStore, tenantID)
		if !dispatcher.ProcessResult(ctx, snapshot, result) {
			http.Error(w, "unable to store result", http.StatusInternalServerError)
			return
		}
		s.statusCache.invalidate()
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "OK")
	}
}

// lookupHeartbeatMonitor resolves {tenantSlug}/{token} to a heartbeat monitor and its store.
func (s *Server) lookupHeartbeatMonitor(r *http.Request) (monitor.Snapshot, *store.Store, int64, bool) {
	slug := strings.ToLower(strings.TrimSpace(r.PathValue("tenantSlug")))
	token := strings.TrimSpace(r.PathValue("token"))
	if slug == "" || token == "" || len(token) > 128 {
		return monitor.Snapshot{}, nil, 0, false
	}
	tenant, err := s.controlStore.GetTenantBySlug(r.Context(), slug)
	if err != nil || !tenant.Active {
		return monitor.Snapshot{}, nil, 0, false
	}
	appStore := s.store
	if s.tenantStores != nil {
		if appStore, err = s.tenantStores.StoreForTenant(r.Context(), tenant.ID); err != nil {
			return monitor.Snapshot{}, nil, 0, false
		}
	}
	snapshot, err := appStore.GetMonitorSnapshotByHeartbeatToken(r.Context(), token)
	if err != nil {
		return monitor.Snapshot{}, nil, 0, false
	}
	return snapshot, appStore, tenant.ID, true
}

// readHeartbeatMessage returns the first 200 characters of a text body as single-line message;
// binary or empty bodies yield "". It errors only when the body exceeds the size limit.
func readHeartbeatMessage(w http.ResponseWriter, r *http.Request) (string, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return "", nil
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, heartbeatBodyLimit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return "", err
		}
		return "", nil
	}
	if !utf8.Valid(raw) {
		return "", nil
	}
	var b strings.Builder
	count := 0
	for _, ch := range string(raw) {
		if count >= heartbeatMessageMaxRunes {
			break
		}
		switch {
		case ch == '\n' || ch == '\r' || ch == '\t':
			ch = ' '
		case unicode.IsControl(ch):
			return "", nil
		}
		b.WriteRune(ch)
		count++
	}
	return strings.TrimSpace(b.String()), nil
}
