package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"goup/internal/monitor"
	emailnotify "goup/internal/notify/email"
	matrixnotify "goup/internal/notify/matrix"
	store "goup/internal/store/sqlite"
	"io"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleRemoteNodeBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload remoteNodeBootstrapRequest
	if err := decodeJSONStrict(w, r, &payload, remoteNodeBootstrapBodyLimit); err != nil {
		if err == errInvalidJSONPayload {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if strings.TrimSpace(payload.NodeID) == "" || strings.TrimSpace(payload.BootstrapKey) == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	now := time.Now()
	attemptKey := s.bootstrapAttemptKey(r, payload.NodeID)
	if allowed, _ := s.bootstrapAllowed(attemptKey, now); !allowed {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	node, err := s.controlStore.AuthenticateRemoteNodeBootstrap(r.Context(), payload.NodeID, payload.BootstrapKey)
	if err != nil {
		s.registerBootstrapFailure(attemptKey, now)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.clearBootstrapAttempts(attemptKey)
	accessToken, expiresAt, err := s.controlStore.IssueRemoteNodeAccessToken(r.Context(), node.ID, remoteNodeAccessTokenTTL)
	if err != nil {
		http.Error(w, "unable to issue access token", http.StatusInternalServerError)
		return
	}
	_ = s.controlStore.TouchRemoteNodeLastSeen(r.Context(), node.ID, time.Now().UTC())
	_ = s.controlStore.InsertRemoteNodeEvent(r.Context(), node.TenantID, node.NodeID, "bootstrap", s.clientIP(r), strings.TrimSpace(r.UserAgent()), "bootstrap successful", time.Now().UTC())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                    true,
		"access_token":          accessToken,
		"access_token_expires":  expiresAt.UTC().Format(time.RFC3339),
		"poll_interval_seconds": remoteNodeDefaultPollIntervalS,
	})
}

func (s *Server) handleRemoteNodePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload remoteNodePollRequest
	if err := decodeJSONStrict(w, r, &payload, remoteNodePollBodyLimit); err != nil {
		if err == errInvalidJSONPayload {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	node, ok := s.authenticateRemoteNodeRequest(w, r)
	if !ok {
		return
	}
	_ = s.controlStore.TouchRemoteNodeLastSeen(r.Context(), node.ID, time.Now().UTC())

	appStore, err := s.tenantStores.StoreForTenant(r.Context(), node.TenantID)
	if err != nil {
		http.Error(w, "unable to resolve tenant store", http.StatusInternalServerError)
		return
	}
	assigned, err := appStore.ListMonitorsByExecutor(r.Context(), "remote", node.NodeID)
	if err != nil {
		http.Error(w, "unable to list assigned monitors", http.StatusInternalServerError)
		return
	}
	monitors := make([]remoteNodeMonitorPayload, 0, len(assigned))
	for _, item := range assigned {
		monitors = append(monitors, remoteNodeMonitorPayload{
			ID:                 item.ID,
			Name:               item.Name,
			Kind:               string(item.Kind),
			Target:             item.Target,
			IntervalSeconds:    int(item.Interval / time.Second),
			TimeoutSeconds:     int(item.Timeout / time.Second),
			TLSMode:            string(item.TLSMode),
			ExpectedStatusCode: item.ExpectedStatusCode,
			ExpectedText:       item.ExpectedText,
			NotifyOnRecovery:   item.NotifyOnRecovery,
		})
	}
	accessToken, expiresAt, err := s.controlStore.IssueRemoteNodeAccessToken(r.Context(), node.ID, remoteNodeAccessTokenTTL)
	if err != nil {
		http.Error(w, "unable to rotate access token", http.StatusInternalServerError)
		return
	}
	_ = s.controlStore.InsertRemoteNodeEvent(r.Context(), node.TenantID, node.NodeID, "poll", s.clientIP(r), strings.TrimSpace(r.UserAgent()), fmt.Sprintf("assigned_monitors=%d", len(monitors)), time.Now().UTC())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                    true,
		"server_time":           time.Now().UTC().Format(time.RFC3339),
		"access_token":          accessToken,
		"access_token_expires":  expiresAt.UTC().Format(time.RFC3339),
		"poll_interval_seconds": remoteNodeDefaultPollIntervalS,
		"assigned_monitors":     monitors,
	})
}

func (s *Server) handleRemoteNodeReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload remoteNodeReportRequest
	if err := decodeJSONStrict(w, r, &payload, remoteNodeReportBodyLimit); err != nil {
		if err == errInvalidJSONPayload {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	node, ok := s.authenticateRemoteNodeRequest(w, r)
	if !ok {
		return
	}
	if len(payload.Results) > remoteNodeReportMaxResults {
		http.Error(w, "too many results", http.StatusRequestEntityTooLarge)
		return
	}
	_ = s.controlStore.TouchRemoteNodeLastSeen(r.Context(), node.ID, time.Now().UTC())

	appStore, err := s.tenantStores.StoreForTenant(r.Context(), node.TenantID)
	if err != nil {
		http.Error(w, "unable to resolve tenant store", http.StatusInternalServerError)
		return
	}

	assigned, err := appStore.ListMonitorsByExecutor(r.Context(), "remote", node.NodeID)
	if err != nil {
		http.Error(w, "unable to list assigned monitors", http.StatusInternalServerError)
		return
	}
	assignedByID := make(map[int64]monitor.Monitor, len(assigned))
	for _, item := range assigned {
		assignedByID[item.ID] = item
	}

	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		http.Error(w, "unable to load monitor snapshots", http.StatusInternalServerError)
		return
	}
	previousByID := make(map[int64]*monitor.Result, len(snapshots))
	for i := range snapshots {
		if snapshots[i].LastResult != nil {
			result := *snapshots[i].LastResult
			previousByID[snapshots[i].Monitor.ID] = &result
		}
	}

	accepted := 0
	for _, item := range payload.Results {
		monitorConfig, ok := assignedByID[item.MonitorID]
		if !ok {
			continue
		}
		result, err := decodeRemoteNodeResult(item, time.Now().UTC())
		if err != nil {
			continue
		}
		result.MonitorID = monitorConfig.ID
		if err := appStore.SaveMonitorResult(r.Context(), result); err != nil {
			continue
		}
		if err := appStore.RecordMonitorState(r.Context(), monitorConfig.ID, result.Status, result.Message, result.CheckedAt); err != nil {
			continue
		}
		if transition, shouldNotify := buildRemoteTransition(monitorConfig, previousByID[monitorConfig.ID], result); shouldNotify {
			s.notifyRemoteTransition(r.Context(), appStore, node.TenantID, transition)
		}
		resultCopy := result
		previousByID[monitorConfig.ID] = &resultCopy
		accepted++
	}
	_ = s.controlStore.InsertRemoteNodeEvent(r.Context(), node.TenantID, node.NodeID, "report", s.clientIP(r), strings.TrimSpace(r.UserAgent()), fmt.Sprintf("accepted=%d received=%d", accepted, len(payload.Results)), time.Now().UTC())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"accepted": accepted,
	})
}

func (s *Server) authenticateRemoteNodeRequest(w http.ResponseWriter, r *http.Request) (store.RemoteNode, bool) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return store.RemoteNode{}, false
	}
	token := strings.TrimSpace(authHeader[len("Bearer "):])
	node, err := s.controlStore.AuthenticateRemoteNodeAccessToken(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return store.RemoteNode{}, false
	}
	return node, true
}

var errInvalidJSONPayload = errors.New("invalid json payload")

func decodeJSONStrict(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return maxBytesErr
		}
		return errInvalidJSONPayload
	}
	if err := dec.Decode(&struct{}{}); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return maxBytesErr
		}
		return errInvalidJSONPayload
	}
	return errInvalidJSONPayload
}

func decodeRemoteNodeResult(item remoteNodeResultPayload, now time.Time) (monitor.Result, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	checkedAt := now
	if strings.TrimSpace(item.CheckedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(item.CheckedAt))
		if err != nil {
			return monitor.Result{}, err
		}
		checkedAt = parsed.UTC()
	}
	if checkedAt.Before(now.Add(-remoteNodeReportMaxPastSkew)) || checkedAt.After(now.Add(remoteNodeReportMaxFutureSkew)) {
		return monitor.Result{}, fmt.Errorf("checked_at outside accepted window")
	}
	status := monitor.Status(strings.ToLower(strings.TrimSpace(item.Status)))
	switch status {
	case monitor.StatusUp, monitor.StatusDown, monitor.StatusDegraded:
	default:
		return monitor.Result{}, fmt.Errorf("unsupported status")
	}
	if item.LatencyMS < 0 || item.LatencyMS > int64(remoteNodeReportMaxPastSkew/time.Millisecond) {
		return monitor.Result{}, fmt.Errorf("invalid latency")
	}
	message := strings.TrimSpace(item.Message)
	if len(message) > remoteNodeReportMaxMessageLen {
		message = message[:remoteNodeReportMaxMessageLen]
	}
	result := monitor.Result{
		MonitorID:        item.MonitorID,
		CheckedAt:        checkedAt,
		Status:           status,
		Latency:          time.Duration(item.LatencyMS) * time.Millisecond,
		Message:          message,
		HTTPStatusCode:   item.HTTPStatusCode,
		TLSValid:         item.TLSValid,
		TLSDaysRemaining: item.TLSDaysRemaining,
	}
	if item.TLSNotAfter != nil && strings.TrimSpace(*item.TLSNotAfter) != "" {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*item.TLSNotAfter)); err == nil {
			value := parsed.UTC()
			result.TLSNotAfter = &value
		}
	}
	return result, nil
}

func buildRemoteTransition(m monitor.Monitor, previous *monitor.Result, current monitor.Result) (monitor.Transition, bool) {
	if previous == nil {
		return monitor.Transition{}, false
	}
	if previous.Status == current.Status {
		return monitor.Transition{}, false
	}
	if current.Status == monitor.StatusUp && !m.NotifyOnRecovery {
		return monitor.Transition{}, false
	}
	return monitor.Transition{
		Monitor:      m,
		Previous:     previous.Status,
		Current:      current.Status,
		CheckedAt:    current.CheckedAt,
		ResultDetail: current.Message,
	}, true
}

func (s *Server) notifyRemoteTransition(ctx context.Context, appStore interface {
	EnsureSystemNotificationEndpoint(context.Context, string, string, string, bool) (int64, error)
	RecordNotificationEvent(context.Context, int64, int64, string, *time.Time, string) error
}, tenantID int64, transition monitor.Transition) {
	tenant, err := s.controlStore.GetTenantByID(ctx, tenantID)
	if err != nil {
		return
	}
	matrixEndpointID, err := appStore.EnsureSystemNotificationEndpoint(ctx, "matrix", "user-matrix", `{}`, true)
	if err != nil {
		return
	}
	emailEndpointID, err := appStore.EnsureSystemNotificationEndpoint(ctx, "email", "user-email", `{}`, true)
	if err != nil {
		return
	}
	notifiers := []monitor.Notifier{
		matrixnotify.NewTenantNotifier(s.controlStore, matrixEndpointID, tenantID),
		emailnotify.NewNotifier(s.controlStore, emailEndpointID, tenantID, s.cfg.BaseURL, tenant.Slug),
	}
	for _, notifier := range notifiers {
		if notifier == nil || !notifier.Enabled() {
			continue
		}
		notifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := notifier.Notify(notifyCtx, transition)
		cancel()
		if err == monitor.ErrNoRecipients {
			continue
		}
		var deliveredAt *time.Time
		errorMessage := ""
		if err == nil {
			now := time.Now().UTC()
			deliveredAt = &now
		} else {
			errorMessage = err.Error()
		}
		_ = appStore.RecordNotificationEvent(ctx, transition.Monitor.ID, notifier.EndpointID(), notifier.EventType(), deliveredAt, errorMessage)
	}
}
