package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"goup/internal/monitor"
	"goup/internal/notify"
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

	// Remote results go through the same dispatcher as the local runner: identical notifier set
	// (including webhooks), mute and confirm_after handling, and the persistent retry queue.
	dispatcher := s.remoteNodeDispatcher(r.Context(), appStore, node.TenantID)

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
		if !dispatcher.ProcessResult(r.Context(), monitor.Snapshot{Monitor: monitorConfig, LastResult: previousByID[monitorConfig.ID]}, result) {
			continue
		}
		resultCopy := result
		previousByID[monitorConfig.ID] = &resultCopy
		accepted++
	}
	// Polls and fully accepted reports arrive every few seconds; only rejected results are worth an event row.
	if accepted < len(payload.Results) {
		_ = s.controlStore.InsertRemoteNodeEvent(r.Context(), node.TenantID, node.NodeID, "report", s.clientIP(r), strings.TrimSpace(r.UserAgent()), fmt.Sprintf("accepted=%d received=%d", accepted, len(payload.Results)), time.Now().UTC())
	}

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

func (s *Server) remoteNodeDispatcher(ctx context.Context, appStore *store.Store, tenantID int64) *monitor.Dispatcher {
	var notifiers []monitor.Notifier
	tenant, err := s.controlStore.GetTenantByID(ctx, tenantID)
	if err == nil {
		notifiers, err = notify.Build(ctx, s.controlStore, appStore, notify.Options{
			TenantID:   tenantID,
			TenantSlug: tenant.Slug,
			BaseURL:    s.cfg.BaseURL,
		})
	}
	if err != nil {
		s.logger.Warn("build notifiers for remote node report failed", "tenant_id", tenantID, "error", err)
	}
	return monitor.NewDispatcher(s.logger, appStore, notifiers...)
}
