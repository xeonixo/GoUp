package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
	emailnotify "goup/internal/notify/email"
	matrixnotify "goup/internal/notify/matrix"
	store "goup/internal/store/sqlite"
)

const (
	remoteNodeAccessTokenTTL       = 5 * time.Minute
	remoteNodeDefaultPollIntervalS = 20
)

type remoteNodeBootstrapRequest struct {
	NodeID       string `json:"node_id"`
	BootstrapKey string `json:"bootstrap_key"`
}

type remoteNodeMonitorPayload struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	Target             string `json:"target"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	TLSMode            string `json:"tls_mode"`
	ExpectedStatusCode *int   `json:"expected_status_code,omitempty"`
	ExpectedText       string `json:"expected_text,omitempty"`
	NotifyOnRecovery   bool   `json:"notify_on_recovery"`
}

type remoteNodeReportRequest struct {
	Results []remoteNodeResultPayload `json:"results"`
}

type remoteNodeResultPayload struct {
	MonitorID        int64   `json:"monitor_id"`
	CheckedAt        string  `json:"checked_at"`
	Status           string  `json:"status"`
	LatencyMS        int64   `json:"latency_ms"`
	Message          string  `json:"message"`
	HTTPStatusCode   *int    `json:"http_status_code,omitempty"`
	TLSValid         *bool   `json:"tls_valid,omitempty"`
	TLSNotAfter      *string `json:"tls_not_after,omitempty"`
	TLSDaysRemaining *int    `json:"tls_days_remaining,omitempty"`
}

func (s *Server) handleCreateRemoteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	redirectBase := s.remoteNodeManageRedirectBase(r)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Ungültiges Formular"), http.StatusSeeOther)
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID <= 0 {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	heartbeatTimeoutSeconds := 120
	if raw := strings.TrimSpace(r.FormValue("heartbeat_timeout_seconds")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 30 {
			heartbeatTimeoutSeconds = value
		}
	}
	node, bootstrapKey, err := s.controlStore.CreateRemoteNode(r.Context(), tenantID, name, heartbeatTimeoutSeconds)
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Remote-Node konnte nicht erstellt werden"), http.StatusSeeOther)
		return
	}
	controlPlaneURL := strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")
	notice := fmt.Sprintf("Remote-Node erstellt. REMOTE_NODE_ID=%s  REMOTE_NODE_BOOTSTRAP_KEY=%s  REMOTE_NODE_CONTROL_PLANE_URL=%s", node.NodeID, bootstrapKey, controlPlaneURL)
	http.Redirect(w, r, redirectBase+"?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}

func (s *Server) handleDeleteRemoteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	redirectBase := s.remoteNodeManageRedirectBase(r)
	tenantID := tenantIDFromRequest(r)
	if tenantID <= 0 {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	nodeID := strings.TrimSpace(r.PathValue("nodeID"))
	if nodeID == "" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Ungültige Remote-Node"), http.StatusSeeOther)
		return
	}
	appStore, err := s.appStore(r)
	if err == nil {
		_ = appStore.ReassignRemoteNodeMonitorsToLocal(r.Context(), nodeID)
	}
	if err := s.controlStore.DeleteRemoteNodeByTenantAndNodeID(r.Context(), tenantID, nodeID); err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Remote-Node konnte nicht gelöscht werden"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, redirectBase+"?notice="+url.QueryEscape("Remote-Node gelöscht. Zugewiesene Monitore laufen wieder lokal."), http.StatusSeeOther)
}

func (s *Server) handleRotateRemoteNodeBootstrapKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	redirectBase := s.remoteNodeManageRedirectBase(r)
	tenantID := tenantIDFromRequest(r)
	if tenantID <= 0 {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Tenant konnte nicht aufgelöst werden"), http.StatusSeeOther)
		return
	}
	nodeID := strings.TrimSpace(r.PathValue("nodeID"))
	if nodeID == "" {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Ungültige Remote-Node"), http.StatusSeeOther)
		return
	}

	bootstrapKey, err := s.controlStore.RotateRemoteNodeBootstrapKey(r.Context(), tenantID, nodeID)
	if err != nil {
		http.Redirect(w, r, redirectBase+"?error="+url.QueryEscape("Bootstrap-Key konnte nicht rotiert werden"), http.StatusSeeOther)
		return
	}
	controlPlaneURL := strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")
	notice := fmt.Sprintf("Bootstrap-Key rotiert. REMOTE_NODE_ID=%s  REMOTE_NODE_BOOTSTRAP_KEY=%s  REMOTE_NODE_CONTROL_PLANE_URL=%s", nodeID, bootstrapKey, controlPlaneURL)
	http.Redirect(w, r, redirectBase+"?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}

func (s *Server) remoteNodeManageRedirectBase(r *http.Request) string {
	base := s.tenantAppBase(r)
	if strings.HasPrefix(r.URL.Path, "/settings/remote-nodes") {
		return base + "settings/remote-nodes"
	}
	return base
}

func (s *Server) handleAdminRemoteNodesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	tenant, err := s.controlStore.GetTenantByID(r.Context(), tenantID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	nodes, err := s.controlStore.ListRemoteNodesByTenant(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "unable to list remote nodes", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_remote_nodes", pageData{
		Title:             fmt.Sprintf("Remote Nodes für %s · GoUp", tenant.Name),
		User:              s.currentUser(r),
		ControlPlaneAdmin: true,
		AdminTenant:       tenant,
		RemoteNodes:       buildRemoteNodeViews(nodes, time.Now().UTC(), s.cfg.BaseURL),
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleAdminCreateRemoteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	if _, err := s.controlStore.GetTenantByID(r.Context(), tenantID); err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/remote-nodes?error=%s", tenantID, url.QueryEscape("Ungültiges Formular")), http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	heartbeatTimeoutSeconds := 120
	if raw := strings.TrimSpace(r.FormValue("heartbeat_timeout_seconds")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value >= 30 {
			heartbeatTimeoutSeconds = value
		}
	}
	node, bootstrapKey, err := s.controlStore.CreateRemoteNode(r.Context(), tenantID, name, heartbeatTimeoutSeconds)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/remote-nodes?error=%s", tenantID, url.QueryEscape("Remote-Node konnte nicht erstellt werden")), http.StatusSeeOther)
		return
	}
	controlPlaneURL := strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")
	notice := fmt.Sprintf("Remote-Node erstellt. REMOTE_NODE_ID=%s  REMOTE_NODE_BOOTSTRAP_KEY=%s  REMOTE_NODE_CONTROL_PLANE_URL=%s", node.NodeID, bootstrapKey, controlPlaneURL)
	s.writeAudit(r, "remote_node.create", "tenant", tenantID, fmt.Sprintf("node_id=%s name=%s", node.NodeID, node.Name))
	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/remote-nodes?notice=%s", tenantID, url.QueryEscape(notice)), http.StatusSeeOther)
}

func (s *Server) handleAdminDeleteRemoteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	if _, err := s.controlStore.GetTenantByID(r.Context(), tenantID); err != nil {
		http.NotFound(w, r)
		return
	}
	nodeID := strings.TrimSpace(r.PathValue("nodeID"))
	if nodeID == "" {
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/remote-nodes?error=%s", tenantID, url.QueryEscape("Ungültige Remote-Node")), http.StatusSeeOther)
		return
	}
	appStore, err := s.tenantStores.StoreForTenant(r.Context(), tenantID)
	if err == nil {
		_ = appStore.ReassignRemoteNodeMonitorsToLocal(r.Context(), nodeID)
	}
	if err := s.controlStore.DeleteRemoteNodeByTenantAndNodeID(r.Context(), tenantID, nodeID); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/remote-nodes?error=%s", tenantID, url.QueryEscape("Remote-Node konnte nicht gelöscht werden")), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "remote_node.delete", "tenant", tenantID, fmt.Sprintf("node_id=%s", nodeID))
	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/remote-nodes?notice=%s", tenantID, url.QueryEscape("Remote-Node gelöscht. Zugewiesene Monitore laufen wieder lokal.")), http.StatusSeeOther)
}

func (s *Server) handleAdminRotateRemoteNodeBootstrapKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	if _, err := s.controlStore.GetTenantByID(r.Context(), tenantID); err != nil {
		http.NotFound(w, r)
		return
	}
	nodeID := strings.TrimSpace(r.PathValue("nodeID"))
	if nodeID == "" {
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/remote-nodes?error=%s", tenantID, url.QueryEscape("Ungültige Remote-Node")), http.StatusSeeOther)
		return
	}

	bootstrapKey, err := s.controlStore.RotateRemoteNodeBootstrapKey(r.Context(), tenantID, nodeID)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/remote-nodes?error=%s", tenantID, url.QueryEscape("Bootstrap-Key konnte nicht rotiert werden")), http.StatusSeeOther)
		return
	}
	controlPlaneURL := strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")
	notice := fmt.Sprintf("Bootstrap-Key rotiert. REMOTE_NODE_ID=%s  REMOTE_NODE_BOOTSTRAP_KEY=%s  REMOTE_NODE_CONTROL_PLANE_URL=%s", nodeID, bootstrapKey, controlPlaneURL)
	s.writeAudit(r, "remote_node.bootstrap.rotate", "tenant", tenantID, fmt.Sprintf("node_id=%s", nodeID))
	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/remote-nodes?notice=%s", tenantID, url.QueryEscape(notice)), http.StatusSeeOther)
}

func (s *Server) handleRemoteNodeBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload remoteNodeBootstrapRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
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
	node, ok := s.authenticateRemoteNodeRequest(w, r)
	if !ok {
		return
	}
	_ = s.controlStore.TouchRemoteNodeLastSeen(r.Context(), node.ID, time.Now().UTC())

	var payload remoteNodeReportRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

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
		result, err := decodeRemoteNodeResult(item)
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

func decodeRemoteNodeResult(item remoteNodeResultPayload) (monitor.Result, error) {
	checkedAt := time.Now().UTC()
	if strings.TrimSpace(item.CheckedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(item.CheckedAt))
		if err != nil {
			return monitor.Result{}, err
		}
		checkedAt = parsed.UTC()
	}
	status := monitor.Status(strings.ToLower(strings.TrimSpace(item.Status)))
	switch status {
	case monitor.StatusUp, monitor.StatusDown, monitor.StatusDegraded:
	default:
		return monitor.Result{}, fmt.Errorf("unsupported status")
	}
	result := monitor.Result{
		MonitorID:        item.MonitorID,
		CheckedAt:        checkedAt,
		Status:           status,
		Latency:          time.Duration(item.LatencyMS) * time.Millisecond,
		Message:          strings.TrimSpace(item.Message),
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
