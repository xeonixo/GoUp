package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	store "goup/internal/store/sqlite"
)

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
	var events []store.RemoteNodeEvent
	if len(nodes) > 0 {
		events, err = s.controlStore.ListRecentRemoteNodeEventsByTenant(r.Context(), tenantID, 200)
		if err != nil {
			s.logger.Warn("admin remote node events list failed", "tenant_id", tenantID, "error", err)
			events = nil
		}
	}

	s.render(w, "admin_remote_nodes", pageData{
		Title:             fmt.Sprintf("Remote Nodes für %s · GoUp", tenant.Name),
		User:              s.currentUser(r),
		ControlPlaneAdmin: true,
		AdminTenant:       tenant,
		RemoteNodes:       buildRemoteNodeViews(nodes, time.Now().UTC(), s.cfg.BaseURL, groupRemoteNodeEventsByNode(events, 8)),
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
