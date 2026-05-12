package httpserver

import (
	store "goup/internal/store/sqlite"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleSettingsRemoteNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tenant, err := s.controlStore.GetTenantByID(r.Context(), user.TenantID)
	if err != nil {
		s.logger.Error("settings remote nodes load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}

	nodes, err := s.controlStore.ListRemoteNodesByTenant(r.Context(), user.TenantID)
	if err != nil {
		s.logger.Error("settings remote nodes list failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load remote nodes", http.StatusInternalServerError)
		return
	}
	var events []store.RemoteNodeEvent
	if len(nodes) > 0 {
		events, err = s.controlStore.ListRecentRemoteNodeEventsByTenant(r.Context(), user.TenantID, 200)
		if err != nil {
			s.logger.Warn("settings remote node events list failed", "tenant_id", user.TenantID, "error", err)
			events = nil
		}
	}

	s.render(w, "settings_remote_nodes", pageData{
		Title:        "Einstellungen · Remote Nodes · GoUp",
		User:         user,
		AdminTenant:  tenant,
		RemoteNodes:  buildRemoteNodeViews(nodes, time.Now().UTC(), s.cfg.BaseURL, groupRemoteNodeEventsByNode(events, 8)),
		AppBase:      s.tenantAppBase(r),
		Notice:       strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:        strings.TrimSpace(r.URL.Query().Get("error")),
		SettingsMode: true,
	})
}
