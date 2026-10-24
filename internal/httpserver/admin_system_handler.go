package httpserver

import (
	"net/http"
	"strings"
)

// adminNavPages maps admin page templates to their highlighted navigation entry.
var adminNavPages = map[string]string{
	"admin_dashboard":             "general",
	"admin_tenants":               "tenants",
	"admin_tenant_form":           "tenants",
	"admin_providers_overview":    "providers",
	"admin_users_overview":        "users",
	"admin_remote_nodes_overview": "remote_nodes",
	"admin_system":                "system",
	"admin_security":              "",
	"admin_providers":             "providers",
	"admin_provider_form":         "providers",
	"admin_local_users":           "users",
	"admin_local_user_form":       "users",
	"admin_remote_nodes":          "remote_nodes",
}

// applyAdminNav selects the active entry and tenant-scoped link set of the admin navigation partial.
func applyAdminNav(data *pageData, name string) {
	active, ok := adminNavPages[name]
	if !ok {
		return
	}
	data.AdminNavActive = active
	switch name {
	case "admin_providers", "admin_provider_form", "admin_local_users", "admin_local_user_form", "admin_remote_nodes":
		data.AdminNavScoped = true
	}
}

func (s *Server) handleAdminSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	view, err := s.collectSystemView(r.Context())
	data := pageData{
		Title:             "System · GoUp",
		User:              s.currentUser(r),
		ControlPlaneAdmin: true,
		SystemView:        &view,
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
	}
	if err != nil {
		s.logger.Error("admin system collect failed", "error", err)
		data.Error = err.Error()
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "admin_system", data)
}
