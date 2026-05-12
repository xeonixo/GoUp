package httpserver

import (
	"fmt"
	store "goup/internal/store/sqlite"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (s *Server) handleAdminLocalUsersList(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	id := strings.TrimSpace(r.PathValue("id"))
	tenantID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	tenant, err := s.controlStore.GetTenantByID(r.Context(), tenantID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	tenantUsers, err := s.controlStore.ListTenantUsers(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("list tenant users failed", "tenant_id", tenantID, "error", err)
		http.Error(w, "unable to load tenant users", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_local_users", pageData{
		Title:             fmt.Sprintf("Benutzer für %s · GoUp", tenant.Name),
		User:              user,
		ControlPlaneAdmin: true,
		AdminTenant:       tenant,
		AdminTenantUsers:  tenantUsers,
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleAdminLocalUserForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
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

	data := pageData{
		Title:             fmt.Sprintf("Lokaler Benutzer für %s · GoUp", tenant.Name),
		User:              user,
		ControlPlaneAdmin: true,
		AdminTenant:       tenant,
		FormAction:        fmt.Sprintf("/admin/tenants/%d/local-users/save", tenant.ID),
		Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:             strings.TrimSpace(r.URL.Query().Get("error")),
		AdminLocalUser:    store.LocalUser{TenantID: tenant.ID, Role: "viewer"},
	}

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	if userIDRaw != "" {
		userID, err := strconv.ParseInt(userIDRaw, 10, 64)
		if err != nil {
			http.Error(w, "invalid user id", http.StatusBadRequest)
			return
		}
		localUser, err := s.controlStore.GetLocalUserByID(r.Context(), tenantID, userID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data.AdminLocalUser = localUser
		data.IsEdit = true
	}

	s.render(w, "admin_local_user_form", data)
}

func (s *Server) handleAdminLocalUserSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}

	userIDRaw := strings.TrimSpace(r.FormValue("user_id"))
	loginName := strings.TrimSpace(r.FormValue("login_name"))
	password := r.FormValue("password")
	email := strings.TrimSpace(r.FormValue("email"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	role := strings.TrimSpace(r.FormValue("role"))

	if role == "" {
		role = "viewer"
	}

	if _, err := s.controlStore.UpsertAuthProvider(r.Context(), tenantID, "local-primary", "local", "Local Login", "", ""); err != nil {
		s.logger.Error("ensure local auth provider failed", "tenant_id", tenantID, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?error=%s", tenantID, url.QueryEscape("Lokaler Provider konnte nicht angelegt werden")), http.StatusSeeOther)
		return
	}

	if userIDRaw == "" {
		if strings.TrimSpace(password) == "" {
			http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users/new?error=%s", tenantID, url.QueryEscape("Passwort ist erforderlich")), http.StatusSeeOther)
			return
		}
		_, err := s.controlStore.CreateLocalUserForTenant(r.Context(), tenantID, loginName, password, email, displayName, role)
		if err != nil {
			s.logger.Error("create local user failed", "tenant_id", tenantID, "error", err)
			http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users/new?error=%s", tenantID, url.QueryEscape("Lokaler Benutzer konnte nicht erstellt werden")), http.StatusSeeOther)
			return
		}
		s.writeAudit(r, "local_user.create", "tenant", tenantID, fmt.Sprintf("login=%s email=%s", loginName, email))
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?notice=%s", tenantID, url.QueryEscape("Lokaler Benutzer erstellt")), http.StatusSeeOther)
		return
	}

	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	_, err = s.controlStore.UpdateLocalUserForTenant(r.Context(), tenantID, userID, loginName, password, email, displayName, role)
	if err != nil {
		s.logger.Error("update local user failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users/%d/edit?error=%s", tenantID, userID, url.QueryEscape("Lokaler Benutzer konnte nicht gespeichert werden")), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "local_user.update", "tenant", tenantID, fmt.Sprintf("user_id=%d login=%s", userID, loginName))

	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?notice=%s", tenantID, url.QueryEscape("Lokaler Benutzer gespeichert")), http.StatusSeeOther)
}

func (s *Server) handleAdminLocalUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	if err := s.controlStore.DeleteLocalUserFromTenant(r.Context(), tenantID, userID); err != nil {
		s.logger.Error("delete local user failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?error=%s", tenantID, url.QueryEscape("Lokaler Benutzer konnte nicht entfernt werden")), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "local_user.delete", "tenant", tenantID, fmt.Sprintf("user_id=%d", userID))

	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?notice=%s", tenantID, url.QueryEscape("Lokaler Benutzer entfernt")), http.StatusSeeOther)
}

func (s *Server) handleAdminTenantUserRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantIDRaw := strings.TrimSpace(r.PathValue("id"))
	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	tenantID, err := strconv.ParseInt(tenantIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid tenant id", http.StatusBadRequest)
		return
	}
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	if err := s.controlStore.RemoveUserFromTenant(r.Context(), tenantID, userID); err != nil {
		s.logger.Error("remove tenant user failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?error=%s", tenantID, url.QueryEscape("Benutzer konnte nicht entfernt werden")), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "tenant_user.remove", "tenant", tenantID, fmt.Sprintf("user_id=%d", userID))

	http.Redirect(w, r, fmt.Sprintf("/admin/tenants/%d/local-users?notice=%s", tenantID, url.QueryEscape("Benutzer entfernt")), http.StatusSeeOther)
}
