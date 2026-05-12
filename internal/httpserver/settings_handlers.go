package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (s *Server) handleSettingsUsers(w http.ResponseWriter, r *http.Request) {
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
		s.logger.Error("settings users load tenant failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load tenant", http.StatusInternalServerError)
		return
	}

	tenantUsers, err := s.controlStore.ListTenantUsers(r.Context(), user.TenantID)
	if err != nil {
		s.logger.Error("settings users list tenant users failed", "tenant_id", user.TenantID, "error", err)
		http.Error(w, "unable to load users", http.StatusInternalServerError)
		return
	}

	s.render(w, "settings_users", pageData{
		Title:            "Einstellungen · Benutzer · GoUp",
		User:             user,
		AdminTenant:      tenant,
		AdminTenantUsers: tenantUsers,
		AppBase:          s.tenantAppBase(r),
		Notice:           strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:            strings.TrimSpace(r.URL.Query().Get("error")),
	})
}

func (s *Server) handleSettingsUserRoleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil || userID <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Ungültige Benutzer-ID"), http.StatusSeeOther)
		return
	}

	role := strings.TrimSpace(r.FormValue("role"))
	if err := s.controlStore.UpdateTenantUserRole(r.Context(), user.TenantID, userID, role); err != nil {
		s.logger.Error("settings users update role failed", "tenant_id", user.TenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Rolle konnte nicht aktualisiert werden"), http.StatusSeeOther)
		return
	}
	if userID == user.UserID {
		user.Role = strings.ToLower(strings.TrimSpace(role))
		user.SessionVersion++
		_ = s.sessions.Set(w, *user)
	}

	s.writeAudit(r, "tenant_user.role_update", "tenant", user.TenantID, fmt.Sprintf("user_id=%d role=%s", userID, role))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Rolle aktualisiert"), http.StatusSeeOther)
}

func (s *Server) handleSettingsUserRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil || userID <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Ungültige Benutzer-ID"), http.StatusSeeOther)
		return
	}
	if userID == user.UserID {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Du kannst dich nicht selbst aus dem Tenant entfernen"), http.StatusSeeOther)
		return
	}

	if err := s.controlStore.RemoveUserFromTenant(r.Context(), user.TenantID, userID); err != nil {
		s.logger.Error("settings users remove failed", "tenant_id", user.TenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Benutzer konnte nicht entfernt werden"), http.StatusSeeOther)
		return
	}

	s.writeAudit(r, "tenant_user.remove", "tenant", user.TenantID, fmt.Sprintf("user_id=%d", userID))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Benutzer entfernt"), http.StatusSeeOther)
}

func (s *Server) handleSettingsLocalUserForm(w http.ResponseWriter, r *http.Request) {
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
		http.NotFound(w, r)
		return
	}

	data := pageData{
		Title:        "Lokales Konto · GoUp",
		User:         user,
		AdminTenant:  tenant,
		FormAction:   s.tenantAppBase(r) + "settings/local-users/save",
		BackURL:      s.tenantAppBase(r) + "settings/users",
		SettingsMode: true,
		AppBase:      s.tenantAppBase(r),
		Notice:       strings.TrimSpace(r.URL.Query().Get("notice")),
		Error:        strings.TrimSpace(r.URL.Query().Get("error")),
	}

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	if userIDRaw != "" {
		userID, err := strconv.ParseInt(userIDRaw, 10, 64)
		if err != nil {
			http.Error(w, "invalid user id", http.StatusBadRequest)
			return
		}
		localUser, err := s.controlStore.GetLocalUserByID(r.Context(), user.TenantID, userID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data.AdminLocalUser = localUser
		data.IsEdit = true
	}

	s.render(w, "admin_local_user_form", data)
}

func (s *Server) handleSettingsLocalUserSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
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

	if _, err := s.controlStore.UpsertAuthProvider(r.Context(), user.TenantID, "local-primary", "local", "Local Login", "", ""); err != nil {
		s.logger.Error("settings ensure local auth provider failed", "tenant_id", user.TenantID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Lokaler Provider konnte nicht angelegt werden"), http.StatusSeeOther)
		return
	}

	if userIDRaw == "" {
		if strings.TrimSpace(password) == "" {
			http.Redirect(w, r, s.tenantAppBase(r)+"settings/local-users/new?error="+url.QueryEscape("Passwort ist erforderlich"), http.StatusSeeOther)
			return
		}
		_, err := s.controlStore.CreateLocalUserForTenant(r.Context(), user.TenantID, loginName, password, email, displayName, role)
		if err != nil {
			s.logger.Error("settings create local user failed", "tenant_id", user.TenantID, "error", err)
			http.Redirect(w, r, s.tenantAppBase(r)+"settings/local-users/new?error="+url.QueryEscape("Lokaler Benutzer konnte nicht erstellt werden"), http.StatusSeeOther)
			return
		}
		s.writeAudit(r, "local_user.create", "tenant", user.TenantID, fmt.Sprintf("login=%s email=%s source=settings", loginName, email))
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Lokaler Benutzer erstellt"), http.StatusSeeOther)
		return
	}

	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	_, err = s.controlStore.UpdateLocalUserForTenant(r.Context(), user.TenantID, userID, loginName, password, email, displayName, role)
	if err != nil {
		s.logger.Error("settings update local user failed", "tenant_id", user.TenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/local-users/"+strconv.FormatInt(userID, 10)+"/edit?error="+url.QueryEscape("Lokaler Benutzer konnte nicht gespeichert werden"), http.StatusSeeOther)
		return
	}

	if userID == user.UserID {
		if session, err := s.sessionForRequest(r); err == nil {
			session.Role = role
			_ = s.sessions.Set(w, *session)
		}
	}

	s.writeAudit(r, "local_user.update", "tenant", user.TenantID, fmt.Sprintf("user_id=%d login=%s source=settings", userID, loginName))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Lokaler Benutzer gespeichert"), http.StatusSeeOther)
}

func (s *Server) handleSettingsLocalUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.currentUser(r)
	if user == nil || user.TenantID <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userIDRaw := strings.TrimSpace(r.PathValue("userID"))
	userID, err := strconv.ParseInt(userIDRaw, 10, 64)
	if err != nil || userID <= 0 {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Ungültige Benutzer-ID"), http.StatusSeeOther)
		return
	}
	if userID == user.UserID {
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Du kannst dich nicht selbst löschen"), http.StatusSeeOther)
		return
	}

	if err := s.controlStore.DeleteLocalUserFromTenant(r.Context(), user.TenantID, userID); err != nil {
		s.logger.Error("settings delete local user failed", "tenant_id", user.TenantID, "user_id", userID, "error", err)
		http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?error="+url.QueryEscape("Lokaler Benutzer konnte nicht entfernt werden"), http.StatusSeeOther)
		return
	}

	s.writeAudit(r, "local_user.delete", "tenant", user.TenantID, fmt.Sprintf("user_id=%d source=settings", userID))
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/users?notice="+url.QueryEscape("Lokaler Benutzer entfernt"), http.StatusSeeOther)
}
