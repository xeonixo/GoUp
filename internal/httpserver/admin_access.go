package httpserver

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"goup/internal/auth"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) handleAdminAccess(w http.ResponseWriter, r *http.Request) {
	setupRequired, err := s.controlStore.IsSetupRequired(r.Context())
	if err != nil {
		http.Error(w, "unable to verify control-plane setup", http.StatusInternalServerError)
		return
	}
	if setupRequired {
		http.Redirect(w, r, "/admin/setup", http.StatusSeeOther)
		return
	}

	if strings.TrimSpace(r.URL.Query().Get("logout")) == "1" {
		s.clearControlPlaneAdminCookie(w)
		s.clearControlPlaneTOTPCookie(w)
		http.Redirect(w, r, "/admin/access?notice="+url.QueryEscape("Control-Plane-Admin abgemeldet"), http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/admin/access?error="+url.QueryEscape("Ungültiges Formular"), http.StatusSeeOther)
			return
		}

		admin, err := s.controlStore.GetControlPlaneAdmin(r.Context())
		if err != nil {
			http.Redirect(w, r, "/admin/access?error="+url.QueryEscape("Admin-Konto konnte nicht geladen werden"), http.StatusSeeOther)
			return
		}

		adminKey := s.adminAccessKey(r)
		now := time.Now()
		if allowed, waitFor := s.adminAccessAllowed(adminKey, now); !allowed {
			s.writeAudit(r, "control_plane.login.lockout", "system", 1, "admin access locked")
			http.Redirect(w, r, "/admin/access?error="+url.QueryEscape(fmt.Sprintf("Zu viele Versuche. Bitte %d Minuten warten.", int(waitFor.Minutes())+1)), http.StatusSeeOther)
			return
		}

		code := strings.TrimSpace(r.FormValue("otp"))
		if code == "" {
			code = strings.TrimSpace(r.FormValue("totp_code"))
		}
		if admin.TOTPEnabled && code != "" {
			if !s.hasControlPlaneTOTPCookie(r, admin.Username) {
				s.registerAdminAccessFailure(adminKey, now)
				s.writeAudit(r, "control_plane.login.failure", "system", 1, "totp stage expired")
				http.Redirect(w, r, "/admin/access?error="+url.QueryEscape("TOTP-Anmeldung ist abgelaufen. Bitte erneut anmelden."), http.StatusSeeOther)
				return
			}
			if !auth.TOTPValidate(admin.TOTPSecret, code) {
				s.registerAdminAccessFailure(adminKey, now)
				s.writeAudit(r, "control_plane.login.failure", "system", 1, "invalid totp")
				http.Redirect(w, r, "/admin/access?totp=1&error="+url.QueryEscape("Ungültiger TOTP-Code"), http.StatusSeeOther)
				return
			}
			s.clearAdminAccessAttempts(adminKey)
			s.clearControlPlaneTOTPCookie(w)
			s.setControlPlaneAdminCookie(w, admin.SessionVersion)
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			return
		}

		providedUsername := strings.TrimSpace(r.FormValue("username"))
		providedPassword := r.FormValue("password")
		if !strings.EqualFold(providedUsername, strings.TrimSpace(admin.Username)) || bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(providedPassword)) != nil {
			s.registerAdminAccessFailure(adminKey, now)
			s.writeAudit(r, "control_plane.login.failure", "system", 1, "invalid credentials")
			http.Redirect(w, r, "/admin/access?error="+url.QueryEscape("Ungültiger Benutzername oder Passwort"), http.StatusSeeOther)
			return
		}

		if admin.TOTPEnabled {
			s.setControlPlaneTOTPCookie(w, admin.Username)
			http.Redirect(w, r, "/admin/access?totp=1", http.StatusSeeOther)
			return
		}

		s.clearAdminAccessAttempts(adminKey)
		s.clearControlPlaneTOTPCookie(w)
		s.setControlPlaneAdminCookie(w, admin.SessionVersion)
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.hasControlPlaneAdminCookie(r) {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	admin, err := s.controlStore.GetControlPlaneAdmin(r.Context())
	if err != nil {
		s.render(w, "admin_access", pageData{
			Title:             "Control-Plane Zugriff · GoUp",
			ControlPlaneAdmin: s.isControlPlaneAdminRequest(r),
			Error:             "Control-Plane-Admin konnte nicht geladen werden. Bitte Logs prüfen.",
			Notice:            strings.TrimSpace(r.URL.Query().Get("notice")),
		})
		return
	}

	s.render(w, "admin_access", pageData{
		Title:                "Control-Plane Zugriff · GoUp",
		ControlPlaneAdmin:    s.isControlPlaneAdminRequest(r),
		AdminUsername:        strings.TrimSpace(admin.Username),
		AdminAccessTOTPStage: admin.TOTPEnabled && strings.TrimSpace(r.URL.Query().Get("totp")) == "1" && s.hasControlPlaneTOTPCookie(r, admin.Username),
		Error:                strings.TrimSpace(r.URL.Query().Get("error")),
		Notice:               strings.TrimSpace(r.URL.Query().Get("notice")),
	})
}

func (s *Server) handleAdminSetup(w http.ResponseWriter, r *http.Request) {
	setupRequired, err := s.controlStore.IsSetupRequired(r.Context())
	if err != nil {
		http.Error(w, "unable to verify setup state", http.StatusInternalServerError)
		return
	}
	if !setupRequired {
		http.Redirect(w, r, "/admin/access", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape("Ungültiges Formular"), http.StatusSeeOther)
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		passwordConfirm := r.FormValue("password_confirm")
		totpCode := strings.TrimSpace(r.FormValue("totp_code"))
		provisionSecret := strings.TrimSpace(r.FormValue("totp_secret"))

		if username == "" {
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape("Benutzername ist erforderlich"), http.StatusSeeOther)
			return
		}
		if len(password) < 12 {
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape("Passwort muss mindestens 12 Zeichen haben"), http.StatusSeeOther)
			return
		}
		if password != passwordConfirm {
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape("Passwörter stimmen nicht überein"), http.StatusSeeOther)
			return
		}
		if provisionSecret == "" || !auth.TOTPValidate(provisionSecret, totpCode) {
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape("Ungültiger TOTP-Code"), http.StatusSeeOther)
			return
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape("Passwort konnte nicht verarbeitet werden"), http.StatusSeeOther)
			return
		}
		if err := s.controlStore.CreateControlPlaneAdmin(r.Context(), username, string(passwordHash)); err != nil {
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape("Admin-Konto konnte nicht erstellt werden"), http.StatusSeeOther)
			return
		}
		if err := s.controlStore.SetControlPlaneAdminTOTP(r.Context(), provisionSecret, true); err != nil {
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape("TOTP konnte nicht aktiviert werden"), http.StatusSeeOther)
			return
		}
		s.writeAudit(r, "control_plane.setup.complete", "system", 1, "initial admin configured")
		http.Redirect(w, r, "/admin/access?notice="+url.QueryEscape("Control-Plane Onboarding abgeschlossen"), http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	secret, provisioningURI, err := issueNewAdminTOTP()
	if err != nil {
		http.Error(w, "unable to initialize TOTP", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_setup", pageData{
		Title:               "Control-Plane Setup · GoUp",
		AdminSetup:          true,
		TOTPSecret:          secret,
		TOTPProvisioningURI: provisioningURI,
		Error:               strings.TrimSpace(r.URL.Query().Get("error")),
		Notice:              strings.TrimSpace(r.URL.Query().Get("notice")),
	})
}

func (s *Server) handleAdminSecuritySettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Ungültiges Formular"), http.StatusSeeOther)
			return
		}
		admin, err := s.controlStore.GetControlPlaneAdmin(r.Context())
		if err != nil {
			http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Admin-Konto konnte nicht geladen werden"), http.StatusSeeOther)
			return
		}
		currentPassword := r.FormValue("current_password")
		if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(currentPassword)) != nil {
			http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Aktuelles Passwort ist falsch"), http.StatusSeeOther)
			return
		}

		securityChanged := false
		newPassword := r.FormValue("new_password")
		newPasswordConfirm := r.FormValue("new_password_confirm")
		if newPassword != "" || newPasswordConfirm != "" {
			if len(newPassword) < 12 {
				http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Neues Passwort muss mindestens 12 Zeichen haben"), http.StatusSeeOther)
				return
			}
			if newPassword != newPasswordConfirm {
				http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Neue Passwörter stimmen nicht überein"), http.StatusSeeOther)
				return
			}
			passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Neues Passwort konnte nicht verarbeitet werden"), http.StatusSeeOther)
				return
			}
			if err := s.controlStore.UpdateControlPlaneAdminPassword(r.Context(), string(passwordHash)); err != nil {
				http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Passwort konnte nicht aktualisiert werden"), http.StatusSeeOther)
				return
			}
			s.writeAudit(r, "control_plane.password.update", "system", 1, "control plane password updated")
			securityChanged = true
		}

		enableTOTP := r.FormValue("enable_totp") == "on"
		if enableTOTP {
			secret := strings.TrimSpace(r.FormValue("totp_secret"))
			code := strings.TrimSpace(r.FormValue("totp_code"))
			if secret == "" || !auth.TOTPValidate(secret, code) {
				http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Ungültiger TOTP-Code"), http.StatusSeeOther)
				return
			}
			if err := s.controlStore.SetControlPlaneAdminTOTP(r.Context(), secret, true); err != nil {
				http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("TOTP konnte nicht aktiviert werden"), http.StatusSeeOther)
				return
			}
			s.writeAudit(r, "control_plane.totp.enable", "system", 1, "totp enabled")
			securityChanged = true
		}

		if securityChanged {
			s.clearControlPlaneAdminCookie(w)
			s.clearControlPlaneTOTPCookie(w)
			http.Redirect(w, r, "/admin/access?notice="+url.QueryEscape("Sicherheitseinstellungen gespeichert. Bitte erneut anmelden."), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/admin/security?notice="+url.QueryEscape("Sicherheitseinstellungen gespeichert"), http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	admin, err := s.controlStore.GetControlPlaneAdmin(r.Context())
	if err != nil {
		http.Redirect(w, r, "/admin/setup", http.StatusSeeOther)
		return
	}
	secret, provisioningURI, err := issueNewAdminTOTP()
	if err != nil {
		http.Error(w, "unable to initialize TOTP", http.StatusInternalServerError)
		return
	}

	s.render(w, "admin_security", pageData{
		Title:               "Control-Plane Sicherheit · GoUp",
		ControlPlaneAdmin:   true,
		AdminUsername:       admin.Username,
		TOTPEnabled:         admin.TOTPEnabled,
		TOTPSecret:          secret,
		TOTPProvisioningURI: provisioningURI,
		Error:               strings.TrimSpace(r.URL.Query().Get("error")),
		Notice:              strings.TrimSpace(r.URL.Query().Get("notice")),
	})
}

func (s *Server) handleAdminTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Ungültiges Formular"), http.StatusSeeOther)
		return
	}
	admin, err := s.controlStore.GetControlPlaneAdmin(r.Context())
	if err != nil {
		http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Admin-Konto konnte nicht geladen werden"), http.StatusSeeOther)
		return
	}
	currentPassword := r.FormValue("current_password")
	if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(currentPassword)) != nil {
		http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("Aktuelles Passwort ist falsch"), http.StatusSeeOther)
		return
	}
	if err := s.controlStore.SetControlPlaneAdminTOTP(r.Context(), "", false); err != nil {
		http.Redirect(w, r, "/admin/security?error="+url.QueryEscape("TOTP konnte nicht deaktiviert werden"), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "control_plane.totp.disable", "system", 1, "totp disabled")
	s.clearControlPlaneAdminCookie(w)
	s.clearControlPlaneTOTPCookie(w)
	http.Redirect(w, r, "/admin/access?notice="+url.QueryEscape("TOTP deaktiviert. Bitte erneut anmelden."), http.StatusSeeOther)
}

func issueNewAdminTOTP() (secret string, provisioningURI string, err error) {
	secret, err = auth.TOTPGenerateSecret()
	if err != nil {
		return "", "", err
	}
	return secret, auth.TOTPOtpAuthURL("GoUp Control Plane", "admin", secret), nil
}

// Admin Handlers
