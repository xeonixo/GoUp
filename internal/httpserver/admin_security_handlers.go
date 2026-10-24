package httpserver

import (
	"golang.org/x/crypto/bcrypt"
	"goup/internal/auth"
	"net/http"
	"net/url"
	"strings"
)

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
			s.clearControlPlaneAdminCookie(w, r)
			s.clearControlPlaneTOTPCookie(w, r)
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
	s.clearControlPlaneAdminCookie(w, r)
	s.clearControlPlaneTOTPCookie(w, r)
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
