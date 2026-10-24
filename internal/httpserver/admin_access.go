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

	if strings.TrimSpace(r.URL.Query().Get("logout")) == "1" && r.Method == http.MethodPost {
		if err := s.controlStore.BumpControlPlaneAdminSessionVersion(r.Context()); err != nil {
			s.logger.Warn("bump control-plane admin session version failed", "error", err)
		}
		s.clearControlPlaneAdminCookie(w, r)
		s.clearControlPlaneTOTPCookie(w, r)
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
			s.clearControlPlaneTOTPCookie(w, r)
			s.setControlPlaneAdminCookie(w, r, admin.SessionVersion)
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			return
		}

		providedUsername := strings.TrimSpace(r.FormValue("username"))
		providedPassword := r.FormValue("password")
		// Always run the bcrypt comparison so that a wrong username takes as long
		// as a wrong password.
		passwordErr := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(providedPassword))
		if !strings.EqualFold(providedUsername, strings.TrimSpace(admin.Username)) || passwordErr != nil {
			s.registerAdminAccessFailure(adminKey, now)
			s.writeAudit(r, "control_plane.login.failure", "system", 1, "invalid credentials")
			http.Redirect(w, r, "/admin/access?error="+url.QueryEscape("Ungültiger Benutzername oder Passwort"), http.StatusSeeOther)
			return
		}

		if admin.TOTPUnreadable {
			s.logger.Error("control-plane admin TOTP secret cannot be decrypted; refusing login (restore the correct GOUP_SSO_SECRET_KEY / GOUP_SESSION_KEY)")
			s.writeAudit(r, "control_plane.login.failure", "system", 1, "totp secret unreadable")
			http.Redirect(w, r, "/admin/access?error="+url.QueryEscape("TOTP-Secret ist nicht lesbar. Bitte Schlüssel-Konfiguration prüfen."), http.StatusSeeOther)
			return
		}
		if admin.TOTPEnabled {
			s.setControlPlaneTOTPCookie(w, r, admin.Username)
			http.Redirect(w, r, "/admin/access?totp=1", http.StatusSeeOther)
			return
		}

		s.clearAdminAccessAttempts(adminKey)
		s.clearControlPlaneTOTPCookie(w, r)
		s.setControlPlaneAdminCookie(w, r, admin.SessionVersion)
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
		setupKey := "setup|" + s.rateLimitIP(r)
		now := time.Now()
		if allowed, waitFor := s.adminAccessAllowed(setupKey, now); !allowed {
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape(fmt.Sprintf("Zu viele Versuche. Bitte %d Minuten warten.", int(waitFor.Minutes())+1)), http.StatusSeeOther)
			return
		}
		if !s.verifySetupToken(r.FormValue("setup_token")) {
			s.registerAdminAccessFailure(setupKey, now)
			s.writeAudit(r, "control_plane.setup.failure", "system", 1, "invalid setup token")
			http.Redirect(w, r, "/admin/setup?error="+url.QueryEscape("Ungültiges Setup-Token"), http.StatusSeeOther)
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
