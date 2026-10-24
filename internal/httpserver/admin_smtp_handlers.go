package httpserver

import (
	"fmt"
	store "goup/internal/store/sqlite"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (s *Server) handleAdminSMTPSettingsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	settings, err := parseSMTPSettingsForm(r)
	if err != nil {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	password := r.FormValue("password")

	if err := s.controlStore.UpsertGlobalSMTPSettings(r.Context(), settings, password); err != nil {
		s.logger.Error("save global smtp settings failed", "error", err)
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP-Einstellungen konnten nicht gespeichert werden"), http.StatusSeeOther)
		return
	}
	s.writeAudit(r, "smtp.settings.update", "system", 1, fmt.Sprintf("host=%s port=%d tls=%s", settings.Host, settings.Port, settings.TLSMode))

	http.Redirect(w, r, "/admin/?notice="+url.QueryEscape("SMTP-Einstellungen gespeichert"), http.StatusSeeOther)
}

func (s *Server) handleAdminSMTPSettingsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	settings, err := parseSMTPSettingsForm(r)
	if err != nil {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	recipient := strings.TrimSpace(r.FormValue("test_recipient"))
	if recipient == "" {
		admin, adminErr := s.controlStore.GetControlPlaneAdmin(r.Context())
		if adminErr == nil && strings.Contains(strings.TrimSpace(admin.Username), "@") {
			recipient = strings.TrimSpace(admin.Username)
		}
	}
	if recipient == "" {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("Test-Empfänger ist erforderlich"), http.StatusSeeOther)
		return
	}

	password := strings.TrimSpace(r.FormValue("password"))
	if password == "" {
		currentCfg, cfgErr := s.controlStore.GetGlobalSMTPDeliveryConfig(r.Context())
		if cfgErr != nil {
			s.logger.Warn("load stored smtp password for test failed", "error", cfgErr)
			http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP-Test fehlgeschlagen: "+cfgErr.Error()), http.StatusSeeOther)
			return
		}
		password = strings.TrimSpace(currentCfg.Password)
	}
	cfg := store.GlobalSMTPDeliveryConfig{Settings: settings, Password: password}
	if strings.TrimSpace(cfg.Settings.Host) == "" || strings.TrimSpace(cfg.Settings.FromEmail) == "" {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP Host/Absender ist nicht konfiguriert"), http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(cfg.Password) == "" {
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP Passwort ist nicht konfiguriert"), http.StatusSeeOther)
		return
	}

	body := "Dies ist eine Testnachricht aus der GoUp Control Plane.\n\nWenn diese Nachricht angekommen ist, funktioniert die globale SMTP-Konfiguration."
	if err := sendSMTPMail(cfg, recipient, "GoUp SMTP Test", body); err != nil {
		s.logger.Warn("smtp test failed", "recipient", recipient, "error", err)
		http.Redirect(w, r, "/admin/?error="+url.QueryEscape("SMTP-Test fehlgeschlagen: "+err.Error()), http.StatusSeeOther)
		return
	}

	s.writeAudit(r, "smtp.settings.test", "system", 1, fmt.Sprintf("recipient=%s host=%s port=%d tls=%s", recipient, settings.Host, settings.Port, settings.TLSMode))
	http.Redirect(w, r, "/admin/?notice="+url.QueryEscape("SMTP-Test erfolgreich versendet"), http.StatusSeeOther)
}

func parseSMTPSettingsForm(r *http.Request) (store.GlobalSMTPSettings, error) {
	port := 587
	if rawPort := strings.TrimSpace(r.FormValue("port")); rawPort != "" {
		parsedPort, err := strconv.Atoi(rawPort)
		if err != nil || parsedPort <= 0 || parsedPort > 65535 {
			return store.GlobalSMTPSettings{}, fmt.Errorf("Ungültiger SMTP-Port")
		}
		port = parsedPort
	}

	settings := store.GlobalSMTPSettings{
		Host:      strings.TrimSpace(r.FormValue("host")),
		Port:      port,
		Username:  strings.TrimSpace(r.FormValue("username")),
		FromEmail: strings.TrimSpace(r.FormValue("from_email")),
		FromName:  strings.TrimSpace(r.FormValue("from_name")),
		TLSMode:   strings.TrimSpace(r.FormValue("tls_mode")),
	}
	return settings, nil
}
