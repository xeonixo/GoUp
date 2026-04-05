package httpserver

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const defaultUILanguage = "en"

var flashMessageTranslationKeys = map[string]string{
	"Control-Plane-Admin abgemeldet":                                              "flash.control_plane_admin_logged_out",
	"Ungültiges Formular":                                                         "flash.invalid_form",
	"Admin-Konto konnte nicht geladen werden":                                     "flash.admin_account_load_failed",
	"Ungültiger Benutzername oder Passwort":                                       "flash.invalid_username_or_password",
	"Ungültiger TOTP-Code":                                                        "flash.invalid_totp_code",
	"Benutzername ist erforderlich":                                               "flash.username_required",
	"Passwort muss mindestens 12 Zeichen haben":                                   "flash.password_min_length_12",
	"Passwörter stimmen nicht überein":                                            "flash.passwords_do_not_match",
	"Passwort konnte nicht verarbeitet werden":                                    "flash.password_processing_failed",
	"Admin-Konto konnte nicht erstellt werden":                                    "flash.admin_account_create_failed",
	"TOTP konnte nicht aktiviert werden":                                          "flash.totp_enable_failed",
	"Control-Plane Onboarding abgeschlossen":                                      "flash.control_plane_onboarding_completed",
	"Aktuelles Passwort ist falsch":                                               "flash.current_password_incorrect",
	"Neues Passwort muss mindestens 12 Zeichen haben":                             "flash.new_password_min_length_12",
	"Neue Passwörter stimmen nicht überein":                                       "flash.new_passwords_do_not_match",
	"Neues Passwort konnte nicht verarbeitet werden":                              "flash.new_password_processing_failed",
	"Passwort konnte nicht aktualisiert werden":                                   "flash.password_update_failed",
	"Sicherheitseinstellungen gespeichert":                                        "flash.security_settings_saved",
	"TOTP konnte nicht deaktiviert werden":                                        "flash.totp_disable_failed",
	"TOTP deaktiviert":                                                            "flash.totp_disabled",
	"Ungültiger SMTP-Port":                                                        "flash.invalid_smtp_port",
	"SMTP-Einstellungen konnten nicht gespeichert werden":                         "flash.smtp_settings_save_failed",
	"SMTP-Einstellungen gespeichert":                                              "flash.smtp_settings_saved",
	"Tenant-Speicher konnte nicht vorbereitet werden":                             "flash.tenant_store_prepare_failed",
	"Tenant erstellt":                                                             "flash.tenant_created",
	"Tenant konnte nicht gespeichert werden":                                      "flash.tenant_save_failed",
	"Tenant aktualisiert":                                                         "flash.tenant_updated",
	"Tenant deaktiviert":                                                          "flash.tenant_disabled",
	"Default-Tenant kann nicht restlos gelöscht werden":                           "flash.default_tenant_delete_forbidden",
	"Tenant konnte nicht restlos gelöscht werden":                                 "flash.tenant_full_delete_failed",
	"Tenant wurde gelöscht, aber Icon-Speicher konnte nicht entfernt werden":      "flash.tenant_deleted_icon_cleanup_failed",
	"Tenant restlos gelöscht":                                                     "flash.tenant_fully_deleted",
	"Lokale Provider können nicht bearbeitet werden":                              "flash.local_providers_not_editable",
	"Lokale Provider werden automatisch verwaltet und sind nicht konfigurierbar":  "flash.local_providers_auto_managed",
	"Provider konnte nicht gespeichert werden":                                    "flash.provider_save_failed",
	"Provider gespeichert, Secret konnte nicht gespeichert werden":                "flash.provider_saved_secret_failed",
	"Provider gespeichert":                                                        "flash.provider_saved",
	"Provider deaktiviert":                                                        "flash.provider_disabled",
	"Lokaler Provider konnte nicht angelegt werden":                               "flash.local_provider_create_failed",
	"Passwort ist erforderlich":                                                   "flash.password_required",
	"Lokaler Benutzer konnte nicht erstellt werden":                               "flash.local_user_create_failed",
	"Lokaler Benutzer erstellt":                                                   "flash.local_user_created",
	"Lokaler Benutzer konnte nicht gespeichert werden":                            "flash.local_user_save_failed",
	"Lokaler Benutzer gespeichert":                                                "flash.local_user_saved",
	"Lokaler Benutzer konnte nicht entfernt werden":                               "flash.local_user_delete_failed",
	"Lokaler Benutzer entfernt":                                                   "flash.local_user_deleted",
	"Benutzer konnte nicht entfernt werden":                                       "flash.user_delete_failed",
	"Benutzer entfernt":                                                           "flash.user_deleted",
	"Profil konnte nicht gespeichert werden":                                      "flash.profile_save_failed",
	"Benachrichtigungen konnten nicht gespeichert werden":                         "flash.notifications_save_failed",
	"Profil gespeichert":                                                          "flash.profile_saved",
	"Unbekannter Benachrichtigungskanal":                                          "flash.unknown_notification_channel",
	"Benachrichtigungskanal konnte nicht gelöscht werden":                         "flash.notification_channel_delete_failed",
	"Benachrichtigungskanal entfernt":                                             "flash.notification_channel_deleted",
	"Bitte aktuelles und neues Passwort angeben":                                  "flash.current_and_new_password_required",
	"Passwort-Bestätigung stimmt nicht überein":                                   "flash.password_confirmation_mismatch",
	"Passwort konnte nicht geändert werden":                                       "flash.password_change_failed",
	"Passwort geändert":                                                           "flash.password_changed",
	"Ungültige Benutzer-ID":                                                       "flash.invalid_user_id",
	"Rolle konnte nicht aktualisiert werden":                                      "flash.role_update_failed",
	"Rolle aktualisiert":                                                          "flash.role_updated",
	"Du kannst dich nicht selbst aus dem Tenant entfernen":                        "flash.cannot_remove_self_from_tenant",
	"Du kannst dich nicht selbst löschen":                                         "flash.cannot_delete_self",
	"Provider Key, Issuer URL und Client ID sind erforderlich":                    "flash.provider_required_fields_missing",
	"Ungültiger Provider Key":                                                     "flash.invalid_provider_key",
	"Provider konnte nicht gelöscht werden":                                       "flash.provider_delete_failed",
	"Provider gelöscht":                                                           "flash.provider_deleted",
	"Anmeldung fehlgeschlagen":                                                    "flash.login_failed",
	"Formular konnte nicht gelesen werden":                                        "flash.form_read_failed",
	"Tenant konnte nicht aufgelöst werden":                                        "flash.tenant_resolution_failed",
	"Ungültige Monitor-ID":                                                        "flash.invalid_monitor_id",
	"Ungültiges Intervall":                                                        "flash.invalid_interval",
	"Ungültiges Timeout":                                                          "flash.invalid_timeout",
	"Ungültiger erwarteter HTTP-Status":                                           "flash.invalid_expected_http_status",
	"Ausgewählte Remote-Node ist nicht verfügbar":                                 "flash.selected_remote_node_unavailable",
	"Monitor wurde nicht gefunden":                                                "flash.monitor_not_found",
	"Monitor aktualisiert":                                                        "flash.monitor_updated",
	"Monitor konnte nicht gelöscht werden":                                        "flash.monitor_delete_failed",
	"Monitor gelöscht":                                                            "flash.monitor_deleted",
	"Monitor konnte nicht aktualisiert werden":                                    "flash.monitor_update_failed",
	"Monitor pausiert":                                                            "flash.monitor_paused",
	"Monitor aktiviert":                                                           "flash.monitor_enabled",
	"Ziel darf nicht leer sein":                                                   "flash.target_required",
	"Monitor-Ziel aktualisiert":                                                   "flash.monitor_target_updated",
	"Passwort-Reset ist derzeit nicht verfügbar":                                  "flash.password_reset_unavailable",
	"Ungültige Eingaben":                                                          "flash.invalid_input",
	"Wenn ein Konto mit dieser E-Mail existiert, wurde ein Reset-Link versendet.": "flash.password_reset_sent_if_exists",
	"Passwort muss mindestens 8 Zeichen haben":                                    "flash.password_min_length_8",
	"Reset-Link ist ungültig oder abgelaufen":                                     "flash.reset_link_invalid_or_expired",
	"Passwort konnte nicht gesetzt werden":                                        "flash.password_set_failed",
	"Passwort wurde aktualisiert. Bitte anmelden.":                                "flash.password_updated_please_login",
	"Reset-Link fehlt":                                                            "flash.reset_link_missing",
	"Authentifizierung nicht konfiguriert":                                        "flash.authentication_not_configured",
	"SSO ist nicht vollständig konfiguriert. Bitte Client-Secret im Admin-Provider neu speichern.": "flash.sso_not_fully_configured",
	"Anmeldung nicht verfügbar":                                       "flash.login_unavailable",
	"Lokale Anmeldung ist für diesen Tenant nicht aktiviert":          "flash.local_login_not_enabled",
	"Remote-Node konnte nicht erstellt werden":                        "flash.remote_node_create_failed",
	"Ungültige Remote-Node":                                           "flash.invalid_remote_node",
	"Remote-Node konnte nicht gelöscht werden":                        "flash.remote_node_delete_failed",
	"Remote-Node gelöscht. Zugewiesene Monitore laufen wieder lokal.": "flash.remote_node_deleted_monitors_local",
	"Bootstrap-Key konnte nicht rotiert werden":                       "flash.bootstrap_key_rotate_failed",
}

var (
	adminAccessWaitPattern     = regexp.MustCompile(`^Zu viele Versuche\. Bitte (\d+) Minuten warten\.$`)
	localLoginWaitPattern      = regexp.MustCompile(`^Zu viele Fehlversuche\. Bitte in (\d+) Minute\(n\) erneut versuchen$`)
	monitorCreatedPattern      = regexp.MustCompile(`^([A-Z]+)-Monitor angelegt$`)
	remoteNodeCreatedPattern   = regexp.MustCompile(`^Remote-Node erstellt\.\s+(REMOTE_NODE_ID=.*)$`)
	bootstrapKeyRotatedPattern = regexp.MustCompile(`^Bootstrap-Key rotiert\.\s+(REMOTE_NODE_ID=.*)$`)
)

type translationCatalog struct {
	translations map[string]map[string]string
}

type languagePreference struct {
	code   string
	weight float64
	index  int
}

func loadTranslationCatalog(fsys fs.FS, dir string) (translationCatalog, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return translationCatalog{}, fmt.Errorf("read translations directory: %w", err)
	}

	catalog := translationCatalog{translations: make(map[string]map[string]string)}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if strings.ToLower(filepath.Ext(name)) != ".json" {
			continue
		}
		language := normalizeUILanguage(strings.TrimSuffix(name, filepath.Ext(name)))
		payload, err := fs.ReadFile(fsys, dir+"/"+name)
		if err != nil {
			return translationCatalog{}, fmt.Errorf("read translation file %s: %w", name, err)
		}
		items := make(map[string]string)
		if err := json.Unmarshal(payload, &items); err != nil {
			return translationCatalog{}, fmt.Errorf("decode translation file %s: %w", name, err)
		}
		if len(items) == 0 {
			continue
		}
		catalog.translations[language] = items
	}

	if _, ok := catalog.translations[defaultUILanguage]; !ok {
		catalog.translations[defaultUILanguage] = map[string]string{}
	}

	return catalog, nil
}

func (c translationCatalog) forLanguage(language string) map[string]string {
	language = normalizeUILanguage(language)
	fallback := c.translations[defaultUILanguage]
	selected := c.translations[language]

	merged := make(map[string]string, len(fallback)+len(selected))
	for key, value := range fallback {
		merged[key] = value
	}
	for key, value := range selected {
		merged[key] = value
	}
	return merged
}

func (s *Server) translationsForLanguage(language string) map[string]string {
	translations := s.i18n.forLanguage(language)
	if len(translations) == 0 {
		return map[string]string{}
	}
	return translations
}

func normalizeUILanguage(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return defaultUILanguage
	}
	if strings.HasPrefix(code, "de") {
		return "de"
	}
	if strings.HasPrefix(code, "en") {
		return "en"
	}
	parts := strings.Split(code, "-")
	if len(parts) > 0 {
		base := strings.TrimSpace(parts[0])
		if base != "" {
			return base
		}
	}
	return defaultUILanguage
}

func detectPreferredLanguage(r *http.Request) string {
	if r == nil {
		return defaultUILanguage
	}
	raw := strings.TrimSpace(r.Header.Get("Accept-Language"))
	if raw == "" {
		return defaultUILanguage
	}

	parts := strings.Split(raw, ",")
	prefs := make([]languagePreference, 0, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		code := part
		weight := 1.0
		if semi := strings.Index(part, ";"); semi >= 0 {
			code = strings.TrimSpace(part[:semi])
			params := strings.TrimSpace(part[semi+1:])
			for _, token := range strings.Split(params, ";") {
				token = strings.TrimSpace(token)
				if !strings.HasPrefix(strings.ToLower(token), "q=") {
					continue
				}
				qValue := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(token), "q="))
				parsed, err := strconv.ParseFloat(qValue, 64)
				if err != nil {
					continue
				}
				if parsed < 0 {
					parsed = 0
				}
				if parsed > 1 {
					parsed = 1
				}
				weight = parsed
			}
		}
		code = strings.TrimSpace(code)
		if code == "" || code == "*" {
			continue
		}
		prefs = append(prefs, languagePreference{code: code, weight: weight, index: i})
	}
	if len(prefs) == 0 {
		return defaultUILanguage
	}

	sort.SliceStable(prefs, func(i, j int) bool {
		if prefs[i].weight == prefs[j].weight {
			return prefs[i].index < prefs[j].index
		}
		return prefs[i].weight > prefs[j].weight
	})

	for _, pref := range prefs {
		normalized := normalizeUILanguage(pref.code)
		if normalized == "de" || normalized == "en" {
			return normalized
		}
	}

	return defaultUILanguage
}

func languageOptions(selected string) []languageOptionView {
	selected = normalizeUILanguage(selected)
	if selected != "en" && selected != "de" {
		selected = "en"
	}
	return []languageOptionView{
		{Code: "en", Label: "English", Selected: selected == "en"},
		{Code: "de", Label: "Deutsch", Selected: selected == "de"},
	}
}

func localizeFlashMessage(translations map[string]string, message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	if key, ok := flashMessageTranslationKeys[message]; ok {
		return translateFlashMessage(translations, key, message, nil)
	}
	if matches := adminAccessWaitPattern.FindStringSubmatch(message); len(matches) == 2 {
		return translateFlashMessage(translations, "flash.too_many_attempts_wait", message, map[string]string{"minutes": matches[1]})
	}
	if matches := localLoginWaitPattern.FindStringSubmatch(message); len(matches) == 2 {
		return translateFlashMessage(translations, "flash.too_many_failed_attempts_wait", message, map[string]string{"minutes": matches[1]})
	}
	if matches := monitorCreatedPattern.FindStringSubmatch(message); len(matches) == 2 {
		return translateFlashMessage(translations, "flash.monitor_created", message, map[string]string{"kind": matches[1]})
	}
	if matches := remoteNodeCreatedPattern.FindStringSubmatch(message); len(matches) == 2 {
		return translateFlashMessage(translations, "flash.remote_node_created", message, map[string]string{"details": matches[1]})
	}
	if matches := bootstrapKeyRotatedPattern.FindStringSubmatch(message); len(matches) == 2 {
		return translateFlashMessage(translations, "flash.bootstrap_key_rotated", message, map[string]string{"details": matches[1]})
	}
	return message
}

func translateFlashMessage(translations map[string]string, key, fallback string, values map[string]string) string {
	translated := strings.TrimSpace(translations[key])
	if translated == "" {
		translated = fallback
	}
	for placeholder, value := range values {
		translated = strings.ReplaceAll(translated, "{"+placeholder+"}", value)
	}
	return translated
}
