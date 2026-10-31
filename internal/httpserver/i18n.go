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

var (
	adminAccessWaitPattern     = regexp.MustCompile(`^Zu viele Versuche\. Bitte (\d+) Minuten warten\.$`)
	localLoginWaitPattern      = regexp.MustCompile(`^Zu viele Fehlversuche\. Bitte in (\d+) Minute\(n\) erneut versuchen$`)
	monitorCreatedPattern      = regexp.MustCompile(`^([A-Z][A-Za-z0-9 ()]*)-Monitor angelegt$`)
	remoteNodeCreatedPattern   = regexp.MustCompile(`^Remote-Node erstellt\.\s+(REMOTE_NODE_ID=.*)$`)
	bootstrapKeyRotatedPattern = regexp.MustCompile(`^Bootstrap-Key rotiert\.\s+(REMOTE_NODE_ID=.*)$`)
	monitorsImportedPattern    = regexp.MustCompile(`^(\d+) Monitor\(e\) importiert$`)
	monitorsUpdatedPattern     = regexp.MustCompile(`^(\d+) Monitor\(e\) aktualisiert$`)
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
	if matches := monitorsImportedPattern.FindStringSubmatch(message); len(matches) == 2 {
		return translateFlashMessage(translations, "flash.monitors_imported", message, map[string]string{"count": matches[1]})
	}
	if matches := monitorsUpdatedPattern.FindStringSubmatch(message); len(matches) == 2 {
		return translateFlashMessage(translations, "flash.monitors_updated", message, map[string]string{"count": matches[1]})
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
