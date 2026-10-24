package email

import (
	"encoding/json"
	"strings"
	"sync"

	"goup/internal/monitor"
	"goup/web"
)

var (
	emailTranslationOnce sync.Once
	emailTranslations    map[string]map[string]string
)

func normalizeEmailLanguage(language string) string {
	language = strings.ToLower(strings.TrimSpace(language))
	if strings.HasPrefix(language, "de") {
		return "de"
	}
	if strings.HasPrefix(language, "en") {
		return "en"
	}
	return defaultEmailLanguage
}

func localizedMonitorStatus(status monitor.Status, translations map[string]string) string {
	key := "email.status." + strings.ToLower(strings.TrimSpace(string(status)))
	value := strings.TrimSpace(translations[key])
	if value != "" {
		return value
	}
	fallback := strings.ToUpper(strings.TrimSpace(string(status)))
	if fallback == "" {
		return "UNKNOWN"
	}
	return fallback
}

func emailTranslationsForLanguage(language string) map[string]string {
	ensureEmailTranslationsLoaded()
	language = normalizeEmailLanguage(language)

	fallback := emailTranslations[defaultEmailLanguage]
	selected := emailTranslations[language]

	merged := make(map[string]string, len(fallback)+len(selected))
	for key, value := range fallback {
		merged[key] = value
	}
	for key, value := range selected {
		merged[key] = value
	}
	return merged
}

func ensureEmailTranslationsLoaded() {
	emailTranslationOnce.Do(func() {
		emailTranslations = map[string]map[string]string{
			"en": {},
			"de": {},
		}
		for _, language := range []string{"en", "de"} {
			payload, err := web.FS.ReadFile("i18n/" + language + ".json")
			if err != nil {
				continue
			}
			items := make(map[string]string)
			if err := json.Unmarshal(payload, &items); err != nil {
				continue
			}
			emailTranslations[language] = items
		}
	})
}

func emailText(translations map[string]string, key, fallback string) string {
	value := strings.TrimSpace(translations[key])
	if value != "" {
		return value
	}
	return fallback
}
