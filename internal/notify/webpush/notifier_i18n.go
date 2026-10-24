package webpush

import (
	"encoding/json"
	"strings"
	"sync"

	"goup/web"
)

var (
	trOnce sync.Once
	trAll  map[string]map[string]string
)

// NormalizeLanguage maps a user language to "de" or "en".
func NormalizeLanguage(language string) string { return normalizeLanguage(language) }

func normalizeLanguage(language string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(language)), "de") {
		return "de"
	}
	return "en"
}

func translations(language string) map[string]string {
	trOnce.Do(func() {
		trAll = map[string]map[string]string{"en": {}, "de": {}}
		for lang := range trAll {
			payload, err := web.FS.ReadFile("i18n/" + lang + ".json")
			if err != nil {
				continue
			}
			items := map[string]string{}
			if json.Unmarshal(payload, &items) == nil {
				trAll[lang] = items
			}
		}
	})
	return trAll[normalizeLanguage(language)]
}

func text(tr map[string]string, key, fallback string) string {
	if v := strings.TrimSpace(tr[key]); v != "" {
		return v
	}
	return fallback
}
