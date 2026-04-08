package matrix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"goup/web"
)

const defaultMatrixLanguage = "en"

var (
	matrixTranslationOnce sync.Once
	matrixTranslations    map[string]map[string]string
)

func matrixTranslationsForLanguage(language string) map[string]string {
	matrixTranslationOnce.Do(func() {
		matrixTranslations = map[string]map[string]string{"en": {}, "de": {}}
		for _, lang := range []string{"en", "de"} {
			payload, err := web.FS.ReadFile("i18n/" + lang + ".json")
			if err != nil {
				continue
			}
			items := make(map[string]string)
			if err := json.Unmarshal(payload, &items); err != nil {
				continue
			}
			matrixTranslations[lang] = items
		}
	})

	language = normalizeMatrixLanguage(language)
	fallback := matrixTranslations[defaultMatrixLanguage]
	selected := matrixTranslations[language]
	merged := make(map[string]string, len(fallback)+len(selected))
	for k, v := range fallback {
		merged[k] = v
	}
	for k, v := range selected {
		merged[k] = v
	}
	return merged
}

func normalizeMatrixLanguage(language string) string {
	language = strings.ToLower(strings.TrimSpace(language))
	if strings.HasPrefix(language, "de") {
		return "de"
	}
	return defaultMatrixLanguage
}

func matrixText(translations map[string]string, key, fallback string) string {
	value := strings.TrimSpace(translations[key])
	if value != "" {
		return value
	}
	return fallback
}

type Notifier struct {
	client       *Client
	controlStore *store.ControlPlaneStore
	tenantID     int64
	endpointID   int64
}

func NewNotifier(client *Client, endpointID int64) *Notifier {
	return &Notifier{client: client, endpointID: endpointID}
}

func NewTenantNotifier(controlStore *store.ControlPlaneStore, endpointID int64, tenantID int64) *Notifier {
	return &Notifier{controlStore: controlStore, endpointID: endpointID, tenantID: tenantID}
}

func (n *Notifier) Enabled() bool {
	if n == nil || n.endpointID <= 0 {
		return false
	}
	if n.controlStore != nil && n.tenantID > 0 {
		return true
	}
	return n.client != nil
}

func (n *Notifier) EndpointID() int64 {
	if n == nil {
		return 0
	}
	return n.endpointID
}

func (n *Notifier) EventType() string {
	return "status_transition"
}

func (n *Notifier) Notify(ctx context.Context, transition monitor.Transition) error {
	if !n.Enabled() {
		return nil
	}

	if n.controlStore != nil && n.tenantID > 0 {
		targets, err := n.controlStore.ListTenantMatrixNotificationTargets(ctx, n.tenantID)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return monitor.ErrNoRecipients
		}

		var sendErrors []string
		for _, target := range targets {
			client := &Client{
				homeserverURL: strings.TrimSpace(target.HomeserverURL),
				accessToken:   strings.TrimSpace(target.AccessToken),
				roomID:        strings.TrimSpace(target.RoomID),
				httpClient:    &http.Client{Timeout: 10 * time.Second},
			}
			if !client.Enabled() {
				continue
			}
			message := formatTransitionMessage(transition, target.PreferredLanguage)
			if err := client.SendMessage(ctx, message); err != nil {
				sendErrors = append(sendErrors, fmt.Sprintf("user_id=%d: %v", target.UserID, err))
			}
		}
		if len(sendErrors) > 0 {
			return fmt.Errorf("matrix delivery failed: %s", strings.Join(sendErrors, "; "))
		}
		return nil
	}

	if n.client == nil {
		return fmt.Errorf("matrix client is not initialized")
	}
	return n.client.SendMessage(ctx, formatTransitionMessage(transition, defaultMatrixLanguage))
}

func formatTransitionMessage(transition monitor.Transition, language string) string {
	tr := matrixTranslationsForLanguage(language)
	headline := fmt.Sprintf("%s %s: %s → %s",
		statusEmoji(transition.Current),
		transition.Monitor.Name,
		strings.ToUpper(string(transition.Previous)),
		strings.ToUpper(string(transition.Current)),
	)
	var lines []string
	if grp := strings.TrimSpace(transition.Monitor.Group); grp != "" {
		lines = append(lines, matrixText(tr, "matrix.group", "Group")+": "+grp)
	}
	lines = append(lines,
		matrixText(tr, "matrix.kind", "Kind")+": "+strings.ToUpper(string(transition.Monitor.Kind)),
		matrixText(tr, "matrix.target", "Target")+": "+transition.Monitor.Target,
		matrixText(tr, "matrix.timestamp", "Time")+": "+transition.CheckedAt.Local().Format(time.RFC3339),
		matrixText(tr, "matrix.details", "Details")+": "+transition.ResultDetail,
	)
	return headline + "\n" + strings.Join(lines, "\n")
}

func statusEmoji(status monitor.Status) string {
	switch status {
	case monitor.StatusUp:
		return "✅"
	case monitor.StatusDegraded:
		return "⚠️"
	default:
		return "❌"
	}
}
