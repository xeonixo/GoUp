package statuspage

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/smtp"
	"net/url"
	"strings"
	"sync"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"goup/web"
)

const (
	EndpointKind          = "status_page_email"
	EndpointName          = "status-page-subscriptions"
	EventType             = "status_page_incident_email"
	defaultEmailLanguage  = "en"
)

type subscriptionStore interface {
	ListConfirmedStatusPageSubscribersForMonitor(ctx context.Context, monitorID int64) ([]store.StatusPageSubscription, error)
	StatusPageDisplayNameForMonitor(ctx context.Context, monitorID int64) (string, bool, error)
}

type smtpSource interface {
	GetGlobalSMTPDeliveryConfig(ctx context.Context) (store.GlobalSMTPDeliveryConfig, error)
}

// Notifier emails confirmed status-page subscribers on public down/recovery events.
// It never includes targets, hosts, or cause details.
type Notifier struct {
	controlStore smtpSource
	appStore     subscriptionStore
	endpointID   int64
	baseURL      string
	tenantSlug   string
	sendMail     func(cfg store.GlobalSMTPDeliveryConfig, to, subject, body string) error
}

func NewNotifier(controlStore smtpSource, appStore subscriptionStore, endpointID int64, baseURL, tenantSlug string) *Notifier {
	return &Notifier{
		controlStore: controlStore,
		appStore:     appStore,
		endpointID:   endpointID,
		baseURL:      strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		tenantSlug:   strings.TrimSpace(tenantSlug),
		sendMail:     sendPlainSMTPMail,
	}
}

func (n *Notifier) Enabled() bool {
	return n != nil && n.endpointID > 0 && n.controlStore != nil && n.appStore != nil
}

func (n *Notifier) EndpointID() int64 {
	if n == nil {
		return 0
	}
	return n.endpointID
}

func (n *Notifier) EventType() string {
	return EventType
}

func (n *Notifier) Notify(ctx context.Context, transition monitor.Transition) error {
	if !n.Enabled() {
		return nil
	}
	if transition.Reminder || transition.CatchUp {
		return monitor.ErrNoRecipients
	}
	if transition.Current != monitor.StatusDown && transition.Current != monitor.StatusUp {
		return monitor.ErrNoRecipients
	}
	if transition.Current == monitor.StatusUp && transition.Previous != monitor.StatusDown && transition.Previous != monitor.StatusDegraded {
		return monitor.ErrNoRecipients
	}

	displayName, onPage, err := n.appStore.StatusPageDisplayNameForMonitor(ctx, transition.Monitor.ID)
	if err != nil {
		return err
	}
	if !onPage || strings.TrimSpace(displayName) == "" {
		return monitor.ErrNoRecipients
	}

	subscribers, err := n.appStore.ListConfirmedStatusPageSubscribersForMonitor(ctx, transition.Monitor.ID)
	if err != nil {
		return err
	}
	if len(subscribers) == 0 {
		return monitor.ErrNoRecipients
	}

	deliveryCfg, err := n.controlStore.GetGlobalSMTPDeliveryConfig(ctx)
	if err != nil {
		return fmt.Errorf("load smtp delivery config: %w", err)
	}
	if strings.TrimSpace(deliveryCfg.Settings.Host) == "" || strings.TrimSpace(deliveryCfg.Settings.FromEmail) == "" {
		return fmt.Errorf("smtp host/from not configured")
	}
	if strings.TrimSpace(deliveryCfg.Password) == "" {
		return fmt.Errorf("smtp password not configured")
	}

	statusURL := n.baseURL + "/"
	if n.tenantSlug != "" {
		statusURL = n.baseURL + "/" + n.tenantSlug + "/status"
	}

	var sendErrors []string
	for _, sub := range subscribers {
		tr := translationsForLanguage(sub.Language)
		subject, body := buildIncidentMail(transition, displayName, statusURL, sub.UnsubscribeTokenHash, n.tenantSlug, n.baseURL, tr)
		if err := n.sendMail(deliveryCfg, sub.Email, subject, body); err != nil {
			sendErrors = append(sendErrors, sub.Email+": "+err.Error())
		}
	}
	if len(sendErrors) > 0 {
		return fmt.Errorf("status page email delivery failed: %s", strings.Join(sendErrors, "; "))
	}
	return nil
}

func buildIncidentMail(transition monitor.Transition, displayName, statusURL, unsubToken, tenantSlug, baseURL string, tr map[string]string) (subject, body string) {
	name := strings.TrimSpace(displayName)
	var eventKey, eventFallback string
	switch transition.Current {
	case monitor.StatusDown:
		eventKey = "email.status_subscribe.incident_down"
		eventFallback = "{name} is experiencing an outage"
		subject = formatMail(tr, "email.status_subscribe.incident_down_subject", "Outage: {name}", map[string]string{"name": name})
	default:
		eventKey = "email.status_subscribe.incident_up"
		eventFallback = "{name} has recovered"
		subject = formatMail(tr, "email.status_subscribe.incident_up_subject", "Recovered: {name}", map[string]string{"name": name})
	}
	lines := []string{
		formatMail(tr, eventKey, eventFallback, map[string]string{"name": name}),
		"",
		formatMail(tr, "email.status_subscribe.incident_time", "Time: {time}", map[string]string{
			"time": transition.CheckedAt.UTC().Format("2006-01-02 15:04 UTC"),
		}),
		formatMail(tr, "email.status_subscribe.incident_link", "Status page: {link}", map[string]string{"link": statusURL}),
	}
	if unsub := BuildUnsubscribeURL(baseURL, tenantSlug, unsubToken); unsub != "" {
		lines = append(lines, "", formatMail(tr, "email.status_subscribe.unsubscribe", "Unsubscribe: {link}", map[string]string{"link": unsub}))
	}
	return subject, strings.Join(lines, "\n")
}

func formatMail(tr map[string]string, key, fallback string, vars map[string]string) string {
	value := strings.TrimSpace(tr[key])
	if value == "" {
		value = fallback
	}
	for k, v := range vars {
		value = strings.ReplaceAll(value, "{"+k+"}", v)
	}
	return value
}

// BuildUnsubscribeURL builds a public unsubscribe URL from an opaque token.
func BuildUnsubscribeURL(baseURL, tenantSlug, plainToken string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	tenantSlug = strings.TrimSpace(tenantSlug)
	plainToken = strings.TrimSpace(plainToken)
	if baseURL == "" || tenantSlug == "" || plainToken == "" {
		return ""
	}
	return baseURL + "/" + tenantSlug + "/status/subscribe/unsubscribe?token=" + url.QueryEscape(plainToken)
}

var (
	translationOnce sync.Once
	translations    map[string]map[string]string
)

func normalizeLanguage(language string) string {
	language = strings.ToLower(strings.TrimSpace(language))
	if strings.HasPrefix(language, "de") {
		return "de"
	}
	return defaultEmailLanguage
}

func translationsForLanguage(language string) map[string]string {
	translationOnce.Do(func() {
		translations = map[string]map[string]string{"en": {}, "de": {}}
		for _, lang := range []string{"en", "de"} {
			payload, err := web.FS.ReadFile("i18n/" + lang + ".json")
			if err != nil {
				continue
			}
			items := make(map[string]string)
			if err := json.Unmarshal(payload, &items); err != nil {
				continue
			}
			translations[lang] = items
		}
	})
	language = normalizeLanguage(language)
	fallback := translations[defaultEmailLanguage]
	selected := translations[language]
	merged := make(map[string]string, len(fallback)+len(selected))
	for k, v := range fallback {
		merged[k] = v
	}
	for k, v := range selected {
		merged[k] = v
	}
	return merged
}

func sanitizeHeader(value string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(value)
}

func sendPlainSMTPMail(cfg store.GlobalSMTPDeliveryConfig, to, subject, body string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("recipient is required")
	}
	host := strings.TrimSpace(cfg.Settings.Host)
	port := cfg.Settings.Port
	if host == "" || port <= 0 {
		return fmt.Errorf("smtp host/port not configured")
	}
	fromEmail := sanitizeHeader(cfg.Settings.FromEmail)
	fromName := sanitizeHeader(cfg.Settings.FromName)
	to = sanitizeHeader(to)
	subject = sanitizeHeader(subject)
	if strings.ContainsAny(to+subject+fromEmail+fromName, "\r\n\x00") {
		return fmt.Errorf("invalid header value")
	}
	fromHeader := fromEmail
	if strings.TrimSpace(fromName) != "" {
		fromHeader = fmt.Sprintf("%s <%s>", fromName, fromEmail)
	}
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\x00", ""), "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", "\n")
	msg := strings.Join([]string{
		"From: " + fromHeader,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")
	addr := fmt.Sprintf("%s:%d", host, port)
	auth := smtp.PlainAuth("", cfg.Settings.Username, cfg.Password, host)

	send := func(client *smtp.Client) error {
		if cfg.Settings.Username != "" || cfg.Password != "" {
			if ok, _ := client.Extension("AUTH"); ok {
				if err := client.Auth(auth); err != nil {
					return err
				}
			}
		}
		if err := client.Mail(fromEmail); err != nil {
			return err
		}
		if err := client.Rcpt(to); err != nil {
			return err
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil {
			_ = wc.Close()
			return err
		}
		if err := wc.Close(); err != nil {
			return err
		}
		return client.Quit()
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Settings.TLSMode)) {
	case "tls":
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
		if err != nil {
			return err
		}
		defer conn.Close()
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return err
		}
		defer client.Close()
		return send(client)
	case "none", "starttls":
		client, err := smtp.Dial(addr)
		if err != nil {
			return err
		}
		defer client.Close()
		if strings.ToLower(strings.TrimSpace(cfg.Settings.TLSMode)) == "starttls" {
			if ok, _ := client.Extension("STARTTLS"); ok {
				if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
					return err
				}
			}
		}
		return send(client)
	default:
		return fmt.Errorf("unsupported smtp tls mode")
	}
}
