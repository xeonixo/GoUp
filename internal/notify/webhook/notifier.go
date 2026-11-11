package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"goup/internal/monitor"
	"goup/internal/netguard"
	"goup/internal/notify/route"
	store "goup/internal/store/sqlite"
)

const (
	NotificationKind = "webhook"
	EventType        = "status_transition_webhook"
	ReminderEvent    = "status_reminder_webhook"
	TestEventType    = "test_notification_webhook"
	defaultTimeout   = 10 * time.Second
	maxTimeout       = 30 * time.Second

	// MinSigningSecretLength is the minimum accepted length for pasted webhook secrets.
	MinSigningSecretLength = 16
	signingSecretPrefix    = "goup_wh_"
	signingSecretRandBytes = 32
)

var ErrInvalidSignature = errors.New("invalid webhook signature")

type tenantWebhookStore interface {
	ListWebhookEndpoints(ctx context.Context) ([]store.WebhookEndpoint, error)
}

type tenantWebhookSecretStore interface {
	GetTenantNotificationEndpointSigningSecrets(ctx context.Context, tenantID, endpointID int64, kind string) (store.TenantNotificationEndpointSigningSecrets, error)
}

type Notifier struct {
	tenantID      int64
	store         tenantWebhookStore
	controlStore  tenantWebhookSecretStore
	now           func() time.Time
	validateURL   func(raw string) (*url.URL, error)
	newHTTPClient func(timeout time.Duration) *http.Client
}

func NewNotifier(appStore tenantWebhookStore, controlStore tenantWebhookSecretStore, tenantID int64) *Notifier {
	return &Notifier{
		tenantID:      tenantID,
		store:         appStore,
		controlStore:  controlStore,
		now:           func() time.Time { return time.Now().UTC() },
		validateURL:   ValidateTargetURL,
		newHTTPClient: newSecureHTTPClient,
	}
}

func (n *Notifier) Enabled() bool {
	return n != nil && n.tenantID > 0 && n.store != nil && n.controlStore != nil
}

func (n *Notifier) EndpointID() int64 {
	return 0
}

func (n *Notifier) EventType() string {
	return EventType
}

func (n *Notifier) Notify(ctx context.Context, transition monitor.Transition) error {
	results, err := n.NotifyAll(ctx, transition)
	if err != nil {
		return err
	}
	for _, result := range results {
		if result.Error != nil {
			return result.Error
		}
	}
	return nil
}

func (n *Notifier) NotifyAll(ctx context.Context, transition monitor.Transition) ([]monitor.FanoutDeliveryResult, error) {
	if !n.Enabled() {
		return nil, nil
	}
	endpoints, err := n.store.ListWebhookEndpoints(ctx)
	if err != nil {
		return nil, fmt.Errorf("load webhook endpoints: %w", err)
	}

	results := make([]monitor.FanoutDeliveryResult, 0, len(endpoints))
	activeCount := 0
	now := n.now()
	for _, endpoint := range endpoints {
		if !endpoint.Enabled {
			continue
		}
		activeCount++
		if !endpointRouteMatches(endpoint, transition, now) {
			continue
		}
		results = append(results, monitor.FanoutDeliveryResult{
			EndpointID: endpoint.ID,
			Error:      n.deliverToEndpoint(ctx, endpoint, transition, eventTypeFor(transition)),
		})
	}
	if activeCount == 0 {
		return nil, monitor.ErrNoRecipients
	}
	return results, nil
}

func (n *Notifier) NotifyEndpoint(ctx context.Context, endpointID int64, transition monitor.Transition) error {
	if !n.Enabled() {
		return nil
	}
	endpoints, err := n.store.ListWebhookEndpoints(ctx)
	if err != nil {
		return fmt.Errorf("load webhook endpoints: %w", err)
	}
	for _, endpoint := range endpoints {
		if endpoint.ID == endpointID && endpoint.Enabled {
			if !endpointRouteMatches(endpoint, transition, n.now()) {
				return nil
			}
			return n.deliverToEndpoint(ctx, endpoint, transition, eventTypeFor(transition))
		}
	}
	return fmt.Errorf("webhook endpoint %d not found", endpointID)
}

func endpointRouteMatches(endpoint store.WebhookEndpoint, transition monitor.Transition, now time.Time) bool {
	rt := endpoint.Route
	if endpoint.ConfigJSON != "" {
		if parsed, err := route.Parse([]byte(endpoint.ConfigJSON)); err == nil {
			rt = parsed
		}
	}
	severity := route.SeverityOf(string(transition.Previous), string(transition.Current), transition.Reminder)
	return rt.Matches(transition.Monitor.Group, transition.Monitor.ID, severity, now)
}

// eventTypeFor names the delivery: reminders for ongoing outages are a distinct event.
func eventTypeFor(transition monitor.Transition) string {
	if transition.Reminder {
		return ReminderEvent
	}
	return EventType
}

func (n *Notifier) SendTest(ctx context.Context, endpointID int64, tenantSlug string) error {
	if !n.Enabled() {
		return nil
	}
	endpoints, err := n.store.ListWebhookEndpoints(ctx)
	if err != nil {
		return fmt.Errorf("load webhook endpoints: %w", err)
	}
	for _, endpoint := range endpoints {
		if endpoint.ID == endpointID {
			return n.deliverToEndpoint(ctx, endpoint, buildTestTransition(n.tenantID, tenantSlug, n.now()), TestEventType)
		}
	}
	return fmt.Errorf("webhook endpoint %d not found", endpointID)
}

func (n *Notifier) deliverToEndpoint(ctx context.Context, endpoint store.WebhookEndpoint, transition monitor.Transition, eventType string) error {
	parsedURL, err := n.validateURL(endpoint.URL)
	if err != nil {
		return err
	}
	secrets, err := n.controlStore.GetTenantNotificationEndpointSigningSecrets(ctx, n.tenantID, endpoint.ID, NotificationKind)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("webhook signing secret is not configured")
		}
		return fmt.Errorf("load webhook signing secret: %w", err)
	}
	if strings.TrimSpace(secrets.Current) == "" {
		return fmt.Errorf("webhook signing secret is not configured")
	}
	payload, err := json.Marshal(buildPayload(eventType, n.tenantID, endpoint.ID, transition, n.now()))
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}
	timestamp := n.now().Format(time.RFC3339)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsedURL.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GoUp-Webhook/1.0")
	req.Header.Set("X-GoUp-Event", eventType)
	req.Header.Set("X-GoUp-Tenant-ID", fmt.Sprintf("%d", n.tenantID))
	req.Header.Set("X-GoUp-Endpoint-ID", fmt.Sprintf("%d", endpoint.ID))
	req.Header.Set("X-GoUp-Timestamp", timestamp)
	req.Header.Set("X-GoUp-Signature", signPayload(secrets.Current, timestamp, payload))

	client := n.newHTTPClient(timeoutDuration(endpoint.TimeoutSeconds))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("deliver webhook: unexpected status %d", resp.StatusCode)
	}
	return nil
}

type payload struct {
	EventType  string         `json:"event_type"`
	TenantID   int64          `json:"tenant_id"`
	EndpointID int64          `json:"endpoint_id"`
	OccurredAt time.Time      `json:"occurred_at"`
	Monitor    payloadMonitor `json:"monitor"`
	Transition payloadStatus  `json:"transition"`
}

type payloadMonitor struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Group  string `json:"group,omitempty"`
}

type payloadStatus struct {
	Previous     string    `json:"previous"`
	Current      string    `json:"current"`
	CheckedAt    time.Time `json:"checked_at"`
	ResultDetail string    `json:"result_detail,omitempty"`
	// Reminder is true for repeated alerts of an ongoing outage (event_type
	// status_reminder_webhook); OutageSeconds is how long the monitor has been down.
	Reminder      bool  `json:"reminder,omitempty"`
	OutageSeconds int64 `json:"outage_seconds,omitempty"`
	// CatchUp is true for the single summary sent after a mute or maintenance window ended.
	CatchUp bool `json:"catch_up,omitempty"`
}

func buildPayload(eventType string, tenantID, endpointID int64, transition monitor.Transition, occurredAt time.Time) payload {
	if strings.TrimSpace(eventType) == "" {
		eventType = EventType
	}
	return payload{
		EventType:  eventType,
		TenantID:   tenantID,
		EndpointID: endpointID,
		OccurredAt: occurredAt,
		Monitor: payloadMonitor{
			ID:     transition.Monitor.ID,
			Name:   strings.TrimSpace(transition.Monitor.Name),
			Kind:   string(transition.Monitor.Kind),
			Target: strings.TrimSpace(transition.Monitor.Target),
			Group:  strings.TrimSpace(transition.Monitor.Group),
		},
		Transition: payloadStatus{
			Previous:      string(transition.Previous),
			Current:       string(transition.Current),
			CheckedAt:     transition.CheckedAt.UTC(),
			ResultDetail:  strings.TrimSpace(transition.ResultDetail),
			Reminder:      transition.Reminder,
			OutageSeconds: int64(transition.OutageDuration.Seconds()),
			CatchUp:       transition.CatchUp,
		},
	}
}

func buildTestTransition(tenantID int64, tenantSlug string, now time.Time) monitor.Transition {
	tenantSlug = strings.TrimSpace(tenantSlug)
	target := fmt.Sprintf("tenant:%d", tenantID)
	if tenantSlug != "" {
		target = "/" + tenantSlug + "/settings/webhooks"
	}
	return monitor.Transition{
		Monitor: monitor.Monitor{
			ID:     0,
			Name:   "GoUp Webhook Test",
			Kind:   monitor.Kind("webhook-test"),
			Target: target,
			Group:  "system",
		},
		Previous:     monitor.Status("test"),
		Current:      monitor.Status("test"),
		CheckedAt:    now.UTC(),
		ResultDetail: "Triggered manually from tenant settings.",
	}
}

func signPayload(secret, timestamp string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

// GenerateSigningSecret returns a high-entropy signing secret. Callers must reveal it once;
// only the ciphertext is stored afterward.
func GenerateSigningSecret() (string, error) {
	raw := make([]byte, signingSecretRandBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate webhook signing secret: %w", err)
	}
	return signingSecretPrefix + hex.EncodeToString(raw), nil
}

// ValidateSigningSecret enforces a minimum length for user-pasted secrets.
func ValidateSigningSecret(secret string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return fmt.Errorf("signing secret is required")
	}
	if len(secret) < MinSigningSecretLength {
		return fmt.Errorf("signing secret must be at least %d characters", MinSigningSecretLength)
	}
	return nil
}

// VerifySignature accepts an HMAC signed with the current secret, or with the previous
// secret while dual-secret rotate grace is active.
func VerifySignature(secrets store.TenantNotificationEndpointSigningSecrets, timestamp string, payload []byte, signature string) error {
	signature = strings.TrimSpace(signature)
	if signature == "" || !strings.HasPrefix(signature, "v1=") {
		return ErrInvalidSignature
	}
	candidates := make([]string, 0, 2)
	if strings.TrimSpace(secrets.Current) != "" {
		candidates = append(candidates, secrets.Current)
	}
	now := time.Now().UTC()
	if secrets.PreviousGraceActive && strings.TrimSpace(secrets.Previous) != "" {
		if secrets.PreviousExpiresAt == nil || !secrets.PreviousExpiresAt.Before(now) {
			candidates = append(candidates, secrets.Previous)
		}
	}
	for _, secret := range candidates {
		if hmac.Equal([]byte(signature), []byte(signPayload(secret, timestamp, payload))) {
			return nil
		}
	}
	return ErrInvalidSignature
}

func timeoutDuration(seconds int) time.Duration {
	if seconds <= 0 {
		return defaultTimeout
	}
	d := time.Duration(seconds) * time.Second
	if d > maxTimeout {
		return maxTimeout
	}
	return d
}

// ValidateTargetURL applies the same SSRF policy as netguard.ValidateURL at
// save time: https only, no credentials, and no private/loopback/metadata
// destinations unless GOUP_ALLOW_PRIVATE_INTEGRATIONS=true. localhost /
// *.localhost and AlwaysBlocked metadata addresses are rejected the same way
// dial-time checks do. Monitor private policy (GOUP_MONITOR_ALLOW_PRIVATE) is
// intentionally not used here.
func ValidateTargetURL(raw string) (*url.URL, error) {
	parsed, err := netguard.ValidateURL(raw, netguard.AllowPrivateIntegrationsFromEnv())
	if err != nil {
		if errors.Is(err, netguard.ErrBlockedAddress) {
			return nil, fmt.Errorf("webhook target address is blocked")
		}
		return nil, fmt.Errorf("invalid webhook url: %w", err)
	}
	return parsed, nil
}

func newSecureHTTPClient(timeout time.Duration) *http.Client {
	return netguard.NewHTTPClient(netguard.Options{
		Timeout:      timeout,
		AllowPrivate: netguard.AllowPrivateIntegrationsFromEnv(),
		UseEnvProxy:  true,
	})
}
