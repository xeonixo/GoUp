package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

const (
	NotificationKind = "webhook"
	EventType        = "status_transition_webhook"
	TestEventType    = "test_notification_webhook"
	defaultTimeout   = 10 * time.Second
	maxTimeout       = 30 * time.Second
)

var blockedWebhookPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("2001:db8::/32"),
}

type tenantWebhookStore interface {
	ListWebhookEndpoints(ctx context.Context) ([]store.WebhookEndpoint, error)
}

type tenantWebhookSecretStore interface {
	GetTenantNotificationEndpointSecret(ctx context.Context, tenantID, endpointID int64, kind string) (string, error)
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
	for _, endpoint := range endpoints {
		if !endpoint.Enabled {
			continue
		}
		activeCount++
		results = append(results, monitor.FanoutDeliveryResult{
			EndpointID: endpoint.ID,
			Error:      n.deliverToEndpoint(ctx, endpoint, transition, EventType),
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
			return n.deliverToEndpoint(ctx, endpoint, transition, EventType)
		}
	}
	return fmt.Errorf("webhook endpoint %d not found", endpointID)
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
	secret, err := n.controlStore.GetTenantNotificationEndpointSecret(ctx, n.tenantID, endpoint.ID, NotificationKind)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("webhook signing secret is not configured")
		}
		return fmt.Errorf("load webhook signing secret: %w", err)
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
	req.Header.Set("X-GoUp-Signature", signPayload(secret, timestamp, payload))

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
			Previous:     string(transition.Previous),
			Current:      string(transition.Current),
			CheckedAt:    transition.CheckedAt.UTC(),
			ResultDetail: strings.TrimSpace(transition.ResultDetail),
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

func ValidateTargetURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook url: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("webhook url must use https")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("webhook url must not contain credentials")
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return nil, fmt.Errorf("webhook url host is required")
	}
	if addr, err := netip.ParseAddr(parsed.Hostname()); err == nil && !isAllowedIPAddress(addr) {
		return nil, fmt.Errorf("webhook target address is blocked")
	}
	return parsed, nil
}

func newSecureHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !isAllowedIPAddress(ip) {
					return nil, fmt.Errorf("webhook target address is blocked")
				}
			}
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				if addr, ok := netip.AddrFromSlice(tcpAddr.IP); ok && !isAllowedIPAddress(addr.Unmap()) {
					_ = conn.Close()
					return nil, fmt.Errorf("webhook target address is blocked")
				}
			}
			return conn, nil
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("webhook redirects are not allowed")
		},
	}
}

func isAllowedIPAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range blockedWebhookPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
