// Package webpush delivers monitor transitions as Web Push notifications (RFC 8030, payload
// encryption per RFC 8291, VAPID per RFC 8292) to the devices users registered in their profile.
package webpush

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	wp "github.com/SherClockHolmes/webpush-go"

	"goup/internal/netguard"
	store "goup/internal/store/sqlite"
)

// EnvVAPIDSubject optionally overrides the VAPID contact ("mailto:you@example.org" or an
// https URL). Without it the SMTP sender address, then the https base URL is used.
const EnvVAPIDSubject = "GOUP_VAPID_SUBJECT"

const (
	sendTimeout    = 10 * time.Second
	sendConcurrent = 4
	// MaxEndpointLength bounds stored endpoint URLs.
	MaxEndpointLength = 2048
)

// allowedEndpointSuffixes are the push services of the browsers GoUp supports. Restricting
// endpoints to them keeps users from turning the server into an SSRF proxy via fake endpoints.
var allowedEndpointSuffixes = []string{
	"push.apple.com", // Safari / iOS web.push.apple.com
	"googleapis.com", // Chrome / Android fcm.googleapis.com
	"mozilla.com",    // Firefox updates.push.services.mozilla.com
	"windows.com",    // Edge *.notify.windows.com
	"mozaws.net",     // legacy Firefox
}

// ValidateEndpoint checks that a push endpoint is an https URL on a known push service.
func ValidateEndpoint(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxEndpointLength {
		return nil, errors.New("invalid push endpoint length")
	}
	parsed, err := netguard.ValidateURL(raw, false)
	if err != nil {
		return nil, err
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return nil, errors.New("push endpoint port is not allowed")
	}
	host := strings.ToLower(parsed.Hostname())
	for _, suffix := range allowedEndpointSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return parsed, nil
		}
	}
	return nil, errors.New("push endpoint host is not a known push service")
}

// NormalizeKeys validates a subscription's p256dh/auth values and returns them as unpadded
// base64url.
func NormalizeKeys(p256dh, auth string) (string, string, error) {
	pub, err := decodeB64(p256dh)
	if err != nil {
		return "", "", errors.New("invalid p256dh key")
	}
	if _, err := ecdh.P256().NewPublicKey(pub); err != nil {
		return "", "", errors.New("invalid p256dh key")
	}
	secret, err := decodeB64(auth)
	if err != nil || len(secret) != 16 {
		return "", "", errors.New("invalid auth secret")
	}
	return base64.RawURLEncoding.EncodeToString(pub), base64.RawURLEncoding.EncodeToString(secret), nil
}

func decodeB64(v string) ([]byte, error) {
	v = strings.TrimRight(strings.TrimSpace(v), "=")
	v = strings.NewReplacer("+", "-", "/", "_").Replace(v)
	return base64.RawURLEncoding.DecodeString(v)
}

// Sender signs (VAPID) and posts encrypted pushes. It is safe for concurrent use.
type Sender struct {
	controlStore *store.ControlPlaneStore
	baseURL      string

	client        wp.HTTPClient
	checkEndpoint func(string) error // overridden in tests

	mu          sync.Mutex
	privateKey  string
	publicKey   string
	subject     string
	subjectDone bool
}

// NewSender creates a sender. baseURL (GOUP_BASE_URL) is only used as VAPID contact fallback.
func NewSender(controlStore *store.ControlPlaneStore, baseURL string) *Sender {
	return &Sender{
		controlStore: controlStore,
		baseURL:      strings.TrimSpace(baseURL),
		client: netguard.NewHTTPClient(netguard.Options{
			Timeout:     sendTimeout,
			UseEnvProxy: true,
			// Push services are public hosts: private ranges stay blocked regardless of
			// GOUP_ALLOW_PRIVATE_INTEGRATIONS.
		}),
		checkEndpoint: func(raw string) error { _, err := ValidateEndpoint(raw); return err },
	}
}

// PublicKey returns the base64url VAPID application server key (generating it on first use).
func (s *Sender) PublicKey(ctx context.Context) (string, error) {
	_, pub, err := s.keys(ctx)
	return pub, err
}

func (s *Sender) keys(ctx context.Context) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.privateKey == "" {
		priv, pub, err := s.controlStore.GetOrCreateVAPIDKeys(ctx)
		if err != nil {
			return "", "", err
		}
		s.privateKey, s.publicKey = priv, pub
	}
	return s.privateKey, s.publicKey, nil
}

// vapidSubject returns the JWT "sub" claim in the form webpush-go expects: a bare e-mail
// address (it prepends "mailto:") or an https URL.
func (s *Sender) vapidSubject(ctx context.Context) string {
	s.mu.Lock()
	if s.subjectDone {
		defer s.mu.Unlock()
		return s.subject
	}
	s.mu.Unlock()

	candidates := []string{os.Getenv(EnvVAPIDSubject)}
	if cfg, err := s.controlStore.GetGlobalSMTPSettings(ctx); err == nil {
		candidates = append(candidates, cfg.FromEmail)
	}
	candidates = append(candidates, s.baseURL)
	subject := ""
	for _, c := range candidates {
		if v := normalizeSubject(c); v != "" {
			subject = v
			break
		}
	}
	if subject == "" {
		subject = "admin@goup.invalid"
	}
	s.mu.Lock()
	s.subject, s.subjectDone = subject, true
	s.mu.Unlock()
	return subject
}

func normalizeSubject(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "mailto:")
	switch {
	case strings.HasPrefix(raw, "https://"):
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" && !strings.EqualFold(u.Hostname(), "localhost") {
			return raw
		}
	case strings.Contains(raw, "@") && !strings.ContainsAny(raw, " \t\r\n"):
		return raw
	}
	return ""
}

// Urgency values per RFC 8030.
type Urgency = wp.Urgency

const (
	UrgencyNormal = wp.UrgencyNormal
	UrgencyHigh   = wp.UrgencyHigh
)

// SendOptions tunes one delivery.
type SendOptions struct {
	TTL     int // seconds
	Urgency Urgency
}

// SendResult is the outcome for one subscription.
type SendResult struct {
	Subscription store.PushSubscription
	// Gone is true when the push service reported the subscription as expired (404/410) and it
	// was deleted.
	Gone bool
	Err  error
}

// Send posts one payload to one subscription without touching the database.
func (s *Sender) Send(ctx context.Context, sub store.PushSubscription, payload []byte, opts SendOptions) (gone bool, err error) {
	if err := s.checkEndpoint(sub.Endpoint); err != nil {
		return false, fmt.Errorf("endpoint rejected: %w", err)
	}
	priv, pub, err := s.keys(ctx)
	if err != nil {
		return false, fmt.Errorf("vapid keys: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()

	resp, err := wp.SendNotificationWithContext(ctx, payload, &wp.Subscription{
		Endpoint: sub.Endpoint,
		Keys:     wp.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
	}, &wp.Options{
		HTTPClient:      s.client,
		Subscriber:      s.vapidSubject(ctx),
		VAPIDPublicKey:  pub,
		VAPIDPrivateKey: priv,
		TTL:             opts.TTL,
		Urgency:         opts.Urgency,
	})
	if err != nil {
		return false, fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return true, fmt.Errorf("subscription expired (http %d)", resp.StatusCode)
	default:
		return false, fmt.Errorf("push service answered http %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
}

// Deliver sends payloadFor(sub) to every subscription with a small worker pool, deletes
// subscriptions the push service reports as gone and records success/error per device.
func (s *Sender) Deliver(ctx context.Context, subs []store.PushSubscription, payloadFor func(store.PushSubscription) []byte, opts func(store.PushSubscription) SendOptions) []SendResult {
	results := make([]SendResult, len(subs))
	sem := make(chan struct{}, sendConcurrent)
	var wg sync.WaitGroup
	for i := range subs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			sub := subs[i]
			gone, err := s.Send(ctx, sub, payloadFor(sub), opts(sub))
			results[i] = SendResult{Subscription: sub, Gone: gone, Err: err}

			// Bookkeeping must survive an expired request context.
			bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			switch {
			case gone:
				_ = s.controlStore.DeletePushSubscriptionByID(bg, sub.ID)
			case err != nil:
				_ = s.controlStore.RecordPushResult(bg, sub.ID, false, err.Error())
			default:
				_ = s.controlStore.RecordPushResult(bg, sub.ID, true, "")
			}
		}(i)
	}
	wg.Wait()
	return results
}
