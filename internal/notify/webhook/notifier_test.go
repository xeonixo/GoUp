package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type stubStore struct {
	endpoints []store.WebhookEndpoint
}

func (s stubStore) ListWebhookEndpoints(context.Context) ([]store.WebhookEndpoint, error) {
	return s.endpoints, nil
}

type stubSecrets struct {
	secret string
}

func (s stubSecrets) GetTenantNotificationEndpointSecret(context.Context, int64, int64, string) (string, error) {
	return s.secret, nil
}

func TestValidateTargetURL(t *testing.T) {
	if _, err := ValidateTargetURL("http://example.com/hook"); err == nil {
		t.Fatalf("expected http url to be rejected")
	}
	if _, err := ValidateTargetURL("https://127.0.0.1/hook"); err == nil {
		t.Fatalf("expected loopback target to be rejected")
	}
	if _, err := ValidateTargetURL("https://example.com/hook"); err != nil {
		t.Fatalf("expected public https url to be accepted: %v", err)
	}
}

func TestSignPayload(t *testing.T) {
	secret := "secret"
	timestamp := "2026-05-05T12:00:00Z"
	body := []byte(`{"ok":true}`)
	got := signPayload(secret, timestamp, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	want := "v1=" + hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("signature mismatch: got %q want %q", got, want)
	}
}

func TestNotifyAllDeliversSignedPayload(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("X-GoUp-Event"); got != EventType {
			t.Fatalf("unexpected event header %q", got)
		}
		if got := r.Header.Get("X-GoUp-Signature"); !strings.HasPrefix(got, "v1=") {
			t.Fatalf("missing signature header: %q", got)
		}
		var payload payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload.Monitor.Name != "API" {
			t.Fatalf("unexpected payload monitor: %+v", payload.Monitor)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	notifier := NewNotifier(
		stubStore{endpoints: []store.WebhookEndpoint{{
			ID:             7,
			Name:           "Primary",
			Enabled:        true,
			URL:            server.URL,
			TimeoutSeconds: 5,
		}}},
		stubSecrets{secret: "secret"},
		3,
	)
	notifier.now = func() time.Time { return time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC) }
	notifier.validateURL = func(raw string) (*url.URL, error) {
		return url.Parse(raw)
	}
	notifier.newHTTPClient = func(timeout time.Duration) *http.Client {
		client := server.Client()
		client.Timeout = timeout
		return client
	}

	results, err := notifier.NotifyAll(context.Background(), monitor.Transition{
		Monitor:      monitor.Monitor{ID: 11, Name: "API", Kind: monitor.KindHTTPS, Target: "https://api.example.com/health"},
		Previous:     monitor.StatusDown,
		Current:      monitor.StatusUp,
		CheckedAt:    time.Date(2026, 5, 5, 11, 59, 0, 0, time.UTC),
		ResultDetail: "ok",
	})
	if err != nil {
		t.Fatalf("notify all: %v", err)
	}
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("unexpected results: %+v", results)
	}
	if requests != 1 {
		t.Fatalf("expected one request, got %d", requests)
	}
}

func TestSendTestUsesTestEventType(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("X-GoUp-Event"); got != TestEventType {
			t.Fatalf("unexpected event header %q", got)
		}
		var payload payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload.EventType != TestEventType {
			t.Fatalf("unexpected payload event type %q", payload.EventType)
		}
		if payload.Monitor.Name != "GoUp Webhook Test" {
			t.Fatalf("unexpected test payload monitor: %+v", payload.Monitor)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	notifier := NewNotifier(
		stubStore{endpoints: []store.WebhookEndpoint{{
			ID:             9,
			Name:           "Primary",
			Enabled:        true,
			URL:            server.URL,
			TimeoutSeconds: 5,
		}}},
		stubSecrets{secret: "secret"},
		44,
	)
	notifier.now = func() time.Time { return time.Date(2026, 5, 5, 13, 0, 0, 0, time.UTC) }
	notifier.validateURL = func(raw string) (*url.URL, error) {
		return url.Parse(raw)
	}
	notifier.newHTTPClient = func(timeout time.Duration) *http.Client {
		client := server.Client()
		client.Timeout = timeout
		return client
	}

	if err := notifier.SendTest(context.Background(), 9, "prod"); err != nil {
		t.Fatalf("send test: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected one request, got %d", requests)
	}
}
