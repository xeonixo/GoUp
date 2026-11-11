package statuspage

import (
	"context"
	"strings"
	"testing"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type memSubStore struct {
	name        string
	onPage      bool
	subscribers []store.StatusPageSubscription
}

func (m *memSubStore) ListConfirmedStatusPageSubscribersForMonitor(ctx context.Context, monitorID int64) ([]store.StatusPageSubscription, error) {
	return m.subscribers, nil
}

func (m *memSubStore) StatusPageDisplayNameForMonitor(ctx context.Context, monitorID int64) (string, bool, error) {
	return m.name, m.onPage, nil
}

type memSMTP struct {
	cfg store.GlobalSMTPDeliveryConfig
}

func (m memSMTP) GetGlobalSMTPDeliveryConfig(ctx context.Context) (store.GlobalSMTPDeliveryConfig, error) {
	return m.cfg, nil
}

func TestNotifierSkipsNonPublicTransitions(t *testing.T) {
	n := NewNotifier(memSMTP{}, &memSubStore{name: "Shop", onPage: true}, 1, "http://example.test", "acme")
	err := n.Notify(context.Background(), monitor.Transition{
		Monitor: monitor.Monitor{ID: 1}, Previous: monitor.StatusUp, Current: monitor.StatusDegraded,
	})
	if err != monitor.ErrNoRecipients {
		t.Fatalf("err = %v", err)
	}
}

func TestNotifierSendsDownWithoutLeaks(t *testing.T) {
	var sent []struct{ to, subject, body string }
	n := NewNotifier(memSMTP{cfg: store.GlobalSMTPDeliveryConfig{
		Settings: store.GlobalSMTPSettings{Host: "smtp.example", Port: 587, FromEmail: "noreply@example.com"},
		Password: "secret",
	}}, &memSubStore{
		name:   "Online Shop",
		onPage: true,
		subscribers: []store.StatusPageSubscription{{
			Email: "visitor@example.com", Language: "en", UnsubscribeTokenHash: "goup_ss_abc",
		}},
	}, 7, "http://example.test", "acme")
	n.sendMail = func(cfg store.GlobalSMTPDeliveryConfig, to, subject, body string) error {
		sent = append(sent, struct{ to, subject, body string }{to, subject, body})
		return nil
	}
	err := n.Notify(context.Background(), monitor.Transition{
		Monitor:      monitor.Monitor{ID: 1, Name: "secret-internal", Target: "10.9.8.7:443"},
		Previous:     monitor.StatusUp,
		Current:      monitor.StatusDown,
		CheckedAt:    time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		ResultDetail: "dial tcp 10.9.8.7:443: connection refused",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 {
		t.Fatalf("sent = %d", len(sent))
	}
	if !strings.Contains(sent[0].subject, "Online Shop") {
		t.Fatalf("subject = %q", sent[0].subject)
	}
	for _, leak := range []string{"10.9.8.7", "secret-internal", "connection refused"} {
		if strings.Contains(sent[0].body, leak) || strings.Contains(sent[0].subject, leak) {
			t.Errorf("mail leaks %q", leak)
		}
	}
	if !strings.Contains(sent[0].body, "/acme/status/subscribe/unsubscribe?token=goup_ss_abc") {
		t.Fatalf("missing unsubscribe link: %s", sent[0].body)
	}
}
