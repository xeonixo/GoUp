package matrix

import (
	"strings"
	"testing"
	"time"

	"goup/internal/monitor"
)

func TestStatusEmoji(t *testing.T) {
	if got := statusEmoji(monitor.StatusUp); got == "" {
		t.Fatalf("expected emoji for up")
	}
	if got := statusEmoji(monitor.StatusDegraded); got == "" {
		t.Fatalf("expected emoji for degraded")
	}
	if got := statusEmoji(monitor.StatusDown); got == "" {
		t.Fatalf("expected emoji for down")
	}
}

func TestFormatTransitionMessage(t *testing.T) {
	msg := formatTransitionMessage(monitor.Transition{
		Monitor:      monitor.Monitor{Name: "DB", Kind: monitor.KindTCP, Target: "db:5432"},
		Previous:     monitor.StatusDown,
		Current:      monitor.StatusUp,
		CheckedAt:    time.Now().UTC(),
		ResultDetail: "ok",
	}, "en")
	if !strings.Contains(msg, "DB") || !strings.Contains(msg, "db:5432") {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestNotifierEnabled(t *testing.T) {
	n := NewNotifier(nil, 1)
	if n.Enabled() {
		t.Fatalf("notifier without client should not be enabled")
	}
	n = NewNotifier(&Client{homeserverURL: "https://m", accessToken: "t", roomID: "!r"}, 1)
	if !n.Enabled() {
		t.Fatalf("notifier with client should be enabled")
	}
}
