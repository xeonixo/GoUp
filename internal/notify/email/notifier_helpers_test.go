package email

import (
	"strings"
	"testing"
	"time"

	"goup/internal/monitor"
)

func TestNormalizeEmailLanguage(t *testing.T) {
	if got := normalizeEmailLanguage("de-DE"); got != "de" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeEmailLanguage("en-US"); got != "en" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeEmailLanguage("fr"); got != defaultEmailLanguage {
		t.Fatalf("got %q", got)
	}
}

func TestLocalizedMonitorStatusFallback(t *testing.T) {
	translations := map[string]string{"email.status.up": "UPX"}
	if got := localizedMonitorStatus(monitor.StatusUp, translations); got != "UPX" {
		t.Fatalf("got %q", got)
	}
	if got := localizedMonitorStatus(monitor.Status("custom"), translations); got != "CUSTOM" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatAndSanitize(t *testing.T) {
	if got := formatEmailTemplate("Hello {name}", map[string]string{"name": "Dev"}); got != "Hello Dev" {
		t.Fatalf("got %q", got)
	}
	if got := sanitizeEmailHeader("a\r\nb"); got != "ab" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildStatusTransitionSubject(t *testing.T) {
	transition := monitor.Transition{
		Monitor:   monitor.Monitor{Name: "API"},
		Previous:  monitor.StatusDown,
		Current:   monitor.StatusUp,
		CheckedAt: time.Now().UTC(),
	}
	subject := buildStatusTransitionSubject(transition, map[string]string{})
	if !strings.Contains(subject, "API") {
		t.Fatalf("subject missing monitor name: %q", subject)
	}
}
