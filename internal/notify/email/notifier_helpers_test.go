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

func TestReminderSubjectAndBody(t *testing.T) {
	tr := monitor.Transition{
		Monitor:  monitor.Monitor{Name: "API", Kind: monitor.KindHTTPS, Target: "https://x"},
		Previous: monitor.StatusDown, Current: monitor.StatusDown,
		CheckedAt: time.Now().UTC(), Reminder: true, OutageDuration: 135 * time.Minute,
	}
	tr2 := map[string]string{"email.reminder.subject": "[STILL DOWN] {monitor}: down for {duration}", "email.reminder.text": "Still down for {duration}", "email.reminder.label": "Outage reminder"}
	if got := buildStatusTransitionSubject(tr, tr2); got != "[STILL DOWN] API: down for 2 h 15 min" {
		t.Fatalf("subject = %q", got)
	}
	body := buildHTMLEmail(tr, "https://goup/", tr2)
	if !strings.Contains(body, "Still down for 2 h 15 min") || !strings.Contains(body, "Outage reminder") || strings.Contains(body, "{transitionText}") {
		t.Fatalf("reminder body wrong")
	}
	// Plain transitions keep the old rendering.
	plain := monitor.Transition{Monitor: monitor.Monitor{Name: "API"}, Previous: monitor.StatusDown, Current: monitor.StatusUp, CheckedAt: time.Now().UTC()}
	if b := buildHTMLEmail(plain, "https://goup/", map[string]string{}); !strings.Contains(b, "DOWN &#8594; UP") {
		t.Fatalf("plain transition rendering changed: missing arrow text")
	}
}
