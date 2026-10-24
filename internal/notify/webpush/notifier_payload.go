package webpush

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"goup/internal/monitor"
)

// MonitorTag is the notification tag; a newer push for the same monitor replaces the old one.
func MonitorTag(tenantID, monitorID int64) string {
	return fmt.Sprintf("goup-monitor-%d-%d", tenantID, monitorID)
}

// MonitorPath is the same-origin path of a monitor's detail page.
func MonitorPath(tenantSlug string, monitorID int64) string {
	prefix := ""
	if tenantSlug = strings.Trim(strings.TrimSpace(tenantSlug), "/"); tenantSlug != "" {
		prefix = "/" + tenantSlug
	}
	return prefix + "/monitors/" + strconv.FormatInt(monitorID, 10)
}

// BuildPayload renders the localized notification for a transition.
func BuildPayload(t monitor.Transition, tenantID int64, tenantSlug, language string, badge *int, downtime, latency time.Duration) Payload {
	tr := translations(language)
	name := strings.TrimSpace(t.Monitor.Name)
	titleKey := "push.title.degraded"
	switch t.Current {
	case monitor.StatusDown:
		titleKey = "push.title.down"
	case monitor.StatusUp:
		titleKey = "push.title.up"
	case monitor.StatusUnknown:
		titleKey = "push.title.unknown"
	}
	if t.Reminder {
		titleKey = "push.title.reminder"
	}
	title := strings.ReplaceAll(text(tr, titleKey, "{name}"), "{name}", name)

	var parts []string
	if t.Reminder && t.OutageDuration > 0 {
		parts = append(parts, strings.ReplaceAll(text(tr, "push.body.reminder", "Down for {duration}"), "{duration}", formatDuration(t.OutageDuration)))
	}
	if t.CatchUp {
		parts = append(parts, text(tr, "push.body.catchup", "Summary after mute"))
	}
	if detail := strings.TrimSpace(t.ResultDetail); detail != "" && t.Current != monitor.StatusUp {
		parts = append(parts, detail)
	}
	if t.Current == monitor.StatusUp && downtime > 0 {
		parts = append(parts, strings.ReplaceAll(text(tr, "push.body.downtime", "Outage: {duration}"), "{duration}", formatDuration(downtime)))
	}
	if latency > 0 && t.Current != monitor.StatusDown {
		parts = append(parts, strings.ReplaceAll(text(tr, "push.body.latency", "Latency: {latency}"), "{latency}", latency.Round(time.Millisecond).String()))
	}
	if len(parts) == 0 {
		parts = append(parts, strings.ToUpper(string(t.Previous))+" → "+strings.ToUpper(string(t.Current)))
	}
	return Payload{
		Title:      title,
		Body:       truncate(strings.Join(parts, " · "), maxBodyRunes),
		URL:        MonitorPath(tenantSlug, t.Monitor.ID),
		Tag:        MonitorTag(tenantID, t.Monitor.ID),
		BadgeCount: badge,
	}
}

// BuildTestPayload renders the payload of the "send test" button. targetURL is the page the
// notification opens.
func BuildTestPayload(language, targetURL string) Payload {
	tr := translations(language)
	return Payload{
		Title: text(tr, "push.test.title", "GoUp test notification"),
		Body:  text(tr, "push.test.body", "Push notifications work on this device."),
		URL:   targetURL,
		Tag:   "goup-test",
	}
}

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:max-1])) + "…"
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		h, m := int(d.Hours()), int(d.Minutes())%60
		if m == 0 {
			return fmt.Sprintf("%d h", h)
		}
		return fmt.Sprintf("%d h %d min", h, m)
	}
	return fmt.Sprintf("%d d", int(d.Hours())/24)
}
