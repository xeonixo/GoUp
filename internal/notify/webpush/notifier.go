package webpush

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"goup/web"
)

const (
	// EventType is the notification event type recorded for push deliveries.
	EventType = "status_transition_webpush"
	// EndpointName is the system notification endpoint row name.
	EndpointName = "user-webpush"
	// EndpointKind is the system notification endpoint kind.
	EndpointKind = "webpush"

	pushTTLSeconds = 24 * 60 * 60
	maxBodyRunes   = 160
	dedupeTTL      = 2 * time.Hour
)

// Category is the user-facing event class a device can opt in/out of.
type Category string

const (
	CategoryDown     Category = "down"
	CategoryRecovery Category = "recovery"
	CategoryDegraded Category = "degraded"
	// CategoryReminder is used by repeated outage reminders (planned for Phase 6). The
	// transition type has no marker for it yet, so CategoryOf never returns it today.
	CategoryReminder Category = "reminder"
)

// CategoryOf maps a transition to the preference category used for filtering. When Phase 6
// adds reminder transitions, map them to CategoryReminder here.
func CategoryOf(t monitor.Transition) Category {
	switch t.Current {
	case monitor.StatusUp:
		return CategoryRecovery
	case monitor.StatusDown:
		return CategoryDown
	default: // degraded (incl. certificate warnings) and unknown
		return CategoryDegraded
	}
}

// Wants reports whether the device subscribed to the category.
func Wants(sub store.PushSubscription, c Category) bool {
	switch c {
	case CategoryDown:
		return sub.NotifyDown
	case CategoryRecovery:
		return sub.NotifyRecovery
	case CategoryDegraded:
		return sub.NotifyDegraded
	case CategoryReminder:
		return sub.NotifyReminder
	}
	return false
}

// StateReader is the part of the tenant store the notifier needs for badge count and outage
// duration. It may be nil; the payload then simply omits those details.
type StateReader interface {
	ListMonitorSnapshots(ctx context.Context) ([]monitor.Snapshot, error)
	ListMonitorIncidents(ctx context.Context, monitorID int64, limit int) ([]store.MonitorIncident, error)
}

// Payload is the JSON document the service worker receives.
type Payload struct {
	Title      string `json:"title"`
	Body       string `json:"body"`
	URL        string `json:"url"`
	Tag        string `json:"tag"`
	BadgeCount *int   `json:"badgeCount,omitempty"`
}

// Notifier pushes transitions to all (non-blocked) members' registered devices of a tenant.
type Notifier struct {
	sender       *Sender
	controlStore *store.ControlPlaneStore
	state        StateReader
	endpointID   int64
	tenantID     int64
	tenantSlug   string
	adminOnly    bool
}

// NewTenantNotifier notifies every member; NewTenantAdminNotifier only tenant admins
// (infrastructure alerts).
func NewTenantNotifier(sender *Sender, controlStore *store.ControlPlaneStore, state StateReader, endpointID, tenantID int64, tenantSlug string) *Notifier {
	return &Notifier{sender: sender, controlStore: controlStore, state: state, endpointID: endpointID, tenantID: tenantID, tenantSlug: tenantSlug}
}

func NewTenantAdminNotifier(sender *Sender, controlStore *store.ControlPlaneStore, state StateReader, endpointID, tenantID int64, tenantSlug string) *Notifier {
	n := NewTenantNotifier(sender, controlStore, state, endpointID, tenantID, tenantSlug)
	n.adminOnly = true
	return n
}

func (n *Notifier) Enabled() bool {
	return n != nil && n.endpointID > 0 && n.tenantID > 0 && n.controlStore != nil && n.sender != nil
}

func (n *Notifier) EndpointID() int64 {
	if n == nil {
		return 0
	}
	return n.endpointID
}

func (n *Notifier) EventType() string { return EventType }

// Notify sends the transition to every matching device.
//
// Retry semantics: the dispatcher's retry queue re-invokes Notify with the same transition
// when this returns an error, so it would normally re-push to devices that already got it.
// To avoid duplicates a (device, transition) pair that succeeded is remembered in memory for
// two hours and skipped on retries. Notify therefore returns an error when any device failed
// transiently (so only the failed devices are retried), and nil when everything that could be
// delivered was delivered. Expired subscriptions (404/410) are deleted and are not an error.
// After a process restart a retry may re-push once; that is accepted.
func (n *Notifier) Notify(ctx context.Context, transition monitor.Transition) error {
	if !n.Enabled() {
		return nil
	}
	targets, err := n.controlStore.ListTenantPushTargets(ctx, n.tenantID, n.adminOnly)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return monitor.ErrNoRecipients
	}
	category := CategoryOf(transition)
	tag := MonitorTag(n.tenantID, transition.Monitor.ID)
	dedupeKey := fmt.Sprintf("%s|%s|%d|%v", tag, transition.Current, transition.CheckedAt.Unix(), transition.CatchUp)

	var subs []store.PushSubscription
	langs := make(map[int64]string)
	for _, t := range targets {
		if !Wants(t.PushSubscription, category) || deliveredRecently(t.ID, dedupeKey) {
			continue
		}
		langs[t.ID] = normalizeLanguage(t.PreferredLanguage)
		subs = append(subs, t.PushSubscription)
	}
	if len(subs) == 0 {
		// Nobody wants this category, or every device already received it.
		return nil
	}

	badge, downtime, latency := n.details(ctx, transition)
	// Built before the concurrent sends; the goroutines only read the map.
	payloads := make(map[string][]byte)
	for _, lang := range langs {
		if _, ok := payloads[lang]; !ok {
			raw, _ := json.Marshal(BuildPayload(transition, n.tenantID, n.tenantSlug, lang, badge, downtime, latency))
			payloads[lang] = raw
		}
	}

	urgency := UrgencyNormal
	if category == CategoryDown {
		urgency = UrgencyHigh
	}
	results := n.sender.Deliver(ctx, subs,
		func(sub store.PushSubscription) []byte { return payloads[langs[sub.ID]] },
		func(store.PushSubscription) SendOptions { return SendOptions{TTL: pushTTLSeconds, Urgency: urgency} })

	var failures []string
	for _, r := range results {
		switch {
		case r.Gone:
		case r.Err != nil:
			failures = append(failures, fmt.Sprintf("subscription %d: %v", r.Subscription.ID, r.Err))
		default:
			markDelivered(r.Subscription.ID, dedupeKey)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("web push delivery failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

// details gathers badge count (monitors currently down), outage duration (recoveries) and the
// latest latency. Failures only reduce detail.
func (n *Notifier) details(ctx context.Context, t monitor.Transition) (badge *int, downtime time.Duration, latency time.Duration) {
	if n.state == nil {
		return nil, 0, 0
	}
	if snaps, err := n.state.ListMonitorSnapshots(ctx); err == nil {
		down := 0
		for _, s := range snaps {
			if s.Monitor.Enabled && s.LastResult != nil && s.LastResult.Status == monitor.StatusDown {
				down++
			}
			if s.Monitor.ID == t.Monitor.ID && s.LastResult != nil {
				latency = s.LastResult.Latency
			}
		}
		badge = &down
	}
	if t.Current == monitor.StatusUp {
		if incidents, err := n.state.ListMonitorIncidents(ctx, t.Monitor.ID, 1); err == nil && len(incidents) > 0 {
			if d := t.CheckedAt.Sub(incidents[0].StartedAt); d > 0 {
				downtime = d
			}
		}
	}
	return badge, downtime, latency
}

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
	title := strings.ReplaceAll(text(tr, titleKey, "{name}"), "{name}", name)

	var parts []string
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

// NormalizeLanguage maps a user language to "de" or "en".
func NormalizeLanguage(language string) string { return normalizeLanguage(language) }

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

// ── de-duplication across retries ─────────────────────────────────────

var (
	dedupeMu   sync.Mutex
	dedupeSeen = map[string]time.Time{}
)

func dedupeID(subID int64, key string) string { return strconv.FormatInt(subID, 10) + "|" + key }

func deliveredRecently(subID int64, key string) bool {
	dedupeMu.Lock()
	defer dedupeMu.Unlock()
	at, ok := dedupeSeen[dedupeID(subID, key)]
	return ok && time.Since(at) < dedupeTTL
}

func markDelivered(subID int64, key string) {
	dedupeMu.Lock()
	defer dedupeMu.Unlock()
	now := time.Now()
	dedupeSeen[dedupeID(subID, key)] = now
	if len(dedupeSeen) > 2048 {
		for k, at := range dedupeSeen {
			if now.Sub(at) > dedupeTTL {
				delete(dedupeSeen, k)
			}
		}
	}
}

// ── translations ──────────────────────────────────────────────────────

var (
	trOnce sync.Once
	trAll  map[string]map[string]string
)

func normalizeLanguage(language string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(language)), "de") {
		return "de"
	}
	return "en"
}

func translations(language string) map[string]string {
	trOnce.Do(func() {
		trAll = map[string]map[string]string{"en": {}, "de": {}}
		for lang := range trAll {
			payload, err := web.FS.ReadFile("i18n/" + lang + ".json")
			if err != nil {
				continue
			}
			items := map[string]string{}
			if json.Unmarshal(payload, &items) == nil {
				trAll[lang] = items
			}
		}
	})
	return trAll[normalizeLanguage(language)]
}

func text(tr map[string]string, key, fallback string) string {
	if v := strings.TrimSpace(tr[key]); v != "" {
		return v
	}
	return fallback
}
