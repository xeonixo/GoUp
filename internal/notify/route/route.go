// Package route filters notification deliveries by monitor group/ID, severity and quiet hours.
package route

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	SeverityDown     = "down"
	SeverityDegraded = "degraded"
	SeverityRecovery = "recovery"
	SeverityReminder = "reminder"

	QuietModeSuppress = "suppress"
)

// Route decides whether a transition should be delivered to an endpoint.
// Empty Groups, MonitorIDs and Severities each mean "match all".
// When both Groups and MonitorIDs are set, a hit on either is enough (OR).
type Route struct {
	Groups     []string    `json:"groups,omitempty"`
	MonitorIDs []int64     `json:"monitor_ids,omitempty"`
	Severities []string    `json:"severities,omitempty"`
	QuietHours *QuietHours `json:"quiet_hours,omitempty"`
}

// QuietHours suppresses deliveries while local time in TZ is inside [Start, End).
// Only Mode "suppress" is supported; other modes are ignored.
type QuietHours struct {
	TZ    string `json:"tz"`
	Start string `json:"start"` // HH:MM
	End   string `json:"end"`   // HH:MM
	Mode  string `json:"mode"`  // "suppress"
}

// Parse extracts a Route from a JSON object that may contain a "route" key.
// Missing or null "route" yields an empty Route (match all).
func Parse(configJSON []byte) (Route, error) {
	raw := strings.TrimSpace(string(configJSON))
	if raw == "" {
		return Route{}, nil
	}
	var wrapper struct {
		Route *Route `json:"route"`
	}
	if err := json.Unmarshal([]byte(raw), &wrapper); err != nil {
		return Route{}, fmt.Errorf("parse notification route: %w", err)
	}
	if wrapper.Route == nil {
		return Route{}, nil
	}
	return normalize(*wrapper.Route), nil
}

// SeverityOf maps a status transition to a routing severity, mirroring webpush.CategoryOf.
// Reminder covers Transition.Reminder and ongoing down→down announcements.
func SeverityOf(previous, current string, reminder bool) string {
	previous = strings.ToLower(strings.TrimSpace(previous))
	current = strings.ToLower(strings.TrimSpace(current))
	if reminder || (previous == SeverityDown && current == SeverityDown) {
		return SeverityReminder
	}
	switch current {
	case "up":
		return SeverityRecovery
	case SeverityDown:
		return SeverityDown
	default: // degraded (incl. certificate warnings) and unknown
		return SeverityDegraded
	}
}

// Matches reports whether the endpoint should receive this event at now.
func (r Route) Matches(monitorGroup string, monitorID int64, severity string, now time.Time) bool {
	if !r.matchesTarget(monitorGroup, monitorID) {
		return false
	}
	if !r.matchesSeverity(severity) {
		return false
	}
	if r.inQuietHours(now) {
		return false
	}
	return true
}

func (r Route) matchesTarget(monitorGroup string, monitorID int64) bool {
	groups := normalizeStrings(r.Groups, false)
	ids := uniqueIDs(r.MonitorIDs)
	if len(groups) == 0 && len(ids) == 0 {
		return true
	}
	groupHit := false
	if len(groups) > 0 {
		monitorGroup = strings.TrimSpace(monitorGroup)
		for _, g := range groups {
			if g == monitorGroup {
				groupHit = true
				break
			}
		}
	}
	idHit := false
	if len(ids) > 0 {
		for _, id := range ids {
			if id == monitorID {
				idHit = true
				break
			}
		}
	}
	if len(groups) > 0 && len(ids) > 0 {
		return groupHit || idHit
	}
	if len(groups) > 0 {
		return groupHit
	}
	return idHit
}

func (r Route) matchesSeverity(severity string) bool {
	wanted := normalizeStrings(r.Severities, true)
	if len(wanted) == 0 {
		return true
	}
	severity = strings.ToLower(strings.TrimSpace(severity))
	for _, s := range wanted {
		if s == severity {
			return true
		}
	}
	return false
}

func (r Route) inQuietHours(now time.Time) bool {
	q := r.QuietHours
	if q == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(q.Mode))
	if mode == "" {
		mode = QuietModeSuppress
	}
	if mode != QuietModeSuppress {
		return false
	}
	loc, err := time.LoadLocation(strings.TrimSpace(q.TZ))
	if err != nil || loc == nil {
		return false
	}
	startMin, okStart := parseHHMM(q.Start)
	endMin, okEnd := parseHHMM(q.End)
	if !okStart || !okEnd {
		return false
	}
	local := now.In(loc)
	nowMin := local.Hour()*60 + local.Minute()
	if startMin == endMin {
		// Zero-width window never suppresses.
		return false
	}
	if startMin < endMin {
		return nowMin >= startMin && nowMin < endMin
	}
	// Overnight window (e.g. 22:00–07:00).
	return nowMin >= startMin || nowMin < endMin
}

// HasSeverity reports whether severity is selected (for settings UI checkboxes).
func (r Route) HasSeverity(severity string) bool {
	severity = strings.ToLower(strings.TrimSpace(severity))
	for _, s := range r.Severities {
		if strings.ToLower(strings.TrimSpace(s)) == severity {
			return true
		}
	}
	return false
}

// GroupsCSV joins groups for form value display.
func (r Route) GroupsCSV() string {
	return strings.Join(normalizeStrings(r.Groups, false), ", ")
}

// MonitorIDsCSV joins monitor IDs for form value display.
func (r Route) MonitorIDsCSV() string {
	if len(r.MonitorIDs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.MonitorIDs))
	for _, id := range uniqueIDs(r.MonitorIDs) {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ", ")
}

func normalize(r Route) Route {
	r.Groups = normalizeStrings(r.Groups, false)
	r.MonitorIDs = uniqueIDs(r.MonitorIDs)
	r.Severities = normalizeStrings(r.Severities, true)
	if r.QuietHours != nil {
		q := *r.QuietHours
		q.TZ = strings.TrimSpace(q.TZ)
		q.Start = strings.TrimSpace(q.Start)
		q.End = strings.TrimSpace(q.End)
		q.Mode = strings.ToLower(strings.TrimSpace(q.Mode))
		if q.Mode == "" {
			q.Mode = QuietModeSuppress
		}
		if q.TZ == "" && q.Start == "" && q.End == "" {
			r.QuietHours = nil
		} else {
			r.QuietHours = &q
		}
	}
	return r
}

func normalizeStrings(values []string, lower bool) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if lower {
			v = strings.ToLower(v)
		}
		key := strings.ToLower(v)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func uniqueIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	out := make([]int64, 0, len(ids))
	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseHHMM(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 0, false
	}
	hour, errH := strconv.Atoi(parts[0])
	min, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil || hour < 0 || hour > 23 || min < 0 || min > 59 {
		return 0, false
	}
	return hour*60 + min, true
}
