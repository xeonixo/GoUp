package monitor

import (
	"sort"
	"strings"
	"time"
)

// Maintenance recurrence modes.
const (
	RecurrenceNone   = "none"
	RecurrenceDaily  = "daily"
	RecurrenceWeekly = "weekly"
)

// Maintenance scopes.
const (
	MaintenanceScopeAll      = "all"
	MaintenanceScopeMonitors = "monitors"
	MaintenanceScopeGroups   = "groups"
)

// MaintenanceWindow is a planned period in which the covered monitors are not alarmed and do
// not count towards uptime. StartsAt/EndsAt are UTC; EndsAt-StartsAt is the length of every
// occurrence. Recurring windows repeat every 24 h / 7 x 24 h in UTC (pure UTC arithmetic, so
// the local wall-clock time shifts by one hour across a DST change).
type MaintenanceWindow struct {
	ID          int64
	Title       string
	Description string
	StartsAt    time.Time
	EndsAt      time.Time
	Recurrence  string
	Scope       string
	MonitorIDs  []int64
	Groups      []string
	CreatedBy   int64
	CreatedAt   time.Time
}

// NormalizeRecurrence returns a valid recurrence value (default none).
func NormalizeRecurrence(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case RecurrenceDaily:
		return RecurrenceDaily
	case RecurrenceWeekly:
		return RecurrenceWeekly
	}
	return RecurrenceNone
}

// NormalizeMaintenanceScope returns a valid scope (default all).
func NormalizeMaintenanceScope(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case MaintenanceScopeMonitors:
		return MaintenanceScopeMonitors
	case MaintenanceScopeGroups:
		return MaintenanceScopeGroups
	}
	return MaintenanceScopeAll
}

func (w MaintenanceWindow) period() time.Duration {
	switch w.Recurrence {
	case RecurrenceDaily:
		return 24 * time.Hour
	case RecurrenceWeekly:
		return 7 * 24 * time.Hour
	}
	return 0
}

// Length is the duration of one occurrence.
func (w MaintenanceWindow) Length() time.Duration { return w.EndsAt.Sub(w.StartsAt) }

// Occurrence returns the occurrence that is active at now or, when none is, the next upcoming
// one. ok is false when the window is over for good (non-recurring and already ended).
func (w MaintenanceWindow) Occurrence(now time.Time) (start, end time.Time, active bool, ok bool) {
	length := w.Length()
	if length <= 0 {
		return time.Time{}, time.Time{}, false, false
	}
	now = now.UTC()
	first := w.StartsAt.UTC()
	period := w.period()
	if period == 0 || now.Before(first) {
		if now.Before(first) {
			return first, first.Add(length), false, true
		}
		end = first.Add(length)
		if now.Before(end) {
			return first, end, true, true
		}
		return time.Time{}, time.Time{}, false, false
	}
	n := now.Sub(first) / period
	start = first.Add(n * period)
	end = start.Add(length)
	if now.Before(end) {
		return start, end, true, true
	}
	start = start.Add(period)
	return start, start.Add(length), false, true
}

// ActiveAt reports whether an occurrence is running at now.
func (w MaintenanceWindow) ActiveAt(now time.Time) bool {
	_, _, active, ok := w.Occurrence(now)
	return ok && active
}

// Covers reports whether the window applies to the monitor.
func (w MaintenanceWindow) Covers(monitorID int64, group string) bool {
	switch w.Scope {
	case MaintenanceScopeMonitors:
		for _, id := range w.MonitorIDs {
			if id == monitorID {
				return true
			}
		}
		return false
	case MaintenanceScopeGroups:
		group = strings.TrimSpace(group)
		for _, name := range w.Groups {
			if strings.TrimSpace(name) == group {
				return true
			}
		}
		return false
	}
	return true
}

// MaintenanceSet is an immutable snapshot of all windows with lookup helpers.
type MaintenanceSet struct {
	Windows []MaintenanceWindow
}

// Active returns the first window covering the monitor that is running at now.
func (s MaintenanceSet) Active(monitorID int64, group string, now time.Time) (MaintenanceWindow, bool) {
	for _, w := range s.Windows {
		if w.Covers(monitorID, group) && w.ActiveAt(now) {
			return w, true
		}
	}
	return MaintenanceWindow{}, false
}

// MaintenanceOccurrence is one concrete (start, end) of a window.
type MaintenanceOccurrence struct {
	Window MaintenanceWindow
	Start  time.Time
	End    time.Time
	Active bool
}

// Upcoming returns the active occurrences and those starting before horizon, soonest first.
func (s MaintenanceSet) Upcoming(now, horizon time.Time) []MaintenanceOccurrence {
	var items []MaintenanceOccurrence
	for _, w := range s.Windows {
		start, end, active, ok := w.Occurrence(now)
		if !ok || (!active && !start.Before(horizon)) {
			continue
		}
		items = append(items, MaintenanceOccurrence{Window: w, Start: start, End: end, Active: active})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Start.Before(items[j].Start) })
	return items
}
