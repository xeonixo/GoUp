package monitor

import (
	"sort"
	"strings"
	"time"
)

// Maintenance recurrence modes.
const (
	RecurrenceNone    = "none"
	RecurrenceDaily   = "daily"
	RecurrenceWeekly  = "weekly"
	RecurrenceMonthly = "monthly"
)

// Maintenance scopes.
const (
	MaintenanceScopeAll      = "all"
	MaintenanceScopeMonitors = "monitors"
	MaintenanceScopeGroups   = "groups"
)

// MaintenanceWindow is a planned period in which the covered monitors are not alarmed and do
// not count towards uptime. StartsAt/EndsAt are stored as UTC instants; EndsAt-StartsAt is the
// length of every occurrence. Timezone is an IANA name (default UTC) used when evaluating
// recurring starts so daily/weekly/monthly windows keep a stable local wall-clock time across
// daylight-saving changes.
type MaintenanceWindow struct {
	ID          int64
	Title       string
	Description string
	StartsAt    time.Time
	EndsAt      time.Time
	Timezone    string
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
	case RecurrenceMonthly:
		return RecurrenceMonthly
	}
	return RecurrenceNone
}

// NormalizeTimezone returns a valid IANA timezone name. Empty or unknown values become UTC.
func NormalizeTimezone(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "UTC"
	}
	if _, err := time.LoadLocation(value); err != nil {
		return "UTC"
	}
	return value
}

// ValidTimezone reports whether value is empty (meaning UTC) or a loadable IANA name.
func ValidTimezone(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	_, err := time.LoadLocation(value)
	return err == nil
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

// Location returns the window's IANA location, falling back to UTC.
func (w MaintenanceWindow) Location() *time.Location {
	name := NormalizeTimezone(w.Timezone)
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	return loc
}

// Length is the duration of one occurrence.
func (w MaintenanceWindow) Length() time.Duration { return w.EndsAt.Sub(w.StartsAt) }

// addRecurrence advances t by n recurrence periods in t's location, preserving wall clock.
func addRecurrence(t time.Time, recurrence string, n int) time.Time {
	if n == 0 {
		return t
	}
	y, m, d := t.Date()
	h, min, sec := t.Clock()
	ns := t.Nanosecond()
	loc := t.Location()
	switch recurrence {
	case RecurrenceDaily:
		return time.Date(y, m, d+n, h, min, sec, ns, loc)
	case RecurrenceWeekly:
		return time.Date(y, m, d+7*n, h, min, sec, ns, loc)
	case RecurrenceMonthly:
		target := time.Date(y, m+time.Month(n), 1, h, min, sec, ns, loc)
		lastDay := time.Date(target.Year(), target.Month()+1, 0, 0, 0, 0, 0, loc).Day()
		day := d
		if day > lastDay {
			day = lastDay
		}
		return time.Date(target.Year(), target.Month(), day, h, min, sec, ns, loc)
	}
	return t
}

func estimateRecurrenceIndex(first, now time.Time, recurrence string) int {
	switch recurrence {
	case RecurrenceDaily:
		days := int(now.Sub(first) / (24 * time.Hour))
		if days < 0 {
			return 0
		}
		return days
	case RecurrenceWeekly:
		weeks := int(now.Sub(first) / (7 * 24 * time.Hour))
		if weeks < 0 {
			return 0
		}
		return weeks
	case RecurrenceMonthly:
		months := (now.Year()-first.Year())*12 + int(now.Month()-first.Month())
		if months < 0 {
			return 0
		}
		return months
	}
	return 0
}

// Occurrence returns the occurrence that is active at now or, when none is, the next upcoming
// one. ok is false when the window is over for good (non-recurring and already ended).
func (w MaintenanceWindow) Occurrence(now time.Time) (start, end time.Time, active bool, ok bool) {
	length := w.Length()
	if length <= 0 {
		return time.Time{}, time.Time{}, false, false
	}
	loc := w.Location()
	nowLocal := now.In(loc)
	first := w.StartsAt.In(loc)
	recurrence := NormalizeRecurrence(w.Recurrence)

	if recurrence == RecurrenceNone || nowLocal.Before(first) {
		endLocal := first.Add(length)
		if nowLocal.Before(first) {
			return first.UTC(), endLocal.UTC(), false, true
		}
		if nowLocal.Before(endLocal) {
			return first.UTC(), endLocal.UTC(), true, true
		}
		if recurrence == RecurrenceNone {
			return time.Time{}, time.Time{}, false, false
		}
	}

	n := estimateRecurrenceIndex(first, nowLocal, recurrence)
	startLocal := addRecurrence(first, recurrence, n)
	for n > 0 && nowLocal.Before(startLocal) {
		n--
		startLocal = addRecurrence(first, recurrence, n)
	}
	endLocal := startLocal.Add(length)
	for !nowLocal.Before(endLocal) {
		n++
		startLocal = addRecurrence(first, recurrence, n)
		endLocal = startLocal.Add(length)
		if n > 100000 {
			return time.Time{}, time.Time{}, false, false
		}
	}
	active = !nowLocal.Before(startLocal)
	return startLocal.UTC(), endLocal.UTC(), active, true
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
