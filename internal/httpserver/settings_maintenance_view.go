package httpserver

import (
	"bytes"
	"fmt"
	"goup/internal/monitor"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type maintenanceRowView struct {
	ID          int64
	Title       string
	Description string
	// StartsRaw/EndsRaw are the UTC instants of the shown occurrence (active, next or last).
	StartsRaw   string
	EndsRaw     string
	StartsLabel string
	EndsLabel   string
	// FirstStartRaw/FirstEndRaw define the series and prefill the edit form.
	FirstStartRaw string
	FirstEndRaw   string
	Timezone      string
	Recurrence    string
	Scope         string
	Targets       string
	State         string // active, upcoming, past
}

type maintenanceMonitorOption struct {
	ID       int64
	Name     string
	Group    string
	Selected bool
}

type maintenanceGroupOption struct {
	Name     string
	Selected bool
}

type maintenanceFormView struct {
	ID          int64
	Title       string
	Description string
	StartsRaw   string
	EndsRaw     string
	StartsLocal string
	EndsLocal   string
	Timezone    string
	Recurrence  string
	Scope       string
}

// maintenanceAdminView backs the "Maintenance windows" settings page.
type maintenanceAdminView struct {
	Active   []maintenanceRowView
	Upcoming []maintenanceRowView
	Past     []maintenanceRowView
	Monitors []maintenanceMonitorOption
	Groups   []maintenanceGroupOption
	Form     maintenanceFormView
	Editing  bool
}

func maintenanceLabel(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func maintenanceWallClock(t time.Time, loc *time.Location) string {
	return t.In(loc).Format(maintenanceLocalLayout)
}

func icsEscapeText(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, ";", `\;`)
	value = strings.ReplaceAll(value, ",", `\,`)
	value = strings.ReplaceAll(value, "\r\n", `\n`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return value
}

func icsFoldLine(line string) string {
	const limit = 75
	if len(line) <= limit {
		return line
	}
	var b strings.Builder
	b.WriteString(line[:limit])
	rest := line[limit:]
	for len(rest) > 0 {
		b.WriteString("\r\n ")
		n := limit - 1
		if n > len(rest) {
			n = len(rest)
		}
		b.WriteString(rest[:n])
		rest = rest[n:]
	}
	return b.String()
}

func maintenanceRRULE(recurrence string) string {
	switch monitor.NormalizeRecurrence(recurrence) {
	case monitor.RecurrenceDaily:
		return "FREQ=DAILY"
	case monitor.RecurrenceWeekly:
		return "FREQ=WEEKLY"
	case monitor.RecurrenceMonthly:
		return "FREQ=MONTHLY"
	}
	return ""
}

// buildMaintenanceICS renders a VCALENDAR of the tenant's maintenance windows.
func buildMaintenanceICS(windows []monitor.MaintenanceWindow, slug string, now time.Time) []byte {
	var buf bytes.Buffer
	buf.WriteString("BEGIN:VCALENDAR\r\n")
	buf.WriteString("VERSION:2.0\r\n")
	buf.WriteString("PRODID:-//GoUp//Maintenance Windows//EN\r\n")
	buf.WriteString("CALSCALE:GREGORIAN\r\n")
	buf.WriteString("METHOD:PUBLISH\r\n")
	stamp := now.UTC().Format("20060102T150405Z")
	for _, w := range windows {
		tz := monitor.NormalizeTimezone(w.Timezone)
		loc := w.Location()
		startLocal := w.StartsAt.In(loc)
		endLocal := w.EndsAt.In(loc)
		uid := fmt.Sprintf("maintenance-%d@%s.goup", w.ID, slug)
		buf.WriteString("BEGIN:VEVENT\r\n")
		buf.WriteString(icsFoldLine("UID:"+uid) + "\r\n")
		buf.WriteString("DTSTAMP:" + stamp + "\r\n")
		if tz == "UTC" {
			buf.WriteString("DTSTART:" + startLocal.UTC().Format("20060102T150405Z") + "\r\n")
			buf.WriteString("DTEND:" + endLocal.UTC().Format("20060102T150405Z") + "\r\n")
		} else {
			buf.WriteString(icsFoldLine("DTSTART;TZID="+tz+":"+startLocal.Format("20060102T150405")) + "\r\n")
			buf.WriteString(icsFoldLine("DTEND;TZID="+tz+":"+endLocal.Format("20060102T150405")) + "\r\n")
		}
		buf.WriteString(icsFoldLine("SUMMARY:"+icsEscapeText(w.Title)) + "\r\n")
		if desc := strings.TrimSpace(w.Description); desc != "" {
			buf.WriteString(icsFoldLine("DESCRIPTION:"+icsEscapeText(desc)) + "\r\n")
		}
		if rrule := maintenanceRRULE(w.Recurrence); rrule != "" {
			buf.WriteString("RRULE:" + rrule + "\r\n")
		}
		buf.WriteString("END:VEVENT\r\n")
	}
	buf.WriteString("END:VCALENDAR\r\n")
	return buf.Bytes()
}

func (s *Server) maintenanceRedirect(w http.ResponseWriter, r *http.Request, kind, message string) {
	http.Redirect(w, r, s.tenantAppBase(r)+"settings/maintenance?"+kind+"="+url.QueryEscape(message), http.StatusSeeOther)
}

func buildMaintenanceAdminView(windows []monitor.MaintenanceWindow, snapshots []monitor.Snapshot, now time.Time, editID int64) maintenanceAdminView {
	names := make(map[int64]string, len(snapshots))
	groupSet := map[string]struct{}{}
	view := maintenanceAdminView{Form: maintenanceFormView{Recurrence: monitor.RecurrenceNone, Scope: monitor.MaintenanceScopeAll, Timezone: "UTC"}}
	for _, snap := range snapshots {
		names[snap.Monitor.ID] = snap.Monitor.Name
		if g := strings.TrimSpace(snap.Monitor.Group); g != "" {
			groupSet[g] = struct{}{}
		}
	}

	var editing *monitor.MaintenanceWindow
	for i := range windows {
		w := windows[i]
		if w.ID == editID {
			editing = &windows[i]
		}
		start, end, active, ok := w.Occurrence(now)
		row := maintenanceRowView{
			ID: w.ID, Title: w.Title, Description: w.Description,
			FirstStartRaw: w.StartsAt.UTC().Format(time.RFC3339),
			FirstEndRaw:   w.EndsAt.UTC().Format(time.RFC3339),
			Timezone:      monitor.NormalizeTimezone(w.Timezone),
			Recurrence:    w.Recurrence, Scope: w.Scope,
		}
		switch w.Scope {
		case monitor.MaintenanceScopeMonitors:
			var parts []string
			for _, id := range w.MonitorIDs {
				if name, known := names[id]; known {
					parts = append(parts, name)
				}
			}
			row.Targets = strings.Join(parts, ", ")
		case monitor.MaintenanceScopeGroups:
			row.Targets = strings.Join(w.Groups, ", ")
		}
		if !ok {
			start, end = w.StartsAt, w.EndsAt
			row.State = "past"
		} else if active {
			row.State = "active"
		} else {
			row.State = "upcoming"
		}
		row.StartsRaw, row.EndsRaw = start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339)
		row.StartsLabel, row.EndsLabel = maintenanceLabel(start), maintenanceLabel(end)
		switch row.State {
		case "active":
			view.Active = append(view.Active, row)
		case "upcoming":
			view.Upcoming = append(view.Upcoming, row)
		default:
			view.Past = append(view.Past, row)
		}
	}
	sort.SliceStable(view.Upcoming, func(i, j int) bool { return view.Upcoming[i].StartsRaw < view.Upcoming[j].StartsRaw })
	sort.SliceStable(view.Past, func(i, j int) bool { return view.Past[i].StartsRaw > view.Past[j].StartsRaw })
	if len(view.Past) > maintenancePastLimit {
		view.Past = view.Past[:maintenancePastLimit]
	}

	selectedMonitors := map[int64]bool{}
	selectedGroups := map[string]bool{}
	if editing != nil {
		view.Editing = true
		loc := editing.Location()
		view.Form = maintenanceFormView{
			ID: editing.ID, Title: editing.Title, Description: editing.Description,
			StartsRaw: editing.StartsAt.UTC().Format(time.RFC3339), EndsRaw: editing.EndsAt.UTC().Format(time.RFC3339),
			StartsLocal: maintenanceWallClock(editing.StartsAt, loc), EndsLocal: maintenanceWallClock(editing.EndsAt, loc),
			Timezone: monitor.NormalizeTimezone(editing.Timezone), Recurrence: editing.Recurrence, Scope: editing.Scope,
		}
		for _, id := range editing.MonitorIDs {
			selectedMonitors[id] = true
		}
		for _, g := range editing.Groups {
			selectedGroups[g] = true
		}
	}
	for _, snap := range snapshots {
		view.Monitors = append(view.Monitors, maintenanceMonitorOption{
			ID: snap.Monitor.ID, Name: snap.Monitor.Name, Group: strings.TrimSpace(snap.Monitor.Group), Selected: selectedMonitors[snap.Monitor.ID],
		})
	}
	groups := make([]string, 0, len(groupSet))
	for g := range groupSet {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		view.Groups = append(view.Groups, maintenanceGroupOption{Name: g, Selected: selectedGroups[g]})
	}
	return view
}
