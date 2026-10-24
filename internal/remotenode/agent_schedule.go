package remotenode

import (
	"context"
	"time"

	"goup/internal/monitor"
)

func (a *Agent) updateAssignments(assigned []assignedMonitorSpec, now time.Time) {
	a.scheduleMu.Lock()
	defer a.scheduleMu.Unlock()

	seen := make(map[int64]struct{}, len(assigned))
	for _, item := range assigned {
		seen[item.ID] = struct{}{}
		a.assignments[item.ID] = item
		interval := normalizedAssignedInterval(item)
		if a.schedule[item.ID] == nil {
			a.schedule[item.ID] = &remoteScheduleState{
				interval: interval,
				nextDue:  monitor.CascadedDueAtOrAfter(item.ID, interval, now),
			}
		} else if a.schedule[item.ID].interval != interval {
			a.schedule[item.ID].interval = interval
			if !a.schedule[item.ID].inFlight {
				a.schedule[item.ID].nextDue = monitor.CascadedDueAtOrAfter(item.ID, interval, now)
			}
		}
	}
	for monitorID := range a.assignments {
		if _, ok := seen[monitorID]; !ok {
			delete(a.assignments, monitorID)
			delete(a.schedule, monitorID)
		}
	}
}

func (a *Agent) dispatchDueChecks(ctx context.Context, now time.Time) {
	due := a.dueAssignments(now)
	for _, item := range due {
		a.dispatchCheck(ctx, item)
	}
}

func (a *Agent) dueAssignments(now time.Time) []assignedMonitorSpec {
	a.scheduleMu.Lock()
	defer a.scheduleMu.Unlock()

	due := make([]assignedMonitorSpec, 0)
	for monitorID, item := range a.assignments {
		state := a.schedule[monitorID]
		if state == nil {
			continue
		}
		interval := normalizedAssignedInterval(item)
		if state.inFlight {
			if !state.nextDue.After(now) {
				skipped := int(now.Sub(state.nextDue)/interval) + 1
				nextDue := state.nextDue.Add(time.Duration(skipped) * interval)
				a.logger.Warn("remote monitor check slot skipped: previous check still running",
					"monitor_id", monitorID,
					"scheduled_at", state.nextDue.Format(time.RFC3339),
					"next_due_at", nextDue.Format(time.RFC3339),
					"skipped_slots", skipped,
					"lag_ms", now.Sub(state.nextDue).Milliseconds(),
				)
				state.nextDue = nextDue
			}
			continue
		}
		if state.nextDue.After(now) {
			continue
		}
		if now.Sub(state.nextDue) >= interval {
			skipped := int(now.Sub(state.nextDue) / interval)
			state.nextDue = state.nextDue.Add(time.Duration(skipped) * interval)
			a.logger.Warn("remote monitor check slots skipped: scheduler lag",
				"monitor_id", monitorID,
				"scheduled_at", state.nextDue.Format(time.RFC3339),
				"skipped_slots", skipped,
				"lag_ms", now.Sub(state.nextDue).Milliseconds(),
			)
		}
		due = append(due, item)
	}
	return due
}

func normalizedAssignedInterval(item assignedMonitorSpec) time.Duration {
	if item.IntervalSeconds <= 0 {
		return time.Minute
	}
	return time.Duration(item.IntervalSeconds) * time.Second
}
