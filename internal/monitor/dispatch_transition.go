package monitor

import (
	"context"
)

// evaluateTransition decides whether the result changes the announced state. settled is false
// while a failure is still waiting for its confirmation (confirm_after).
func (d *Dispatcher) evaluateTransition(ctx context.Context, snapshot Snapshot, result Result) (transition Transition, ok bool, settled bool) {
	confirm := snapshot.Monitor.ConfirmAfter
	if confirm <= 1 || snapshot.LastResult == nil {
		transition, ok = buildTransition(snapshot, result)
		return transition, ok, true
	}
	statuses, err := d.store.RecentMonitorStatuses(ctx, snapshot.Monitor.ID, confirm+1)
	if err != nil || len(statuses) == 0 {
		if err != nil {
			d.logger.Warn("load recent monitor statuses failed", "monitor_id", snapshot.Monitor.ID, "error", err)
		}
		transition, ok = buildTransition(snapshot, result)
		return transition, ok, true
	}
	return buildConfirmedTransition(snapshot, result, statuses, confirm)
}

func isFailureStatus(status Status) bool {
	return status == StatusDown || status == StatusDegraded
}

func consecutiveFailures(statuses []Status) int {
	count := 0
	for _, status := range statuses {
		if !isFailureStatus(status) {
			break
		}
		count++
	}
	return count
}

// buildConfirmedTransition implements flapping protection. statuses are the latest result
// statuses, newest first, with statuses[0] being the current result (already saved). A failure is
// announced once confirm consecutive failed results were seen; recovery is immediate but only
// announced if the failure itself was announced.
func buildConfirmedTransition(snapshot Snapshot, result Result, statuses []Status, confirm int) (Transition, bool, bool) {
	newTransition := func(previous Status) Transition {
		return Transition{
			Monitor:      snapshot.Monitor,
			Previous:     previous,
			Current:      result.Status,
			CheckedAt:    result.CheckedAt,
			ResultDetail: result.Message,
		}
	}

	switch {
	case result.Status == StatusUp:
		if len(statuses) < 2 || !snapshot.Monitor.NotifyOnRecovery {
			return Transition{}, false, true
		}
		// Unknown is announced immediately, so leaving it is always news; a failure only
		// counts once it was confirmed.
		if statuses[1] != StatusUnknown && consecutiveFailures(statuses[1:]) < confirm {
			return Transition{}, false, true
		}
		return newTransition(statuses[1]), true, true
	case !isFailureStatus(result.Status):
		transition, ok := buildTransition(snapshot, result)
		return transition, ok, true
	}

	streak := consecutiveFailures(statuses)
	switch {
	case streak < confirm:
		return Transition{}, false, false
	case streak == confirm:
		if len(statuses) <= confirm {
			// No result before the streak: nothing to compare against.
			return Transition{}, false, true
		}
		return newTransition(statuses[confirm]), true, true
	default:
		// Already announced; only a change between failure states is news.
		if snapshot.LastResult != nil && snapshot.LastResult.Status != result.Status {
			return newTransition(snapshot.LastResult.Status), true, true
		}
		return Transition{}, false, true
	}
}

func buildTransition(snapshot Snapshot, result Result) (Transition, bool) {
	if snapshot.LastResult == nil {
		return Transition{}, false
	}
	previous := snapshot.LastResult.Status
	if previous == result.Status {
		return Transition{}, false
	}
	if result.Status == StatusUp && !snapshot.Monitor.NotifyOnRecovery {
		return Transition{}, false
	}

	return Transition{
		Monitor:      snapshot.Monitor,
		Previous:     previous,
		Current:      result.Status,
		CheckedAt:    result.CheckedAt,
		ResultDetail: result.Message,
	}, true
}
