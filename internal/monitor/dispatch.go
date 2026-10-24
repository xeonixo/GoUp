package monitor

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Dispatcher turns check results into persisted state and notifications. The local runner and the
// remote-node report path share it, so both use the same notifier set, mute handling,
// flapping protection and persistent retry queue.
type Dispatcher struct {
	logger              *slog.Logger
	store               Store
	notifiers           []Notifier
	notifyMaxRetries    int
	notifyRetryInterval time.Duration
	maintenance         MaintenanceChecker
	now                 func() time.Time
}

func NewDispatcher(logger *slog.Logger, store Store, notifiers ...Notifier) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	d := &Dispatcher{
		logger:              logger,
		store:               store,
		notifiers:           notifiers,
		notifyMaxRetries:    3,
		notifyRetryInterval: 5 * time.Minute,
		now:                 time.Now,
	}
	if checker, ok := store.(MaintenanceChecker); ok {
		d.maintenance = checker
	}
	return d
}

func (d *Dispatcher) inMaintenance(ctx context.Context, item Monitor, now time.Time) bool {
	return d.maintenance != nil && d.maintenance.ActiveMaintenance(ctx, item.ID, item.Group, now)
}

// ProcessResult persists a check result, records the state change and sends the resulting
// notification. snapshot is the monitor with its result from before this check. It reports
// whether the result could be saved.
func (d *Dispatcher) ProcessResult(ctx context.Context, snapshot Snapshot, result Result) bool {
	now := d.now()
	inMaintenance := d.inMaintenance(ctx, snapshot.Monitor, now)
	result.InMaintenance = inMaintenance

	if err := d.store.SaveMonitorResult(ctx, result); err != nil {
		d.logger.Error("save monitor result failed", "monitor_id", snapshot.Monitor.ID, "error", err)
		return false
	}

	// Downtime inside a maintenance window must not open incidents or state events; a recovery
	// still closes an incident that was already open.
	if !inMaintenance || result.Status == StatusUp {
		if err := d.store.RecordMonitorState(ctx, snapshot.Monitor.ID, result.Status, result.Message, result.CheckedAt); err != nil {
			d.logger.Error("record monitor state failed", "monitor_id", snapshot.Monitor.ID, "error", err)
		}
	}

	// The outage ended (or changed character): the next down alert starts a new reminder series.
	if result.Status != StatusDown && snapshot.Monitor.LastAlertAt != nil {
		if err := d.store.SetMonitorLastAlert(ctx, snapshot.Monitor.ID, nil); err != nil {
			d.logger.Error("clear last alert failed", "monitor_id", snapshot.Monitor.ID, "error", err)
		}
	}

	transition, hasTransition, settled := d.evaluateTransition(ctx, snapshot, result)

	// Inside a maintenance window nothing is announced. The status from before the window is
	// kept as the catch-up marker (shared with mute), so one summary follows afterwards if the
	// status differs.
	if inMaintenance {
		if hasTransition {
			d.recordSuppressed(ctx, transition, "maintenance")
		}
		if snapshot.Monitor.MuteStartStatus == "" && snapshot.LastResult != nil {
			if err := d.store.SetMonitorMuteStartStatus(ctx, snapshot.Monitor.ID, snapshot.LastResult.Status); err != nil {
				d.logger.Error("set maintenance catch-up marker failed", "monitor_id", snapshot.Monitor.ID, "error", err)
			}
		}
		return true
	}

	// Muted monitors still record results and state changes; only notifications are skipped,
	// but the suppressed transition is logged and a catch-up is sent once the mute is over.
	if snapshot.Monitor.IsMuted(now) {
		if hasTransition {
			d.recordSuppressed(ctx, transition, "muted")
		}
		return true
	}

	if start := snapshot.Monitor.MuteStartStatus; start != "" {
		if !settled {
			// An unconfirmed failure: decide on the catch-up with a later result.
			return true
		}
		if err := d.store.ClearMonitorMuteStartStatus(ctx, snapshot.Monitor.ID); err != nil {
			d.logger.Error("clear mute catch-up marker failed", "monitor_id", snapshot.Monitor.ID, "error", err)
		}
		// The catch-up replaces any regular transition of this very check.
		hasTransition = false
		if result.Status != start && !(result.Status == StatusUp && !snapshot.Monitor.NotifyOnRecovery) {
			transition = Transition{
				Monitor:      snapshot.Monitor,
				Previous:     start,
				Current:      result.Status,
				CheckedAt:    result.CheckedAt,
				ResultDetail: result.Message,
				CatchUp:      true,
			}
			hasTransition = true
		}
	}

	if hasTransition {
		d.dispatchTransition(ctx, transition)
		if transition.Current == StatusDown {
			d.markAlerted(ctx, transition.Monitor.ID, now)
		}
		return true
	}

	if settled {
		d.maybeRemind(ctx, snapshot, result, now)
	}
	return true
}

func (d *Dispatcher) markAlerted(ctx context.Context, monitorID int64, at time.Time) {
	at = at.UTC()
	if err := d.store.SetMonitorLastAlert(ctx, monitorID, &at); err != nil {
		d.logger.Error("record last alert failed", "monitor_id", monitorID, "error", err)
	}
}

// maybeRemind repeats the down alert of an ongoing, already announced outage once the
// monitor's reminder interval has passed since the last announcement. The timestamp is
// persisted before sending, so a restart or a failing channel never causes a reminder burst.
func (d *Dispatcher) maybeRemind(ctx context.Context, snapshot Snapshot, result Result, now time.Time) {
	interval := snapshot.Monitor.RemindInterval()
	last := snapshot.Monitor.LastAlertAt
	if interval <= 0 || last == nil || result.Status != StatusDown {
		return
	}
	if snapshot.LastResult == nil || snapshot.LastResult.Status != StatusDown {
		return
	}
	if now.Before(last.Add(interval)) {
		return
	}

	since := *last
	if start, ok, err := d.store.CurrentOutageStart(ctx, snapshot.Monitor.ID); err != nil {
		d.logger.Warn("load outage start failed", "monitor_id", snapshot.Monitor.ID, "error", err)
	} else if ok && start.Before(since) {
		since = start
	}
	duration := result.CheckedAt.Sub(since)
	if duration < 0 {
		duration = 0
	}

	d.markAlerted(ctx, snapshot.Monitor.ID, now)
	d.dispatchTransition(ctx, Transition{
		Monitor:        snapshot.Monitor,
		Previous:       StatusDown,
		Current:        StatusDown,
		CheckedAt:      result.CheckedAt,
		ResultDetail:   result.Message,
		Reminder:       true,
		OutageDuration: duration,
	})
}

// recordSuppressed logs a transition that was not announced. One event is written per
// transition, attached to the first plain notifier (endpoint ids are required by the schema).
func (d *Dispatcher) recordSuppressed(ctx context.Context, transition Transition, reason string) {
	for _, notifier := range d.notifiers {
		if notifier == nil || !notifier.Enabled() || notifier.EndpointID() <= 0 {
			continue
		}
		if _, isFanout := notifier.(FanoutNotifier); isFanout {
			continue
		}
		if err := d.store.RecordSuppressedNotificationEvent(ctx, transition.Monitor.ID, notifier.EndpointID(), notifier.EventType(), reason); err != nil {
			d.logger.Error("record suppressed notification event failed", "monitor_id", transition.Monitor.ID, "error", err)
		}
		return
	}
}

// dispatchTransition sends a transition to every enabled notifier and queues failed deliveries.
func (d *Dispatcher) dispatchTransition(ctx context.Context, transition Transition) {
	monitorID := transition.Monitor.ID
	for _, notifier := range d.notifiers {
		if notifier == nil || !notifier.Enabled() {
			continue
		}

		if fanout, ok := notifier.(FanoutNotifier); ok {
			d.dispatchFanoutTransition(ctx, monitorID, fanout, transition)
			continue
		}

		notifyCtx, notifyCancel := context.WithTimeout(ctx, 5*time.Second)
		err := notifier.Notify(notifyCtx, transition)
		notifyCancel()

		// No recipients configured – nothing was sent, don't pollute the log.
		if errors.Is(err, ErrNoRecipients) {
			continue
		}

		var deliveredAt *time.Time
		errorMessage := ""
		if err == nil {
			now := time.Now().UTC()
			deliveredAt = &now
		} else {
			errorMessage = err.Error()
		}

		if recordErr := d.store.RecordNotificationEvent(ctx, monitorID, notifier.EndpointID(), notifier.EventType(), deliveredAt, errorMessage); recordErr != nil {
			d.logger.Error("record notification event failed", "monitor_id", monitorID, "endpoint_id", notifier.EndpointID(), "error", recordErr)
		}

		if err != nil {
			d.logger.Error("send transition notification failed", "monitor_id", monitorID, "endpoint_id", notifier.EndpointID(), "error", err)
			d.enqueueRetry(ctx, monitorID, notifier.EndpointID(), notifier.EventType(), transition)
		}
	}
}
