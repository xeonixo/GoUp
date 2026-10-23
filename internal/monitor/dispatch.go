package monitor

import (
	"context"
	"database/sql"
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

// SetMaintenanceChecker overrides the maintenance source (the store is used by default).
func (d *Dispatcher) SetMaintenanceChecker(checker MaintenanceChecker) { d.maintenance = checker }

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

func (d *Dispatcher) enqueueRetry(ctx context.Context, monitorID, endpointID int64, eventType string, transition Transition) {
	if d.notifyMaxRetries <= 0 {
		return
	}
	retryParams := NotificationRetryParams{
		MonitorID:     monitorID,
		EndpointID:    endpointID,
		EventType:     eventType,
		Transition:    transition,
		MaxAttempts:   d.notifyMaxRetries,
		NextAttemptAt: time.Now().UTC().Add(d.notifyRetryInterval),
	}
	if enqErr := d.store.EnqueueNotificationRetry(ctx, retryParams); enqErr != nil {
		d.logger.Error("enqueue notification retry failed", "monitor_id", monitorID, "endpoint_id", endpointID, "error", enqErr)
	}
}

func (d *Dispatcher) dispatchFanoutTransition(ctx context.Context, monitorID int64, notifier FanoutNotifier, transition Transition) {
	notifyCtx, notifyCancel := context.WithTimeout(ctx, 5*time.Second)
	results, err := notifier.NotifyAll(notifyCtx, transition)
	notifyCancel()
	if errors.Is(err, ErrNoRecipients) {
		return
	}
	if err != nil {
		d.logger.Error("send fanout notification failed", "monitor_id", monitorID, "event_type", notifier.EventType(), "error", err)
		return
	}
	for _, result := range results {
		if result.EndpointID <= 0 {
			continue
		}
		var deliveredAt *time.Time
		errorMessage := ""
		if result.Error == nil {
			now := time.Now().UTC()
			deliveredAt = &now
		} else {
			errorMessage = result.Error.Error()
		}

		if recordErr := d.store.RecordNotificationEvent(ctx, monitorID, result.EndpointID, notifier.EventType(), deliveredAt, errorMessage); recordErr != nil {
			d.logger.Error("record notification event failed", "monitor_id", monitorID, "endpoint_id", result.EndpointID, "error", recordErr)
		}
		if result.Error != nil {
			d.enqueueRetry(ctx, monitorID, result.EndpointID, notifier.EventType(), transition)
		}
	}
}

// RunRetries periodically resends queued notifications until ctx ends.
func (d *Dispatcher) RunRetries(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.dispatchDueRetries(ctx)
		}
	}
}

func (d *Dispatcher) dispatchDueRetries(ctx context.Context) {
	due, err := d.store.ListDueNotificationRetries(ctx, time.Now().UTC(), 50)
	if err != nil {
		d.logger.Error("list due notification retries failed", "error", err)
		return
	}
	for _, retry := range due {
		d.dispatchRetry(ctx, retry)
	}
}

// retrySuperseded reports whether the monitor's current status no longer matches the status the
// queued notification announces, so resending it would be misleading.
func (d *Dispatcher) retrySuperseded(ctx context.Context, retry NotificationRetry) (bool, string) {
	snapshot, err := d.store.GetMonitorSnapshot(ctx, retry.Transition.Monitor.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, "monitor no longer exists"
		}
		d.logger.Warn("load monitor for notification retry failed", "retry_id", retry.ID, "error", err)
		return false, ""
	}
	if snapshot.LastResult != nil && snapshot.LastResult.Status != retry.Transition.Current {
		return true, "superseded: monitor is now " + string(snapshot.LastResult.Status)
	}
	if retry.Transition.Reminder {
		now := d.now()
		if snapshot.Monitor.IsMuted(now) {
			return true, "superseded: monitor is muted"
		}
		if snapshot.Monitor.RemindEveryMinutes <= 0 {
			return true, "superseded: reminders are off"
		}
		if d.inMaintenance(ctx, snapshot.Monitor, now) {
			return true, "superseded: monitor is in maintenance"
		}
	}
	return false, ""
}

func (d *Dispatcher) dispatchRetry(ctx context.Context, retry NotificationRetry) {
	var notifier Notifier
	var fanout FanoutNotifier
	for _, n := range d.notifiers {
		if n == nil || !n.Enabled() || n.EventType() != retry.EventType {
			continue
		}
		if candidate, ok := n.(FanoutNotifier); ok {
			fanout = candidate
			break
		}
		if n.EndpointID() == retry.EndpointID {
			notifier = n
			break
		}
	}
	if notifier == nil && fanout == nil {
		if err := d.store.UpdateNotificationRetry(ctx, retry.ID, false, "notifier not found", time.Time{}, true); err != nil {
			d.logger.Error("abandon notification retry failed", "retry_id", retry.ID, "error", err)
		}
		d.logger.Warn("notification retry abandoned: notifier not found", "retry_id", retry.ID, "endpoint_id", retry.EndpointID)
		return
	}

	if stale, reason := d.retrySuperseded(ctx, retry); stale {
		if err := d.store.SupersedeNotificationRetry(ctx, retry.ID, reason); err != nil {
			d.logger.Error("supersede notification retry failed", "retry_id", retry.ID, "error", err)
		}
		d.logger.Info("notification retry dropped: "+reason, "retry_id", retry.ID, "monitor_id", retry.Transition.Monitor.ID)
		return
	}

	notifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	var err error
	if fanout != nil {
		err = fanout.NotifyEndpoint(notifyCtx, retry.EndpointID, retry.Transition)
	} else {
		err = notifier.Notify(notifyCtx, retry.Transition)
	}
	cancel()

	if errors.Is(err, ErrNoRecipients) {
		// No recipients configured — treat as success, no point retrying.
		if updateErr := d.store.UpdateNotificationRetry(ctx, retry.ID, true, "", time.Time{}, false); updateErr != nil {
			d.logger.Error("update notification retry failed", "retry_id", retry.ID, "error", updateErr)
		}
		return
	}

	succeeded := err == nil
	abandoned := !succeeded && (retry.AttemptCount+1) >= retry.MaxAttempts
	nextAttemptAt := time.Now().UTC().Add(d.notifyRetryInterval)

	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	if updateErr := d.store.UpdateNotificationRetry(ctx, retry.ID, succeeded, errMsg, nextAttemptAt, abandoned); updateErr != nil {
		d.logger.Error("update notification retry failed", "retry_id", retry.ID, "error", updateErr)
	}

	if succeeded {
		now := time.Now().UTC()
		if recErr := d.store.RecordNotificationEvent(ctx, retry.Transition.Monitor.ID, retry.EndpointID, retry.EventType, &now, ""); recErr != nil {
			d.logger.Error("record retry success event failed", "retry_id", retry.ID, "error", recErr)
		}
		d.logger.Info("notification retry succeeded", "retry_id", retry.ID, "endpoint_id", retry.EndpointID, "attempt", retry.AttemptCount+1)
	} else if abandoned {
		d.logger.Warn("notification retry abandoned after max attempts", "retry_id", retry.ID, "endpoint_id", retry.EndpointID, "attempts", retry.AttemptCount+1)
	} else {
		d.logger.Warn("notification retry failed, will retry", "retry_id", retry.ID, "endpoint_id", retry.EndpointID, "attempt", retry.AttemptCount+1, "error", err)
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
