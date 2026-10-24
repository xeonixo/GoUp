package monitor

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

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
