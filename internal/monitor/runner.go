package monitor

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"
)

// ErrNoRecipients is returned by a Notifier when no recipients are configured.
// The runner treats this as "nothing to do" and skips recording a notification event.
var ErrNoRecipients = errors.New("no notification recipients configured")

type Store interface {
	ListMonitorSnapshots(ctx context.Context) ([]Snapshot, error)
	SaveMonitorResult(ctx context.Context, result Result) error
	RecordMonitorState(ctx context.Context, monitorID int64, status Status, message string, checkedAt time.Time) error
	RecordNotificationEvent(ctx context.Context, monitorID int64, endpointID int64, eventType string, deliveredAt *time.Time, errorMessage string) error
	EnqueueNotificationRetry(ctx context.Context, params NotificationRetryParams) error
	ListDueNotificationRetries(ctx context.Context, now time.Time, limit int) ([]NotificationRetry, error)
	UpdateNotificationRetry(ctx context.Context, id int64, succeeded bool, errorMessage string, nextAttemptAt time.Time, abandoned bool) error
}

type Checker interface {
	Check(ctx context.Context, item Monitor) Result
}

type Runner struct {
	logger              *slog.Logger
	store               Store
	notifiers           []Notifier
	checkers            map[Kind]Checker
	interval            time.Duration
	workers             int
	workerSem           chan struct{}
	scheduleMu          sync.Mutex
	schedule            map[int64]*monitorScheduleState
	notifyMaxRetries    int
	notifyRetryInterval time.Duration
}

type monitorScheduleState struct {
	interval time.Duration
	nextDue  time.Time
	inFlight bool
}

type Transition struct {
	Monitor      Monitor
	Previous     Status
	Current      Status
	CheckedAt    time.Time
	ResultDetail string
}

type Notifier interface {
	Enabled() bool
	EndpointID() int64
	EventType() string
	Notify(ctx context.Context, transition Transition) error
}

type FanoutDeliveryResult struct {
	EndpointID int64
	Error      error
}

type FanoutNotifier interface {
	Enabled() bool
	EventType() string
	NotifyAll(ctx context.Context, transition Transition) ([]FanoutDeliveryResult, error)
	NotifyEndpoint(ctx context.Context, endpointID int64, transition Transition) error
}

func NewRunner(logger *slog.Logger, store Store, notifiers ...Notifier) *Runner {
	r := &Runner{
		logger:              logger,
		store:               store,
		notifiers:           notifiers,
		interval:            5 * time.Second,
		workers:             4,
		schedule:            make(map[int64]*monitorScheduleState),
		notifyMaxRetries:    3,
		notifyRetryInterval: 5 * time.Minute,
		checkers: map[Kind]Checker{
			KindHTTPS: HTTPSChecker{},
			KindTCP:   TCPChecker{},
			KindICMP:  ICMPChecker{},
			KindSMTP:  SMTPChecker{},
			KindIMAP:  IMAPChecker{},
			KindDNS:   DNSChecker{},
			KindUDP:   UDPChecker{},
			KindWhois: WhoisChecker{},
		},
	}
	r.workerSem = make(chan struct{}, r.workers)
	return r
}

func (r *Runner) SetWorkers(workers int) {
	if workers <= 0 {
		workers = 1
	}
	r.scheduleMu.Lock()
	defer r.scheduleMu.Unlock()
	r.workers = workers
	r.workerSem = make(chan struct{}, workers)
}

func (r *Runner) Run(ctx context.Context) {
	go r.runRetries(ctx)

	r.runDueChecks(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runDueChecks(ctx)
		}
	}
}

func (r *Runner) runDueChecks(ctx context.Context) {
	snapshots, err := r.store.ListMonitorSnapshots(ctx)
	if err != nil {
		r.logger.Error("load monitor snapshots failed", "error", err)
		return
	}

	now := time.Now().UTC()
	dueSnapshots := r.dueSnapshots(snapshots, now)
	if len(dueSnapshots) == 0 {
		return
	}

	for _, due := range dueSnapshots {
		r.dispatchSnapshot(ctx, due)
	}
}

type dueSnapshot struct {
	snapshot Snapshot
	dueAt    time.Time
	lag      time.Duration
}

func (r *Runner) dueSnapshots(snapshots []Snapshot, now time.Time) []dueSnapshot {
	r.scheduleMu.Lock()
	defer r.scheduleMu.Unlock()

	seen := make(map[int64]struct{}, len(snapshots))
	due := make([]dueSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		monitorID := snapshot.Monitor.ID
		seen[monitorID] = struct{}{}

		if !snapshot.Monitor.Enabled || snapshot.Monitor.ExecutorKind == "remote" {
			delete(r.schedule, monitorID)
			continue
		}

		interval := normalizedMonitorInterval(snapshot.Monitor.Interval)
		state := r.schedule[monitorID]
		if state == nil {
			state = &monitorScheduleState{
				interval: interval,
				nextDue:  CascadedDueAtOrAfter(monitorID, interval, now),
			}
			r.schedule[monitorID] = state
		} else if state.interval != interval {
			state.interval = interval
			if !state.inFlight {
				state.nextDue = CascadedDueAtOrAfter(monitorID, interval, now)
			}
		}

		if state.inFlight {
			if !state.nextDue.After(now) {
				nextDue, skipped := skipRunningSlots(state.nextDue, interval, now)
				r.logger.Warn("monitor check slot skipped: previous check still running",
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

		dueAt := state.nextDue
		if now.Sub(dueAt) >= interval {
			var skipped int
			dueAt, skipped = skipMissedSlots(dueAt, interval, now)
			state.nextDue = dueAt
			r.logger.Warn("monitor check slots skipped: scheduler lag",
				"monitor_id", monitorID,
				"scheduled_at", dueAt.Format(time.RFC3339),
				"skipped_slots", skipped,
				"lag_ms", now.Sub(dueAt).Milliseconds(),
			)
		}

		due = append(due, dueSnapshot{
			snapshot: snapshot,
			dueAt:    dueAt,
			lag:      now.Sub(dueAt),
		})
	}

	for monitorID := range r.schedule {
		if _, ok := seen[monitorID]; !ok {
			delete(r.schedule, monitorID)
		}
	}

	return due
}

func (r *Runner) dispatchSnapshot(ctx context.Context, due dueSnapshot) {
	r.scheduleMu.Lock()
	state := r.schedule[due.snapshot.Monitor.ID]
	if state == nil || state.inFlight {
		r.scheduleMu.Unlock()
		return
	}
	select {
	case r.workerSem <- struct{}{}:
	default:
		r.scheduleMu.Unlock()
		r.logger.Warn("monitor check delayed: worker capacity exhausted",
			"monitor_id", due.snapshot.Monitor.ID,
			"scheduled_at", due.dueAt.Format(time.RFC3339),
			"lag_ms", due.lag.Milliseconds(),
			"workers", r.workers,
		)
		return
	}
	state.inFlight = true
	state.nextDue = due.dueAt.Add(normalizedMonitorInterval(due.snapshot.Monitor.Interval))
	r.scheduleMu.Unlock()

	go func() {
		defer func() {
			<-r.workerSem
			r.scheduleMu.Lock()
			if state := r.schedule[due.snapshot.Monitor.ID]; state != nil {
				state.inFlight = false
			}
			r.scheduleMu.Unlock()
		}()
		r.runSnapshot(ctx, due.snapshot, due.dueAt)
	}()
}

func (r *Runner) runSnapshot(ctx context.Context, snapshot Snapshot, scheduledAt time.Time) {
	checker, ok := r.checkers[snapshot.Monitor.Kind]
	if !ok {
		r.logger.Warn("no checker registered for monitor kind", "monitor_id", snapshot.Monitor.ID, "kind", snapshot.Monitor.Kind)
		return
	}

	runCtx, cancel := context.WithTimeout(ctx, snapshot.Monitor.Timeout+2*time.Second)
	result := checker.Check(runCtx, snapshot.Monitor)
	cancel()
	result.CheckedAt = scheduledAt.UTC()

	if result.Status != StatusUp && snapshot.Monitor.RetryCount > 0 {
		for attempt := 0; attempt < snapshot.Monitor.RetryCount; attempt++ {
			if snapshot.Monitor.RetryInterval > 0 {
				select {
				case <-time.After(snapshot.Monitor.RetryInterval):
				case <-ctx.Done():
					goto doneRetrying
				}
			}
			retryCtx, retryCancel := context.WithTimeout(ctx, snapshot.Monitor.Timeout+2*time.Second)
			retryResult := checker.Check(retryCtx, snapshot.Monitor)
			retryCancel()
			result = retryResult
			result.CheckedAt = scheduledAt.UTC()
			if result.Status == StatusUp {
				break
			}
		}
	}
doneRetrying:

	if err := r.store.SaveMonitorResult(ctx, result); err != nil {
		r.logger.Error("save monitor result failed", "monitor_id", snapshot.Monitor.ID, "error", err)
		return
	}

	if err := r.store.RecordMonitorState(ctx, snapshot.Monitor.ID, result.Status, result.Message, result.CheckedAt); err != nil {
		r.logger.Error("record monitor state failed", "monitor_id", snapshot.Monitor.ID, "error", err)
	}

	if transition, ok := buildTransition(snapshot, result); ok {
		for _, notifier := range r.notifiers {
			if notifier == nil || !notifier.Enabled() {
				continue
			}

			if fanout, ok := notifier.(FanoutNotifier); ok {
				r.dispatchFanoutTransition(ctx, snapshot.Monitor.ID, fanout, transition)
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

			if recordErr := r.store.RecordNotificationEvent(ctx, snapshot.Monitor.ID, notifier.EndpointID(), notifier.EventType(), deliveredAt, errorMessage); recordErr != nil {
				r.logger.Error("record notification event failed", "monitor_id", snapshot.Monitor.ID, "endpoint_id", notifier.EndpointID(), "error", recordErr)
			}

			if err != nil {
				r.logger.Error("send transition notification failed", "monitor_id", snapshot.Monitor.ID, "endpoint_id", notifier.EndpointID(), "error", err)
				if r.notifyMaxRetries > 0 {
					retryParams := NotificationRetryParams{
						MonitorID:     snapshot.Monitor.ID,
						EndpointID:    notifier.EndpointID(),
						EventType:     notifier.EventType(),
						Transition:    transition,
						MaxAttempts:   r.notifyMaxRetries,
						NextAttemptAt: time.Now().UTC().Add(r.notifyRetryInterval),
					}
					if enqErr := r.store.EnqueueNotificationRetry(ctx, retryParams); enqErr != nil {
						r.logger.Error("enqueue notification retry failed", "monitor_id", snapshot.Monitor.ID, "endpoint_id", notifier.EndpointID(), "error", enqErr)
					}
				}
			}
		}
	}

	r.logger.Info("monitor check completed",
		"monitor_id", snapshot.Monitor.ID,
		"name", snapshot.Monitor.Name,
		"kind", snapshot.Monitor.Kind,
		"status", result.Status,
		"latency_ms", result.Latency.Milliseconds(),
		"scheduled_at", scheduledAt.UTC().Format(time.RFC3339),
	)
}

func normalizedMonitorInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return time.Minute
	}
	return interval
}

func CascadedDueAtOrAfter(monitorID int64, interval time.Duration, now time.Time) time.Time {
	interval = normalizedMonitorInterval(interval)
	phase := MonitorPhaseOffset(monitorID, interval)
	base := now.Truncate(interval).Add(phase)
	if base.Before(now) {
		base = base.Add(interval)
	}
	return base.UTC()
}

func MonitorPhaseOffset(monitorID int64, interval time.Duration) time.Duration {
	interval = normalizedMonitorInterval(interval)
	seconds := int64(interval / time.Second)
	if seconds <= 1 {
		return 0
	}
	h := fnv.New64a()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(monitorID))
	_, _ = h.Write(buf[:])
	offsetSeconds := int64(h.Sum64() % uint64(seconds))
	return time.Duration(offsetSeconds) * time.Second
}

func skipMissedSlots(dueAt time.Time, interval time.Duration, now time.Time) (time.Time, int) {
	interval = normalizedMonitorInterval(interval)
	if dueAt.After(now) {
		return dueAt, 0
	}
	missed := int(now.Sub(dueAt) / interval)
	nextDue := dueAt.Add(time.Duration(missed) * interval)
	return nextDue.UTC(), missed
}

func skipRunningSlots(dueAt time.Time, interval time.Duration, now time.Time) (time.Time, int) {
	interval = normalizedMonitorInterval(interval)
	if dueAt.After(now) {
		return dueAt, 0
	}
	skipped := int(now.Sub(dueAt)/interval) + 1
	nextDue := dueAt.Add(time.Duration(skipped) * interval)
	return nextDue.UTC(), skipped
}

func (r *Runner) dispatchFanoutTransition(ctx context.Context, monitorID int64, notifier FanoutNotifier, transition Transition) {
	notifyCtx, notifyCancel := context.WithTimeout(ctx, 5*time.Second)
	results, err := notifier.NotifyAll(notifyCtx, transition)
	notifyCancel()
	if errors.Is(err, ErrNoRecipients) {
		return
	}
	if err != nil {
		r.logger.Error("send fanout notification failed", "monitor_id", monitorID, "event_type", notifier.EventType(), "error", err)
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

		if recordErr := r.store.RecordNotificationEvent(ctx, monitorID, result.EndpointID, notifier.EventType(), deliveredAt, errorMessage); recordErr != nil {
			r.logger.Error("record notification event failed", "monitor_id", monitorID, "endpoint_id", result.EndpointID, "error", recordErr)
		}
		if result.Error != nil && r.notifyMaxRetries > 0 {
			retryParams := NotificationRetryParams{
				MonitorID:     monitorID,
				EndpointID:    result.EndpointID,
				EventType:     notifier.EventType(),
				Transition:    transition,
				MaxAttempts:   r.notifyMaxRetries,
				NextAttemptAt: time.Now().UTC().Add(r.notifyRetryInterval),
			}
			if enqErr := r.store.EnqueueNotificationRetry(ctx, retryParams); enqErr != nil {
				r.logger.Error("enqueue notification retry failed", "monitor_id", monitorID, "endpoint_id", result.EndpointID, "error", enqErr)
			}
		}
	}
}

func (r *Runner) runRetries(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.dispatchDueRetries(ctx)
		}
	}
}

func (r *Runner) dispatchDueRetries(ctx context.Context) {
	due, err := r.store.ListDueNotificationRetries(ctx, time.Now().UTC(), 50)
	if err != nil {
		r.logger.Error("list due notification retries failed", "error", err)
		return
	}
	for _, retry := range due {
		r.dispatchRetry(ctx, retry)
	}
}

func (r *Runner) dispatchRetry(ctx context.Context, retry NotificationRetry) {
	var notifier Notifier
	var fanout FanoutNotifier
	for _, n := range r.notifiers {
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
		if err := r.store.UpdateNotificationRetry(ctx, retry.ID, false, "notifier not found", time.Time{}, true); err != nil {
			r.logger.Error("abandon notification retry failed", "retry_id", retry.ID, "error", err)
		}
		r.logger.Warn("notification retry abandoned: notifier not found", "retry_id", retry.ID, "endpoint_id", retry.EndpointID)
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
		if updateErr := r.store.UpdateNotificationRetry(ctx, retry.ID, true, "", time.Time{}, false); updateErr != nil {
			r.logger.Error("update notification retry failed", "retry_id", retry.ID, "error", updateErr)
		}
		return
	}

	succeeded := err == nil
	abandoned := !succeeded && (retry.AttemptCount+1) >= retry.MaxAttempts
	nextAttemptAt := time.Now().UTC().Add(r.notifyRetryInterval)

	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	if updateErr := r.store.UpdateNotificationRetry(ctx, retry.ID, succeeded, errMsg, nextAttemptAt, abandoned); updateErr != nil {
		r.logger.Error("update notification retry failed", "retry_id", retry.ID, "error", updateErr)
	}

	if succeeded {
		now := time.Now().UTC()
		if recErr := r.store.RecordNotificationEvent(ctx, retry.Transition.Monitor.ID, retry.EndpointID, retry.EventType, &now, ""); recErr != nil {
			r.logger.Error("record retry success event failed", "retry_id", retry.ID, "error", recErr)
		}
		r.logger.Info("notification retry succeeded", "retry_id", retry.ID, "endpoint_id", retry.EndpointID, "attempt", retry.AttemptCount+1)
	} else if abandoned {
		r.logger.Warn("notification retry abandoned after max attempts", "retry_id", retry.ID, "endpoint_id", retry.EndpointID, "attempts", retry.AttemptCount+1)
	} else {
		r.logger.Warn("notification retry failed, will retry", "retry_id", retry.ID, "endpoint_id", retry.EndpointID, "attempt", retry.AttemptCount+1, "error", err)
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
