package monitor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
	// SupersedeNotificationRetry closes a retry whose transition is no longer the monitor's current state.
	SupersedeNotificationRetry(ctx context.Context, id int64, reason string) error
	// RecordSuppressedNotificationEvent logs a transition that was intentionally not announced (muted).
	RecordSuppressedNotificationEvent(ctx context.Context, monitorID int64, endpointID int64, eventType string, reason string) error
	// GetMonitorSnapshot loads one monitor with its latest result; sql.ErrNoRows when it was deleted.
	GetMonitorSnapshot(ctx context.Context, monitorID int64) (Snapshot, error)
	// RecentMonitorStatuses returns the latest result statuses, newest first.
	RecentMonitorStatuses(ctx context.Context, monitorID int64, limit int) ([]Status, error)
	// ClearMonitorMuteStartStatus drops the pending mute catch-up marker.
	ClearMonitorMuteStartStatus(ctx context.Context, monitorID int64) error
	// SetMonitorMuteStartStatus stores the catch-up marker (status before notifications were
	// suppressed). Mutes and maintenance windows share it.
	SetMonitorMuteStartStatus(ctx context.Context, monitorID int64, status Status) error
	// SetMonitorLastAlert records when the current outage was last announced; nil clears it.
	SetMonitorLastAlert(ctx context.Context, monitorID int64, at *time.Time) error
	// CurrentOutageStart returns when the ongoing run of down results began.
	CurrentOutageStart(ctx context.Context, monitorID int64) (time.Time, bool, error)
}

// MaintenanceChecker tells whether a monitor is inside a maintenance window. The sqlite store
// implements it; the dispatcher uses it when the store does.
type MaintenanceChecker interface {
	ActiveMaintenance(ctx context.Context, monitorID int64, group string, now time.Time) bool
}

type Checker interface {
	Check(ctx context.Context, item Monitor) Result
}

type Runner struct {
	*Dispatcher
	logger            *slog.Logger
	store             Store
	checkers          map[Kind]Checker
	interval          time.Duration
	checkTimeoutGrace time.Duration
	workers           int
	workerSem         chan struct{}
	scheduleMu        sync.Mutex
	schedule          map[int64]*monitorScheduleState
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
	// CatchUp marks the single summary sent after a mute ended; Previous is the status at mute start.
	CatchUp bool
	// Reminder marks a repeated alert for an ongoing outage (Previous == Current == down);
	// OutageDuration is how long the monitor has been down.
	Reminder       bool
	OutageDuration time.Duration
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
		Dispatcher:        NewDispatcher(logger, store, notifiers...),
		logger:            logger,
		store:             store,
		interval:          5 * time.Second,
		checkTimeoutGrace: 2 * time.Second,
		workers:           4,
		schedule:          make(map[int64]*monitorScheduleState),
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
	go r.RunRetries(ctx)

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

	runCtx, cancel := context.WithTimeout(ctx, r.checkTimeout(snapshot.Monitor))
	result := r.runChecker(runCtx, checker, snapshot.Monitor)
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
			retryCtx, retryCancel := context.WithTimeout(ctx, r.checkTimeout(snapshot.Monitor))
			retryResult := r.runChecker(retryCtx, checker, snapshot.Monitor)
			retryCancel()
			result = retryResult
			result.CheckedAt = scheduledAt.UTC()
			if result.Status == StatusUp {
				break
			}
		}
	}
doneRetrying:

	if !r.ProcessResult(ctx, snapshot, result) {
		return
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

func (r *Runner) checkTimeout(item Monitor) time.Duration {
	timeout := item.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	return timeout + r.checkTimeoutGrace
}

func (r *Runner) runChecker(ctx context.Context, checker Checker, item Monitor) Result {
	startedAt := time.Now()
	resultCh := make(chan Result, 1)

	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				resultCh <- Result{
					MonitorID: item.ID,
					CheckedAt: time.Now().UTC(),
					Status:    StatusDown,
					Latency:   time.Since(startedAt),
					Message:   "monitor check failed unexpectedly",
				}
				r.logger.Error("monitor checker panicked", "monitor_id", item.ID, "kind", item.Kind, "panic", recovered)
			}
		}()
		resultCh <- checker.Check(ctx, item)
	}()

	select {
	case result := <-resultCh:
		return result
	case <-ctx.Done():
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Latency:   time.Since(startedAt),
			Message:   fmt.Sprintf("monitor check timed out after %s", formatLatency(r.checkTimeout(item))),
		}
	}
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
