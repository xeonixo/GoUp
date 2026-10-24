package monitor

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"
)

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
			KindHTTPS:     HTTPSChecker{},
			KindTCP:       TCPChecker{},
			KindICMP:      ICMPChecker{},
			KindSMTP:      SMTPChecker{},
			KindIMAP:      IMAPChecker{},
			KindDNS:       DNSChecker{},
			KindUDP:       UDPChecker{},
			KindWhois:     WhoisChecker{},
			KindHeartbeat: HeartbeatChecker{},
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

		interval := normalizedMonitorInterval(snapshot.Monitor.ScheduleInterval())
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
	state.nextDue = due.dueAt.Add(normalizedMonitorInterval(due.snapshot.Monitor.ScheduleInterval()))
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
