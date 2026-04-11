package monitor

import (
	"context"
	"errors"
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
	notifyMaxRetries    int
	notifyRetryInterval time.Duration
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

func NewRunner(logger *slog.Logger, store Store, notifiers ...Notifier) *Runner {
	return &Runner{
		logger:              logger,
		store:               store,
		notifiers:           notifiers,
		interval:            5 * time.Second,
		workers:             4,
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

	now := time.Now()
	dueSnapshots := make([]Snapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if !snapshot.IsDue(now) {
			continue
		}
		dueSnapshots = append(dueSnapshots, snapshot)
	}
	if len(dueSnapshots) == 0 {
		return
	}

	workers := r.workers
	if workers <= 0 {
		workers = 1
	}
	if workers > len(dueSnapshots) {
		workers = len(dueSnapshots)
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, snapshot := range dueSnapshots {
		snapshot := snapshot
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			r.runSnapshot(ctx, snapshot)
		}()
	}
	wg.Wait()
}

func (r *Runner) runSnapshot(ctx context.Context, snapshot Snapshot) {
	checker, ok := r.checkers[snapshot.Monitor.Kind]
	if !ok {
		r.logger.Warn("no checker registered for monitor kind", "monitor_id", snapshot.Monitor.ID, "kind", snapshot.Monitor.Kind)
		return
	}

	runCtx, cancel := context.WithTimeout(ctx, snapshot.Monitor.Timeout+2*time.Second)
	result := checker.Check(runCtx, snapshot.Monitor)
	cancel()

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
	)
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
	for _, n := range r.notifiers {
		if n != nil && n.Enabled() && n.EndpointID() == retry.EndpointID && n.EventType() == retry.EventType {
			notifier = n
			break
		}
	}
	if notifier == nil {
		if err := r.store.UpdateNotificationRetry(ctx, retry.ID, false, "notifier not found", time.Time{}, true); err != nil {
			r.logger.Error("abandon notification retry failed", "retry_id", retry.ID, "error", err)
		}
		r.logger.Warn("notification retry abandoned: notifier not found", "retry_id", retry.ID, "endpoint_id", retry.EndpointID)
		return
	}

	notifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err := notifier.Notify(notifyCtx, retry.Transition)
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
