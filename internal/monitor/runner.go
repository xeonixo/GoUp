package monitor

import (
	"context"
	"errors"
	"log/slog"
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
}

type Checker interface {
	Check(ctx context.Context, item Monitor) Result
}

type Runner struct {
	logger    *slog.Logger
	store     Store
	notifiers []Notifier
	checkers  map[Kind]Checker
	interval  time.Duration
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
		logger:    logger,
		store:     store,
		notifiers: notifiers,
		interval:  5 * time.Second,
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
	for _, snapshot := range snapshots {
		if !snapshot.IsDue(now) {
			continue
		}

		checker, ok := r.checkers[snapshot.Monitor.Kind]
		if !ok {
			r.logger.Warn("no checker registered for monitor kind", "monitor_id", snapshot.Monitor.ID, "kind", snapshot.Monitor.Kind)
			continue
		}

		runCtx, cancel := context.WithTimeout(ctx, snapshot.Monitor.Timeout+2*time.Second)
		result := checker.Check(runCtx, snapshot.Monitor)
		cancel()

		if err := r.store.SaveMonitorResult(ctx, result); err != nil {
			r.logger.Error("save monitor result failed", "monitor_id", snapshot.Monitor.ID, "error", err)
			continue
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
