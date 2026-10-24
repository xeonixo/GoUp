package monitor

import (
	"context"
	"errors"
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
