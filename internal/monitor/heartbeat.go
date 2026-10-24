package monitor

import (
	"context"
	"time"
)

// Messages of heartbeat results; the ping handler uses the same texts as the checker.
const (
	HeartbeatMessageReceived = "Heartbeat empfangen"
	HeartbeatMessageNone     = "Noch kein Heartbeat empfangen"
	HeartbeatMessageInWindow = "Heartbeat im erwarteten Zeitfenster"
	HeartbeatMessageFailed   = "Job hat einen Fehler gemeldet"
)

// HeartbeatChecker evaluates push monitors: instead of probing a target it checks whether the
// monitor's last ping (Monitor.LastHeartbeatAt, loaded with the snapshot) is recent enough.
// Interval is the expected ping period and Timeout the grace period on top of it.
type HeartbeatChecker struct {
	now func() time.Time
}

// HeartbeatDeadline is how long after the last ping (or after creation) a monitor may stay
// silent before it counts as down.
func HeartbeatDeadline(item Monitor) time.Duration {
	return item.Interval + item.Timeout
}

func (c HeartbeatChecker) Check(_ context.Context, item Monitor) Result {
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	now = now.UTC()
	result := Result{MonitorID: item.ID, CheckedAt: now}
	deadline := HeartbeatDeadline(item)

	if item.LastHeartbeatAt == nil {
		// Never pinged: the job gets one full period plus grace after the last edit (a monitor
		// switched to this kind or resumed from a pause starts a fresh window).
		since := item.UpdatedAt
		if since.Before(item.CreatedAt) {
			since = item.CreatedAt
		}
		result.Message = HeartbeatMessageNone
		result.Status = StatusDown
		if now.Sub(since) <= deadline {
			result.Status = StatusUnknown
		}
		return result
	}

	silence := max(now.Sub(*item.LastHeartbeatAt), 0)
	switch {
	case silence > deadline:
		result.Status = StatusDown
		result.Message = "Kein Heartbeat seit " + FormatOutageDuration(silence)
	case item.LastHeartbeatFailed:
		result.Status = StatusDown
		result.Message = HeartbeatMessageFailed
	default:
		result.Status = StatusUp
		result.Message = HeartbeatMessageInWindow
	}
	return result
}
