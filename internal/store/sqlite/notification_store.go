package sqlite

import (
	"context"
	"fmt"
	"goup/internal/monitor"
	"strings"
	"time"
)

func (s *Store) EnqueueNotificationRetry(ctx context.Context, p monitor.NotificationRetryParams) error {
	if p.MonitorID <= 0 || p.EndpointID <= 0 || p.EventType == "" {
		return fmt.Errorf("invalid notification retry params")
	}
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = 3
	}
	t := p.Transition
	now := time.Now().UTC()
	if t.Reminder {
		// At most one pending reminder per monitor and channel: an older one is obsolete.
		if _, err := s.db.ExecContext(ctx, `
UPDATE notification_retries
SET status = 'superseded', error_message = 'superseded: newer reminder', updated_at = ?
WHERE monitor_id = ? AND endpoint_id = ? AND reminder = 1 AND status = 'pending'
`, now, p.MonitorID, p.EndpointID); err != nil && !isMalformedSQLiteError(err) {
			return fmt.Errorf("supersede older reminder retries: %w", err)
		}
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO notification_retries (
    monitor_id, endpoint_id, event_type,
    monitor_name, monitor_kind, monitor_target, monitor_group,
    previous_status, current_status, checked_at, result_detail,
    attempt_count, max_attempts, next_attempt_at,
    status, error_message, created_at, updated_at, reminder, outage_seconds
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 'pending', '', ?, ?, ?, ?)
`,
		p.MonitorID, p.EndpointID, strings.TrimSpace(p.EventType),
		t.Monitor.Name, string(t.Monitor.Kind), t.Monitor.Target, t.Monitor.Group,
		string(t.Previous), string(t.Current), t.CheckedAt.UTC(), t.ResultDetail,
		p.MaxAttempts, p.NextAttemptAt.UTC(),
		now, now, boolToInt(t.Reminder), int64(t.OutageDuration.Seconds()),
	)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("enqueue notification retry: %w", err)
	}
	return nil
}

func (s *Store) ListDueNotificationRetries(ctx context.Context, now time.Time, limit int) ([]monitor.NotificationRetry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, monitor_id, endpoint_id, event_type,
       monitor_name, monitor_kind, monitor_target, monitor_group,
       previous_status, current_status, checked_at, result_detail,
       attempt_count, max_attempts, next_attempt_at, reminder, outage_seconds
FROM notification_retries
WHERE status = 'pending' AND next_attempt_at <= ?
ORDER BY next_attempt_at ASC
LIMIT ?
`, now.UTC(), limit)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return []monitor.NotificationRetry{}, nil
		}
		return nil, fmt.Errorf("list due notification retries: %w", err)
	}
	defer rows.Close()

	items := make([]monitor.NotificationRetry, 0)
	for rows.Next() {
		var (
			id             int64
			monitorID      int64
			endpointID     int64
			eventType      string
			monitorName    string
			monitorKind    string
			monitorTarget  string
			monitorGroup   string
			previousStatus string
			currentStatus  string
			checkedAt      time.Time
			resultDetail   string
			attemptCount   int
			maxAttempts    int
			nextAttemptAt  time.Time
			reminder       int
			outageSeconds  int64
		)
		if err := rows.Scan(
			&id, &monitorID, &endpointID, &eventType,
			&monitorName, &monitorKind, &monitorTarget, &monitorGroup,
			&previousStatus, &currentStatus, &checkedAt, &resultDetail,
			&attemptCount, &maxAttempts, &nextAttemptAt, &reminder, &outageSeconds,
		); err != nil {
			if isMalformedSQLiteError(err) {
				return []monitor.NotificationRetry{}, nil
			}
			return nil, fmt.Errorf("scan notification retry: %w", err)
		}
		items = append(items, monitor.NotificationRetry{
			ID:         id,
			EndpointID: endpointID,
			EventType:  eventType,
			Transition: monitor.Transition{
				Monitor: monitor.Monitor{
					ID:     monitorID,
					Name:   monitorName,
					Kind:   monitor.Kind(monitorKind),
					Target: monitorTarget,
					Group:  monitorGroup,
				},
				Previous:       monitor.Status(previousStatus),
				Current:        monitor.Status(currentStatus),
				CheckedAt:      checkedAt,
				ResultDetail:   resultDetail,
				Reminder:       reminder == 1,
				OutageDuration: time.Duration(outageSeconds) * time.Second,
			},
			AttemptCount:  attemptCount,
			MaxAttempts:   maxAttempts,
			NextAttemptAt: nextAttemptAt,
		})
	}
	if err := rows.Err(); err != nil {
		if isMalformedSQLiteError(err) {
			return []monitor.NotificationRetry{}, nil
		}
		return nil, fmt.Errorf("iterate notification retries: %w", err)
	}
	return items, nil
}

func (s *Store) UpdateNotificationRetry(ctx context.Context, id int64, succeeded bool, errorMessage string, nextAttemptAt time.Time, abandoned bool) error {
	now := time.Now().UTC()
	status := "pending"
	if succeeded {
		status = "succeeded"
	} else if abandoned {
		status = "abandoned"
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE notification_retries
SET attempt_count   = attempt_count + 1,
    status          = ?,
    error_message   = ?,
    next_attempt_at = ?,
    updated_at      = ?
WHERE id = ?
`, status, strings.TrimSpace(errorMessage), nextAttemptAt.UTC(), now, id)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("update notification retry: %w", err)
	}
	return nil
}

// SupersedeNotificationRetry closes a pending retry whose transition is no longer current.
func (s *Store) SupersedeNotificationRetry(ctx context.Context, id int64, reason string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE notification_retries
SET status = 'superseded', error_message = ?, updated_at = ?
WHERE id = ?
`, strings.TrimSpace(reason), time.Now().UTC(), id)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("supersede notification retry: %w", err)
	}
	return nil
}
