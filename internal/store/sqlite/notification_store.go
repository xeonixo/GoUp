package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"goup/internal/monitor"
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
	_, err := s.db.ExecContext(ctx, `
INSERT INTO notification_retries (
    monitor_id, endpoint_id, event_type,
    monitor_name, monitor_kind, monitor_target, monitor_group,
    previous_status, current_status, checked_at, result_detail,
    attempt_count, max_attempts, next_attempt_at,
    status, error_message, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 'pending', '', ?, ?)
`,
		p.MonitorID, p.EndpointID, strings.TrimSpace(p.EventType),
		t.Monitor.Name, string(t.Monitor.Kind), t.Monitor.Target, t.Monitor.Group,
		string(t.Previous), string(t.Current), t.CheckedAt.UTC(), t.ResultDetail,
		p.MaxAttempts, p.NextAttemptAt.UTC(),
		now, now,
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
       attempt_count, max_attempts, next_attempt_at
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
		)
		if err := rows.Scan(
			&id, &monitorID, &endpointID, &eventType,
			&monitorName, &monitorKind, &monitorTarget, &monitorGroup,
			&previousStatus, &currentStatus, &checkedAt, &resultDetail,
			&attemptCount, &maxAttempts, &nextAttemptAt,
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
				Previous:     monitor.Status(previousStatus),
				Current:      monitor.Status(currentStatus),
				CheckedAt:    checkedAt,
				ResultDetail: resultDetail,
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

type NotificationEvent struct {
	ID          int64
	MonitorID   int64
	MonitorName string
	EndpointID  int64
	Endpoint    string
	EventType   string
	CreatedAt   time.Time
	DeliveredAt *time.Time
	Error       string
}

func (s *Store) EnsureSystemNotificationEndpoint(ctx context.Context, kind, name, configJSON string, enabled bool) (int64, error) {
	kind = strings.TrimSpace(kind)
	name = strings.TrimSpace(name)
	if kind == "" || name == "" {
		return 0, fmt.Errorf("notification endpoint kind and name are required")
	}
	if configJSON == "" {
		configJSON = "{}"
	}

	now := time.Now().UTC()

	var id int64
	err := s.db.QueryRowContext(ctx, `
SELECT id
FROM notification_endpoints
WHERE kind = ? AND name = ?
LIMIT 1
`, kind, name).Scan(&id)
	if err != nil {
		if err != sql.ErrNoRows {
			return 0, fmt.Errorf("lookup notification endpoint: %w", err)
		}

		result, insertErr := s.db.ExecContext(ctx, `
INSERT INTO notification_endpoints (kind, name, enabled, config_json, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
`, kind, name, boolToInt(enabled), configJSON, now, now)
		if insertErr != nil {
			return 0, fmt.Errorf("create notification endpoint: %w", insertErr)
		}
		id, insertErr = result.LastInsertId()
		if insertErr != nil {
			return 0, fmt.Errorf("read notification endpoint id: %w", insertErr)
		}
		return id, nil
	}

	_, err = s.db.ExecContext(ctx, `
UPDATE notification_endpoints
SET enabled = ?, config_json = ?, updated_at = ?
WHERE id = ?
`, boolToInt(enabled), configJSON, now, id)
	if err != nil {
		return 0, fmt.Errorf("update notification endpoint: %w", err)
	}

	return id, nil
}

func (s *Store) RecordNotificationEvent(ctx context.Context, monitorID int64, endpointID int64, eventType string, deliveredAt *time.Time, errorMessage string) error {
	eventType = strings.TrimSpace(eventType)
	if monitorID <= 0 || endpointID <= 0 || eventType == "" {
		return fmt.Errorf("invalid notification event payload")
	}

	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO notification_events (
    monitor_id,
    endpoint_id,
    event_type,
    created_at,
    delivered_at,
    error_message
) VALUES (?, ?, ?, ?, ?, ?)
`, monitorID, endpointID, eventType, now, deliveredAt, strings.TrimSpace(errorMessage))
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("record notification event: %w", err)
	}

	return nil
}

func (s *Store) ListRecentNotificationEvents(ctx context.Context, limit int) ([]NotificationEvent, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT
    e.id,
    e.monitor_id,
    COALESCE(m.name, ''),
    e.endpoint_id,
    COALESCE(ne.name, ''),
    e.event_type,
    e.created_at,
    e.delivered_at,
    e.error_message
FROM notification_events e
LEFT JOIN monitors m ON m.id = e.monitor_id
LEFT JOIN notification_endpoints ne ON ne.id = e.endpoint_id
ORDER BY e.id DESC
LIMIT ?
`, limit)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return []NotificationEvent{}, nil
		}
		return nil, fmt.Errorf("list notification events: %w", err)
	}
	defer rows.Close()

	items := make([]NotificationEvent, 0, limit)
	for rows.Next() {
		var item NotificationEvent
		var deliveredAt sql.NullTime
		if err := rows.Scan(
			&item.ID,
			&item.MonitorID,
			&item.MonitorName,
			&item.EndpointID,
			&item.Endpoint,
			&item.EventType,
			&item.CreatedAt,
			&deliveredAt,
			&item.Error,
		); err != nil {
			if isMalformedSQLiteError(err) {
				return []NotificationEvent{}, nil
			}
			return nil, fmt.Errorf("scan notification event: %w", err)
		}
		if deliveredAt.Valid {
			value := deliveredAt.Time
			item.DeliveredAt = &value
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		if isMalformedSQLiteError(err) {
			return []NotificationEvent{}, nil
		}
		return nil, fmt.Errorf("iterate notification events: %w", err)
	}

	return items, nil
}
