package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

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
	// Suppressed marks a notification that was deliberately not sent (e.g. monitor muted).
	Suppressed bool
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

// RecordSuppressedNotificationEvent logs a transition whose notification was intentionally not sent.
func (s *Store) RecordSuppressedNotificationEvent(ctx context.Context, monitorID int64, endpointID int64, eventType string, reason string) error {
	eventType = strings.TrimSpace(eventType)
	if monitorID <= 0 || endpointID <= 0 || eventType == "" {
		return fmt.Errorf("invalid notification event payload")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO notification_events (monitor_id, endpoint_id, event_type, created_at, delivered_at, error_message, suppressed)
VALUES (?, ?, ?, ?, NULL, ?, 1)
`, monitorID, endpointID, eventType, time.Now().UTC(), strings.TrimSpace(reason))
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("record suppressed notification event: %w", err)
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
    e.error_message,
    e.suppressed
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
			&item.Suppressed,
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

func (s *Store) CountNotificationEvents(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_events`).Scan(&count)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("count notification events: %w", err)
	}
	return count, nil
}

func (s *Store) ListNotificationEventsPaginated(ctx context.Context, limit, offset int) ([]NotificationEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
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
    e.error_message,
    e.suppressed
FROM notification_events e
LEFT JOIN monitors m ON m.id = e.monitor_id
LEFT JOIN notification_endpoints ne ON ne.id = e.endpoint_id
ORDER BY e.id DESC
LIMIT ? OFFSET ?
`, limit, offset)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return []NotificationEvent{}, nil
		}
		return nil, fmt.Errorf("list notification events paginated: %w", err)
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
			&item.Suppressed,
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
