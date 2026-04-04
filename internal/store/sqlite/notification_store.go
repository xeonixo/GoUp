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
