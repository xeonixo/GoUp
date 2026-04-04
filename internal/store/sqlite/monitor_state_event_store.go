package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type MonitorStateEvent struct {
	ID          int64
	MonitorID   int64
	MonitorName string
	CheckedAt   time.Time
	FromStatus  string
	ToStatus    string
	Message     string
}

func (s *Store) ListRecentMonitorStateEvents(ctx context.Context, limit int) ([]MonitorStateEvent, error) {
	if limit <= 0 {
		limit = 30
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT
	e.id,
	e.monitor_id,
	COALESCE(m.name, ''),
	e.checked_at,
	e.from_status,
	e.to_status,
	e.message
FROM monitor_state_events e
LEFT JOIN monitors m ON m.id = e.monitor_id
ORDER BY e.checked_at DESC, e.id DESC
LIMIT ?
`, limit)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return []MonitorStateEvent{}, nil
		}
		return nil, fmt.Errorf("list monitor state events: %w", err)
	}
	defer rows.Close()

	items := make([]MonitorStateEvent, 0, limit)
	for rows.Next() {
		var item MonitorStateEvent
		if err := rows.Scan(
			&item.ID,
			&item.MonitorID,
			&item.MonitorName,
			&item.CheckedAt,
			&item.FromStatus,
			&item.ToStatus,
			&item.Message,
		); err != nil {
			if isMalformedSQLiteError(err) {
				return []MonitorStateEvent{}, nil
			}
			return nil, fmt.Errorf("scan monitor state event: %w", err)
		}
		item.FromStatus = strings.ToLower(strings.TrimSpace(item.FromStatus))
		item.ToStatus = strings.ToLower(strings.TrimSpace(item.ToStatus))
		item.Message = strings.TrimSpace(item.Message)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		if isMalformedSQLiteError(err) {
			return []MonitorStateEvent{}, nil
		}
		return nil, fmt.Errorf("iterate monitor state events: %w", err)
	}

	return items, nil
}
