package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// NotificationOutcomeCounts summarises notification_events since a point in time.
type NotificationOutcomeCounts struct {
	Delivered  int
	Failed     int
	Suppressed int
}

// NotificationFailure is one failed delivery attempt, joined with monitor and endpoint names.
type NotificationFailure struct {
	CreatedAt    time.Time
	MonitorName  string
	EndpointKind string
	EndpointName string
	EventType    string
	Error        string
}

// MaintenanceRuns holds the last recorded retention/rollup maintenance timestamps (zero = never).
type MaintenanceRuns struct {
	RawRetention    time.Time
	RollupRetention time.Time
}

// NotificationOutcomeCountsSince counts delivered, failed and suppressed events created at or after since.
// A failed event is one that was neither delivered nor suppressed and carries an error message.
func (s *Store) NotificationOutcomeCountsSince(ctx context.Context, since time.Time) (NotificationOutcomeCounts, error) {
	var counts NotificationOutcomeCounts
	err := s.db.QueryRowContext(ctx, `
SELECT
    COALESCE(SUM(CASE WHEN suppressed = 0 AND delivered_at IS NOT NULL THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN suppressed = 0 AND delivered_at IS NULL AND error_message != '' THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN suppressed = 1 THEN 1 ELSE 0 END), 0)
FROM notification_events
WHERE created_at >= ?
`, since.UTC()).Scan(&counts.Delivered, &counts.Failed, &counts.Suppressed)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return NotificationOutcomeCounts{}, nil
		}
		return NotificationOutcomeCounts{}, fmt.Errorf("count notification outcomes: %w", err)
	}
	return counts, nil
}

// ListRecentNotificationFailures returns the newest failed deliveries created at or after since.
func (s *Store) ListRecentNotificationFailures(ctx context.Context, since time.Time, limit int) ([]NotificationFailure, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT e.created_at, COALESCE(m.name, ''), COALESCE(ne.kind, ''), COALESCE(ne.name, ''), e.event_type, e.error_message
FROM notification_events e
LEFT JOIN monitors m ON m.id = e.monitor_id
LEFT JOIN notification_endpoints ne ON ne.id = e.endpoint_id
WHERE e.created_at >= ? AND e.suppressed = 0 AND e.delivered_at IS NULL AND e.error_message != ''
ORDER BY e.created_at DESC, e.id DESC
LIMIT ?
`, since.UTC(), limit)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list notification failures: %w", err)
	}
	defer rows.Close()

	var failures []NotificationFailure
	for rows.Next() {
		var f NotificationFailure
		if err := rows.Scan(&f.CreatedAt, &f.MonitorName, &f.EndpointKind, &f.EndpointName, &f.EventType, &f.Error); err != nil {
			return nil, fmt.Errorf("scan notification failure: %w", err)
		}
		failures = append(failures, f)
	}
	return failures, rows.Err()
}

// MaintenanceRuns reads when raw-result and hourly-rollup retention last ran.
func (s *Store) MaintenanceRuns(ctx context.Context) (MaintenanceRuns, error) {
	var runs MaintenanceRuns
	for key, dst := range map[string]*time.Time{
		lastRetentionRunSettingKey:    &runs.RawRetention,
		lastRollupRetentionRunSetting: &runs.RollupRetention,
	} {
		value, err := s.getSetting(ctx, key)
		if err != nil {
			return MaintenanceRuns{}, fmt.Errorf("read maintenance setting %s: %w", key, err)
		}
		if parsed, parseErr := time.Parse(time.RFC3339Nano, value); parseErr == nil {
			*dst = parsed
		}
	}
	return runs, nil
}

// NotificationRetryQueueStats returns the number of pending notification retries and the
// time of the earliest scheduled attempt (nil when the queue is empty).
func (s *Store) NotificationRetryQueueStats(ctx context.Context) (int, *time.Time, error) {
	var pending int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_retries WHERE status = 'pending'`).Scan(&pending); err != nil {
		if isMalformedSQLiteError(err) {
			return 0, nil, nil
		}
		return 0, nil, fmt.Errorf("count pending notification retries: %w", err)
	}
	if pending == 0 {
		return 0, nil, nil
	}
	var oldest time.Time
	err := s.db.QueryRowContext(ctx, `
SELECT next_attempt_at FROM notification_retries WHERE status = 'pending' ORDER BY next_attempt_at ASC LIMIT 1
`).Scan(&oldest)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMalformedSQLiteError(err) {
			return pending, nil, nil
		}
		return 0, nil, fmt.Errorf("oldest pending notification retry: %w", err)
	}
	oldest = oldest.UTC()
	return pending, &oldest, nil
}
