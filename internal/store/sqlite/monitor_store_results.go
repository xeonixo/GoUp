package sqlite

import (
	"context"
	"fmt"
	"goup/internal/monitor"
	"strings"
	"time"
)

// RecentMonitorStatuses returns the latest result statuses of a monitor, newest first.
func (s *Store) RecentMonitorStatuses(ctx context.Context, monitorID int64, limit int) ([]monitor.Status, error) {
	if limit <= 0 {
		limit = 1
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT status
FROM monitor_results
WHERE monitor_id = ?
ORDER BY checked_at DESC, id DESC
LIMIT ?
`, monitorID, limit)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list recent monitor statuses: %w", err)
	}
	defer rows.Close()
	statuses := make([]monitor.Status, 0, limit)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan recent monitor status: %w", err)
		}
		statuses = append(statuses, monitor.Status(strings.ToLower(strings.TrimSpace(raw))))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recent monitor statuses: %w", err)
	}
	return statuses, nil
}

// ListLatenciesSince returns up/degraded latencies (ms) of raw results since the given time.
func (s *Store) ListLatenciesSince(ctx context.Context, monitorID int64, since time.Time) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT latency_ms
FROM monitor_results
WHERE monitor_id = ? AND checked_at >= ? AND status IN ('up', 'degraded')
`, monitorID, since.UTC())
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list latencies: %w", err)
	}
	defer rows.Close()
	values := make([]int, 0, 256)
	for rows.Next() {
		var value int
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan latency: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate latencies: %w", err)
	}
	return values, nil
}

func isMalformedSQLiteError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database disk image is malformed")
}

func (s *Store) SaveMonitorResult(ctx context.Context, result monitor.Result) error {
	checkedAt := result.CheckedAt.UTC()
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin result transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
INSERT INTO monitor_results (
    monitor_id, checked_at, status, latency_ms, message,
    http_status_code, tls_valid, tls_not_after, tls_days_remaining, in_maintenance
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, result.MonitorID, checkedAt, string(result.Status), int(result.Latency.Milliseconds()), strings.TrimSpace(result.Message), result.HTTPStatusCode, nullableBoolInt(result.TLSValid), result.TLSNotAfter, result.TLSDaysRemaining, boolToInt(result.InMaintenance))
	if err != nil {
		return fmt.Errorf("save monitor result: %w", err)
	}

	if err := upsertHourlyRollup(ctx, tx, result.MonitorID, checkedAt, result.Status, int(result.Latency.Milliseconds()), result.InMaintenance); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monitor result transaction: %w", err)
	}

	return nil
}
