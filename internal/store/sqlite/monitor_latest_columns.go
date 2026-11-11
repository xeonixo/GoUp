package sqlite

import (
	"context"
	"fmt"
	"goup/internal/monitor"
	"strings"
	"time"
)

const lastResultBackfillSettingKey = "monitor_last_result_backfill_v1_completed_at"

// ensureMonitorLatestResultColumns adds denormalized last-check fields used by dashboard
// snapshots so reads do not need a correlated join into monitor_results.
func (s *Store) ensureMonitorLatestResultColumns(ctx context.Context) error {
	columns := []struct {
		name       string
		definition string
	}{
		{"last_result_id", "INTEGER"},
		{"last_checked_at", "DATETIME"},
		{"last_status", "TEXT NOT NULL DEFAULT ''"},
		{"last_latency_ms", "INTEGER NOT NULL DEFAULT 0"},
		{"last_message", "TEXT NOT NULL DEFAULT ''"},
		{"last_http_status_code", "INTEGER"},
		{"last_tls_valid", "INTEGER"},
		{"last_tls_not_after", "DATETIME"},
		{"last_tls_days_remaining", "INTEGER"},
	}
	addedAny := false
	for _, column := range columns {
		added, err := s.ensureColumn(ctx, "monitors", column.name, column.definition)
		if err != nil {
			return err
		}
		if added {
			addedAny = true
		}
	}
	if !addedAny {
		done, err := s.hasSetting(ctx, lastResultBackfillSettingKey)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return s.backfillMonitorLatestResults(ctx)
}

func (s *Store) backfillMonitorLatestResults(ctx context.Context) error {
	hasLatency, err := s.tableHasColumn(ctx, "monitor_results", "latency_ms")
	if err != nil {
		return err
	}
	if !hasLatency {
		// Incomplete legacy schemas are repaired later; skip until columns exist.
		return nil
	}

	// One index seek per monitor via idx_monitor_results_latest, instead of nine
	// correlated subqueries that re-walk history for each column.
	_, err = s.db.ExecContext(ctx, `
UPDATE monitors
SET
    last_result_id = latest.id,
    last_checked_at = latest.checked_at,
    last_status = COALESCE(latest.status, ''),
    last_latency_ms = COALESCE(latest.latency_ms, 0),
    last_message = COALESCE(latest.message, ''),
    last_http_status_code = latest.http_status_code,
    last_tls_valid = latest.tls_valid,
    last_tls_not_after = latest.tls_not_after,
    last_tls_days_remaining = latest.tls_days_remaining
FROM (
    SELECT
        m.id AS monitor_id,
        r.id,
        r.checked_at,
        r.status,
        r.latency_ms,
        r.message,
        r.http_status_code,
        r.tls_valid,
        r.tls_not_after,
        r.tls_days_remaining
    FROM monitors m
    JOIN monitor_results r ON r.id = (
        SELECT mr.id
        FROM monitor_results mr
        WHERE mr.monitor_id = m.id
        ORDER BY mr.checked_at DESC, mr.id DESC
        LIMIT 1
    )
) AS latest
WHERE monitors.id = latest.monitor_id
`)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("backfill monitor latest results: %w", err)
	}
	if err := s.setSetting(ctx, lastResultBackfillSettingKey, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("mark monitor latest result backfill complete: %w", err)
	}
	return nil
}

func updateMonitorLatestResult(ctx context.Context, execer sqlExecutor, resultID int64, result monitor.Result, checkedAt time.Time) error {
	_, err := execer.ExecContext(ctx, `
UPDATE monitors
SET
    last_result_id = ?,
    last_checked_at = ?,
    last_status = ?,
    last_latency_ms = ?,
    last_message = ?,
    last_http_status_code = ?,
    last_tls_valid = ?,
    last_tls_not_after = ?,
    last_tls_days_remaining = ?
WHERE id = ?
  AND (last_checked_at IS NULL OR last_checked_at <= ? OR (last_checked_at = ? AND COALESCE(last_result_id, 0) <= ?))
`,
		resultID,
		checkedAt,
		string(result.Status),
		int(result.Latency.Milliseconds()),
		strings.TrimSpace(result.Message),
		result.HTTPStatusCode,
		nullableBoolInt(result.TLSValid),
		result.TLSNotAfter,
		result.TLSDaysRemaining,
		result.MonitorID,
		checkedAt,
		checkedAt,
		resultID,
	)
	if err != nil {
		return fmt.Errorf("update monitor latest result: %w", err)
	}
	return nil
}

// CountOpenIncidents returns open incidents for enabled monitors.
func (s *Store) CountOpenIncidents(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM incidents i
JOIN monitors m ON m.id = i.monitor_id
WHERE i.resolved_at IS NULL
  AND m.enabled = 1
`).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// DashboardStatsFromSnapshots builds monitor counts from an already-loaded snapshot list
// and loads only the open-incident count from the database.
func (s *Store) DashboardStatsFromSnapshots(ctx context.Context, snapshots []monitor.Snapshot) (DashboardStats, error) {
	stats := DashboardStats{MonitorCount: len(snapshots)}
	for _, item := range snapshots {
		if item.Monitor.Enabled {
			stats.EnabledMonitorCount++
		}
	}
	openCount, err := s.CountOpenIncidents(ctx)
	if err != nil {
		return DashboardStats{}, err
	}
	stats.OpenIncidentCount = openCount
	return stats, nil
}
