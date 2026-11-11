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
	hasMessage, err := s.tableHasColumn(ctx, "monitor_results", "message")
	if err != nil {
		return err
	}
	hasHTTP, err := s.tableHasColumn(ctx, "monitor_results", "http_status_code")
	if err != nil {
		return err
	}
	hasTLSValid, err := s.tableHasColumn(ctx, "monitor_results", "tls_valid")
	if err != nil {
		return err
	}
	hasTLSNotAfter, err := s.tableHasColumn(ctx, "monitor_results", "tls_not_after")
	if err != nil {
		return err
	}
	hasTLSDays, err := s.tableHasColumn(ctx, "monitor_results", "tls_days_remaining")
	if err != nil {
		return err
	}

	latencyExpr := "COALESCE((SELECT mr.latency_ms FROM monitor_results mr WHERE mr.monitor_id = monitors.id ORDER BY mr.checked_at DESC, mr.id DESC LIMIT 1), 0)"
	messageExpr := "''"
	if hasMessage {
		messageExpr = "COALESCE((SELECT mr.message FROM monitor_results mr WHERE mr.monitor_id = monitors.id ORDER BY mr.checked_at DESC, mr.id DESC LIMIT 1), '')"
	}
	httpExpr := "NULL"
	if hasHTTP {
		httpExpr = "(SELECT mr.http_status_code FROM monitor_results mr WHERE mr.monitor_id = monitors.id ORDER BY mr.checked_at DESC, mr.id DESC LIMIT 1)"
	}
	tlsValidExpr := "NULL"
	if hasTLSValid {
		tlsValidExpr = "(SELECT mr.tls_valid FROM monitor_results mr WHERE mr.monitor_id = monitors.id ORDER BY mr.checked_at DESC, mr.id DESC LIMIT 1)"
	}
	tlsNotAfterExpr := "NULL"
	if hasTLSNotAfter {
		tlsNotAfterExpr = "(SELECT mr.tls_not_after FROM monitor_results mr WHERE mr.monitor_id = monitors.id ORDER BY mr.checked_at DESC, mr.id DESC LIMIT 1)"
	}
	tlsDaysExpr := "NULL"
	if hasTLSDays {
		tlsDaysExpr = "(SELECT mr.tls_days_remaining FROM monitor_results mr WHERE mr.monitor_id = monitors.id ORDER BY mr.checked_at DESC, mr.id DESC LIMIT 1)"
	}

	_, err = s.db.ExecContext(ctx, `
UPDATE monitors
SET
    last_result_id = (
        SELECT mr.id FROM monitor_results mr
        WHERE mr.monitor_id = monitors.id
        ORDER BY mr.checked_at DESC, mr.id DESC LIMIT 1
    ),
    last_checked_at = (
        SELECT mr.checked_at FROM monitor_results mr
        WHERE mr.monitor_id = monitors.id
        ORDER BY mr.checked_at DESC, mr.id DESC LIMIT 1
    ),
    last_status = COALESCE((
        SELECT mr.status FROM monitor_results mr
        WHERE mr.monitor_id = monitors.id
        ORDER BY mr.checked_at DESC, mr.id DESC LIMIT 1
    ), ''),
    last_latency_ms = `+latencyExpr+`,
    last_message = `+messageExpr+`,
    last_http_status_code = `+httpExpr+`,
    last_tls_valid = `+tlsValidExpr+`,
    last_tls_not_after = `+tlsNotAfterExpr+`,
    last_tls_days_remaining = `+tlsDaysExpr+`
WHERE EXISTS (
    SELECT 1 FROM monitor_results mr WHERE mr.monitor_id = monitors.id
)
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
