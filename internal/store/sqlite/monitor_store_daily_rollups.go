package sqlite

import (
	"context"
	"fmt"
	"time"
)

const (
	dailyRollupBackfillSettingKey = "daily_rollup_backfill_v1_completed_at"
	dailyRollupRetentionDays      = 400 // matches hourly retention for the 12M trend
	lastDailyRollupRetentionRun   = "last_daily_rollup_retention_run_at"
)

func (s *Store) ensureMonitorDailyRollupsTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS monitor_daily_rollups (
	monitor_id INTEGER NOT NULL,
	day_bucket DATETIME NOT NULL,
	total_checks INTEGER NOT NULL DEFAULT 0,
	up_checks INTEGER NOT NULL DEFAULT 0,
	down_checks INTEGER NOT NULL DEFAULT 0,
	degraded_checks INTEGER NOT NULL DEFAULT 0,
	unknown_checks INTEGER NOT NULL DEFAULT 0,
	maintenance_checks INTEGER NOT NULL DEFAULT 0,
	latency_sum_ms INTEGER NOT NULL DEFAULT 0,
	latency_min_ms INTEGER NOT NULL DEFAULT 0,
	latency_max_ms INTEGER NOT NULL DEFAULT 0,
	first_checked_at DATETIME NOT NULL,
	last_checked_at DATETIME NOT NULL,
	PRIMARY KEY (monitor_id, day_bucket),
	FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
)`); err != nil {
		return fmt.Errorf("create monitor_daily_rollups table: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS idx_monitor_daily_rollups_day_bucket
ON monitor_daily_rollups(day_bucket DESC)`); err != nil {
		return fmt.Errorf("create monitor_daily_rollups index: %w", err)
	}
	return nil
}

// ListMonitorDailyRollupsSince returns daily rollups for all monitors since the given day.
// Results are mapped onto MonitorHourlyRollup (HourBucket = day_bucket) for shared trend builders.
func (s *Store) ListMonitorDailyRollupsSince(ctx context.Context, since time.Time) ([]MonitorHourlyRollup, error) {
	dayStart := time.Date(since.UTC().Year(), since.UTC().Month(), since.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return s.listHourlyRollups(ctx, `
SELECT
    monitor_id,
    day_bucket,
    total_checks,
    up_checks,
    down_checks,
    degraded_checks,
    unknown_checks,
    maintenance_checks,
    latency_sum_ms,
    latency_min_ms,
    latency_max_ms,
    first_checked_at,
    last_checked_at
FROM monitor_daily_rollups
WHERE day_bucket >= ?
ORDER BY day_bucket ASC, monitor_id ASC
`, dayStart)
}

// ListMonitorDailyRollupsForMonitorSince returns one monitor's daily rollups, oldest first.
func (s *Store) ListMonitorDailyRollupsForMonitorSince(ctx context.Context, monitorID int64, since time.Time) ([]MonitorHourlyRollup, error) {
	dayStart := time.Date(since.UTC().Year(), since.UTC().Month(), since.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return s.listHourlyRollups(ctx, `
SELECT
    monitor_id,
    day_bucket,
    total_checks,
    up_checks,
    down_checks,
    degraded_checks,
    unknown_checks,
    maintenance_checks,
    latency_sum_ms,
    latency_min_ms,
    latency_max_ms,
    first_checked_at,
    last_checked_at
FROM monitor_daily_rollups
WHERE monitor_id = ? AND day_bucket >= ?
ORDER BY day_bucket ASC
`, monitorID, dayStart)
}
