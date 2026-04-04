package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"goup/internal/monitor"
)

const (
	rawResultRetentionDays         = 30
	hourlyRollupRetentionDays      = 365
	maintenanceInterval            = 6 * time.Hour
	retentionRunInterval           = 24 * time.Hour
	hourlyRollupBackfillSettingKey = "hourly_rollup_backfill_v1_completed_at"
	lastRetentionRunSettingKey     = "last_raw_retention_run_at"
	lastRollupRetentionRunSetting  = "last_hourly_rollup_retention_run_at"
	lastOptimizeMonthSettingKey    = "last_sqlite_optimize_month"
)

type MaintenanceResult struct {
	BackfilledHourlyRollups bool
	DeletedRawResults       int64
	DeletedHourlyRollups    int64
	Optimized               bool
}

type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func MaintenanceInterval() time.Duration {
	return maintenanceInterval
}

func (s *Store) RunMaintenance(ctx context.Context, now time.Time) (MaintenanceResult, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	result := MaintenanceResult{}

	backfilled, err := s.ensureHourlyRollupBackfill(ctx, now)
	if err != nil {
		return result, err
	}
	result.BackfilledHourlyRollups = backfilled

	deleted, err := s.pruneRawResultsIfDue(ctx, now)
	if err != nil {
		return result, err
	}
	result.DeletedRawResults = deleted

	deletedRollups, err := s.pruneHourlyRollupsIfDue(ctx, now)
	if err != nil {
		return result, err
	}
	result.DeletedHourlyRollups = deletedRollups

	optimized, err := s.optimizeIfDue(ctx, now)
	if err != nil {
		return result, err
	}
	result.Optimized = optimized

	return result, nil
}

func upsertHourlyRollup(ctx context.Context, execer sqlExecutor, monitorID int64, checkedAt time.Time, status monitor.Status, latencyMS int) error {
	hourBucket := checkedAt.UTC().Truncate(time.Hour)
	upChecks, downChecks, degradedChecks := 0, 0, 0
	switch status {
	case monitor.StatusUp:
		upChecks = 1
	case monitor.StatusDown:
		downChecks = 1
	case monitor.StatusDegraded:
		degradedChecks = 1
	}

	_, err := execer.ExecContext(ctx, `
INSERT INTO monitor_hourly_rollups (
    monitor_id,
    hour_bucket,
    total_checks,
    up_checks,
    down_checks,
    degraded_checks,
    latency_sum_ms,
    latency_min_ms,
    latency_max_ms,
    first_checked_at,
    last_checked_at
) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(monitor_id, hour_bucket) DO UPDATE SET
    total_checks = monitor_hourly_rollups.total_checks + 1,
    up_checks = monitor_hourly_rollups.up_checks + excluded.up_checks,
    down_checks = monitor_hourly_rollups.down_checks + excluded.down_checks,
    degraded_checks = monitor_hourly_rollups.degraded_checks + excluded.degraded_checks,
    latency_sum_ms = monitor_hourly_rollups.latency_sum_ms + excluded.latency_sum_ms,
    latency_min_ms = MIN(monitor_hourly_rollups.latency_min_ms, excluded.latency_min_ms),
    latency_max_ms = MAX(monitor_hourly_rollups.latency_max_ms, excluded.latency_max_ms),
    first_checked_at = MIN(monitor_hourly_rollups.first_checked_at, excluded.first_checked_at),
    last_checked_at = MAX(monitor_hourly_rollups.last_checked_at, excluded.last_checked_at)
`, monitorID, hourBucket, upChecks, downChecks, degradedChecks, latencyMS, latencyMS, latencyMS, checkedAt.UTC(), checkedAt.UTC())
	if err != nil {
		return fmt.Errorf("upsert hourly rollup: %w", err)
	}

	return nil
}

func (s *Store) ensureHourlyRollupBackfill(ctx context.Context, now time.Time) (bool, error) {
	alreadyDone, err := s.hasSetting(ctx, hourlyRollupBackfillSettingKey)
	if err != nil {
		return false, fmt.Errorf("check hourly rollup backfill setting: %w", err)
	}
	if alreadyDone {
		return false, nil
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO monitor_hourly_rollups (
    monitor_id,
    hour_bucket,
    total_checks,
    up_checks,
    down_checks,
    degraded_checks,
    latency_sum_ms,
    latency_min_ms,
    latency_max_ms,
    first_checked_at,
    last_checked_at
)
SELECT
    monitor_id,
    substr(checked_at, 1, 13) || ':00:00',
    COUNT(*),
    SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END),
    SUM(CASE WHEN status = 'down' THEN 1 ELSE 0 END),
    SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END),
    SUM(latency_ms),
    MIN(latency_ms),
    MAX(latency_ms),
    MIN(checked_at),
    MAX(checked_at)
FROM monitor_results
GROUP BY monitor_id, substr(checked_at, 1, 13)
ON CONFLICT(monitor_id, hour_bucket) DO UPDATE SET
    total_checks = excluded.total_checks,
    up_checks = excluded.up_checks,
    down_checks = excluded.down_checks,
    degraded_checks = excluded.degraded_checks,
    latency_sum_ms = excluded.latency_sum_ms,
    latency_min_ms = excluded.latency_min_ms,
    latency_max_ms = excluded.latency_max_ms,
    first_checked_at = excluded.first_checked_at,
    last_checked_at = excluded.last_checked_at
`)
	if err != nil {
		return false, fmt.Errorf("backfill hourly rollups: %w", err)
	}

	if err := s.setSetting(ctx, hourlyRollupBackfillSettingKey, now.Format(time.RFC3339Nano)); err != nil {
		return false, fmt.Errorf("mark hourly rollup backfill complete: %w", err)
	}

	return true, nil
}

func (s *Store) pruneRawResultsIfDue(ctx context.Context, now time.Time) (int64, error) {
	due, err := s.shouldRunAfter(ctx, lastRetentionRunSettingKey, retentionRunInterval, now)
	if err != nil {
		return 0, fmt.Errorf("check retention schedule: %w", err)
	}
	if !due {
		return 0, nil
	}

	cutoff := now.AddDate(0, 0, -rawResultRetentionDays)
	result, err := s.db.ExecContext(ctx, `
DELETE FROM monitor_results
WHERE checked_at < ?
`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired monitor results: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted monitor result rows: %w", err)
	}

	if err := s.setSetting(ctx, lastRetentionRunSettingKey, now.Format(time.RFC3339Nano)); err != nil {
		return 0, fmt.Errorf("store retention run timestamp: %w", err)
	}

	return deleted, nil
}

func (s *Store) pruneHourlyRollupsIfDue(ctx context.Context, now time.Time) (int64, error) {
	due, err := s.shouldRunAfter(ctx, lastRollupRetentionRunSetting, retentionRunInterval, now)
	if err != nil {
		return 0, fmt.Errorf("check rollup retention schedule: %w", err)
	}
	if !due {
		return 0, nil
	}

	cutoff := now.AddDate(0, 0, -hourlyRollupRetentionDays)
	result, err := s.db.ExecContext(ctx, `
DELETE FROM monitor_hourly_rollups
WHERE hour_bucket < ?
`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired monitor rollups: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read deleted monitor rollup rows: %w", err)
	}

	if err := s.setSetting(ctx, lastRollupRetentionRunSetting, now.Format(time.RFC3339Nano)); err != nil {
		return 0, fmt.Errorf("store rollup retention run timestamp: %w", err)
	}

	return deleted, nil
}

func (s *Store) optimizeIfDue(ctx context.Context, now time.Time) (bool, error) {
	currentMonth := now.Format("2006-01")
	storedMonth, err := s.getSetting(ctx, lastOptimizeMonthSettingKey)
	if err != nil {
		return false, fmt.Errorf("load optimize month setting: %w", err)
	}
	if storedMonth == currentMonth {
		return false, nil
	}

	if _, err := s.db.ExecContext(ctx, `PRAGMA optimize`); err != nil {
		return false, fmt.Errorf("sqlite optimize failed: %w", err)
	}

	if err := s.setSetting(ctx, lastOptimizeMonthSettingKey, currentMonth); err != nil {
		return false, fmt.Errorf("store optimize month setting: %w", err)
	}

	return true, nil
}

func (s *Store) shouldRunAfter(ctx context.Context, key string, interval time.Duration, now time.Time) (bool, error) {
	value, err := s.getSetting(ctx, key)
	if err != nil {
		return false, err
	}
	if value == "" {
		return true, nil
	}
	lastRun, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return true, nil
	}
	return now.Sub(lastRun) >= interval, nil
}

func (s *Store) hasSetting(ctx context.Context, key string) (bool, error) {
	value, err := s.getSetting(ctx, key)
	if err != nil {
		return false, err
	}
	return value != "", nil
}

func (s *Store) getSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `
SELECT value
FROM app_settings
WHERE key = ?
`, key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return value, nil
}

func (s *Store) setSetting(ctx context.Context, key, value string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO app_settings (key, value, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = excluded.updated_at
`, key, value, now)
	return err
}
