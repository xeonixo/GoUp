package sqlite

import (
	"context"
	"fmt"
	"goup/internal/monitor"
	"time"
)

// upsertHourlyRollup adds one check to its hourly bucket. Latency sum/min/max only
// cover up and degraded checks (matching the backfill); down and unknown checks carry no
// meaningful latency and must not pull the minimum down to 0.
func upsertHourlyRollup(ctx context.Context, execer sqlExecutor, monitorID int64, checkedAt time.Time, status monitor.Status, latencyMS int, inMaintenance bool) error {
	hourBucket := checkedAt.UTC().Truncate(time.Hour)
	upChecks, downChecks, degradedChecks, unknownChecks, maintenanceChecks := 0, 0, 0, 0, 0
	latencySumMS, latencyMinMS, latencyMaxMS := 0, 0, 0
	// Checks inside a maintenance window only count in total_checks and maintenance_checks.
	switch {
	case inMaintenance:
		maintenanceChecks = 1
	default:
		switch status {
		case monitor.StatusUp:
			upChecks = 1
			latencySumMS, latencyMinMS, latencyMaxMS = latencyMS, latencyMS, latencyMS
		case monitor.StatusDegraded:
			degradedChecks = 1
			latencySumMS, latencyMinMS, latencyMaxMS = latencyMS, latencyMS, latencyMS
		case monitor.StatusDown:
			downChecks = 1
		default:
			unknownChecks = 1
		}
	}

	_, err := execer.ExecContext(ctx, `
INSERT INTO monitor_hourly_rollups (
    monitor_id,
    hour_bucket,
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
) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(monitor_id, hour_bucket) DO UPDATE SET
    total_checks = monitor_hourly_rollups.total_checks + 1,
    up_checks = monitor_hourly_rollups.up_checks + excluded.up_checks,
    down_checks = monitor_hourly_rollups.down_checks + excluded.down_checks,
    degraded_checks = monitor_hourly_rollups.degraded_checks + excluded.degraded_checks,
    unknown_checks = monitor_hourly_rollups.unknown_checks + excluded.unknown_checks,
    maintenance_checks = monitor_hourly_rollups.maintenance_checks + excluded.maintenance_checks,
    latency_sum_ms = monitor_hourly_rollups.latency_sum_ms + excluded.latency_sum_ms,
    latency_min_ms = CASE
        WHEN excluded.up_checks + excluded.degraded_checks = 0 THEN monitor_hourly_rollups.latency_min_ms
        WHEN monitor_hourly_rollups.up_checks + monitor_hourly_rollups.degraded_checks = 0 THEN excluded.latency_min_ms
        ELSE MIN(monitor_hourly_rollups.latency_min_ms, excluded.latency_min_ms)
    END,
    latency_max_ms = MAX(monitor_hourly_rollups.latency_max_ms, excluded.latency_max_ms),
    first_checked_at = MIN(monitor_hourly_rollups.first_checked_at, excluded.first_checked_at),
    last_checked_at = MAX(monitor_hourly_rollups.last_checked_at, excluded.last_checked_at)
`, monitorID, hourBucket, upChecks, downChecks, degradedChecks, unknownChecks, maintenanceChecks, latencySumMS, latencyMinMS, latencyMaxMS, checkedAt.UTC(), checkedAt.UTC())
	if err != nil {
		return fmt.Errorf("upsert hourly rollup: %w", err)
	}

	return nil
}

// ensureHourlyRollupMinRepair recomputes latency_min_ms for rollups that an older bug left at 0
// because a down check landed in the bucket. Only buckets whose raw results are still fully
// present are repaired; older ones keep their value. Runs once per database.
func (s *Store) ensureHourlyRollupMinRepair(ctx context.Context, now time.Time) error {
	done, err := s.hasSetting(ctx, hourlyRollupMinRepairSettingKey)
	if err != nil {
		return fmt.Errorf("check rollup min repair setting: %w", err)
	}
	if done {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `
UPDATE monitor_hourly_rollups
SET latency_min_ms = COALESCE((
    SELECT MIN(r.latency_ms)
    FROM monitor_results r
    WHERE r.monitor_id = monitor_hourly_rollups.monitor_id
      AND substr(r.checked_at, 1, 13) = substr(monitor_hourly_rollups.hour_bucket, 1, 13)
      AND r.status IN ('up', 'degraded')
), latency_min_ms)
WHERE latency_min_ms = 0
  AND up_checks + degraded_checks > 0
  AND total_checks = (
    SELECT COUNT(*)
    FROM monitor_results r
    WHERE r.monitor_id = monitor_hourly_rollups.monitor_id
      AND substr(r.checked_at, 1, 13) = substr(monitor_hourly_rollups.hour_bucket, 1, 13)
  )
`)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("repair hourly rollup latency minimum: %w", err)
	}
	if err := s.setSetting(ctx, hourlyRollupMinRepairSettingKey, now.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("mark rollup min repair complete: %w", err)
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
    unknown_checks,
    maintenance_checks,
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
    SUM(CASE WHEN in_maintenance = 0 AND status = 'up' THEN 1 ELSE 0 END),
    SUM(CASE WHEN in_maintenance = 0 AND status = 'down' THEN 1 ELSE 0 END),
    SUM(CASE WHEN in_maintenance = 0 AND status = 'degraded' THEN 1 ELSE 0 END),
    SUM(CASE WHEN in_maintenance = 0 AND status NOT IN ('up', 'down', 'degraded') THEN 1 ELSE 0 END),
    SUM(CASE WHEN in_maintenance = 1 THEN 1 ELSE 0 END),
	SUM(CASE WHEN in_maintenance = 0 AND status IN ('up', 'degraded') THEN latency_ms ELSE 0 END),
	COALESCE(MIN(CASE WHEN in_maintenance = 0 AND status IN ('up', 'degraded') THEN latency_ms END), 0),
	COALESCE(MAX(CASE WHEN in_maintenance = 0 AND status IN ('up', 'degraded') THEN latency_ms END), 0),
    MIN(checked_at),
    MAX(checked_at)
FROM monitor_results
GROUP BY monitor_id, substr(checked_at, 1, 13)
ON CONFLICT(monitor_id, hour_bucket) DO UPDATE SET
    total_checks = excluded.total_checks,
    up_checks = excluded.up_checks,
    down_checks = excluded.down_checks,
    degraded_checks = excluded.degraded_checks,
    unknown_checks = excluded.unknown_checks,
    maintenance_checks = excluded.maintenance_checks,
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
