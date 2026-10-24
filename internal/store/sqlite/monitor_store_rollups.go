package sqlite

import (
	"context"
	"fmt"
	"time"
)

type MonitorHourlyRollup struct {
	MonitorID      int64
	HourBucket     time.Time
	TotalChecks    int
	UpChecks       int
	DownChecks     int
	DegradedChecks int
	// UnknownChecks are checks without a verdict (e.g. remote node offline); they are
	// excluded from uptime.
	UnknownChecks int
	// MaintenanceChecks are checks inside a maintenance window (filled by Phase 6); they are
	// counted in TotalChecks only and excluded from uptime.
	MaintenanceChecks int
	LatencySumMS      int
	LatencyMinMS      int
	LatencyMaxMS      int
	FirstCheckedAt    time.Time
	LastCheckedAt     time.Time
}

// EffectiveChecks is the uptime denominator: checks that produced a verdict outside maintenance.
func (r MonitorHourlyRollup) EffectiveChecks() int {
	effective := r.TotalChecks - r.UnknownChecks - r.MaintenanceChecks
	if effective < 0 {
		return 0
	}
	return effective
}

func (s *Store) ListMonitorHourlyRollupsSince(ctx context.Context, since time.Time) ([]MonitorHourlyRollup, error) {
	return s.listHourlyRollups(ctx, `
SELECT
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
FROM monitor_hourly_rollups
WHERE hour_bucket >= ?
ORDER BY hour_bucket ASC, monitor_id ASC
`, since.UTC())
}

// ListMonitorHourlyRollupsForMonitorSince returns one monitor's hourly rollups, oldest first.
func (s *Store) ListMonitorHourlyRollupsForMonitorSince(ctx context.Context, monitorID int64, since time.Time) ([]MonitorHourlyRollup, error) {
	return s.listHourlyRollups(ctx, `
SELECT
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
FROM monitor_hourly_rollups
WHERE monitor_id = ? AND hour_bucket >= ?
ORDER BY hour_bucket ASC
`, monitorID, since.UTC())
}

func (s *Store) listHourlyRollups(ctx context.Context, query string, args ...any) ([]MonitorHourlyRollup, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return []MonitorHourlyRollup{}, nil
		}
		return nil, fmt.Errorf("list monitor hourly rollups: %w", err)
	}
	defer rows.Close()

	items := make([]MonitorHourlyRollup, 0)
	for rows.Next() {
		var item MonitorHourlyRollup
		if err := rows.Scan(
			&item.MonitorID,
			&item.HourBucket,
			&item.TotalChecks,
			&item.UpChecks,
			&item.DownChecks,
			&item.DegradedChecks,
			&item.UnknownChecks,
			&item.MaintenanceChecks,
			&item.LatencySumMS,
			&item.LatencyMinMS,
			&item.LatencyMaxMS,
			&item.FirstCheckedAt,
			&item.LastCheckedAt,
		); err != nil {
			if isMalformedSQLiteError(err) {
				return []MonitorHourlyRollup{}, nil
			}
			return nil, fmt.Errorf("scan monitor hourly rollup: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		if isMalformedSQLiteError(err) {
			return []MonitorHourlyRollup{}, nil
		}
		return nil, fmt.Errorf("iterate monitor hourly rollups: %w", err)
	}

	return items, nil
}
