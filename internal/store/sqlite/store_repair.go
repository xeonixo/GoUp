package sqlite

import (
	"context"
	"fmt"
)

func (s *Store) repairCorruptedHistoryTables(ctx context.Context) error {
	if err := s.ensureTableReadable(ctx, "notification_events"); err != nil {
		if !isMalformedSQLiteError(err) {
			return fmt.Errorf("check notification_events: %w", err)
		}
		if recreateErr := s.recreateNotificationEventsTable(ctx); recreateErr != nil {
			return fmt.Errorf("recreate notification_events: %w", recreateErr)
		}
	}

	if err := s.ensureTableReadable(ctx, "notification_retries"); err != nil {
		if !isMalformedSQLiteError(err) {
			return fmt.Errorf("check notification_retries: %w", err)
		}
		if recreateErr := s.recreateNotificationRetriesTable(ctx); recreateErr != nil {
			return fmt.Errorf("recreate notification_retries: %w", recreateErr)
		}
	}

	if err := s.ensureTableReadable(ctx, "monitor_hourly_rollups"); err != nil {
		if !isMalformedSQLiteError(err) {
			return fmt.Errorf("check monitor_hourly_rollups: %w", err)
		}
		if recreateErr := s.recreateMonitorHourlyRollupsTable(ctx); recreateErr != nil {
			return fmt.Errorf("recreate monitor_hourly_rollups: %w", recreateErr)
		}
	}

	return nil
}

func (s *Store) ensureTableReadable(ctx context.Context, table string) error {
	switch table {
	case "notification_events", "notification_retries", "monitor_hourly_rollups":
	default:
		return fmt.Errorf("unsupported table readability check: %s", table)
	}
	query := fmt.Sprintf("SELECT 1 FROM %s LIMIT 1", table)
	_, err := s.db.ExecContext(ctx, query)
	return err
}

func (s *Store) recreateNotificationRetriesTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DROP TABLE IF EXISTS notification_retries`); err != nil {
		return err
	}
	return s.ensureNotificationRetriesTable(ctx)
}

func (s *Store) recreateNotificationEventsTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DROP TABLE IF EXISTS notification_events`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS notification_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    endpoint_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    delivered_at DATETIME,
    error_message TEXT NOT NULL DEFAULT '',
    suppressed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE,
    FOREIGN KEY(endpoint_id) REFERENCES notification_endpoints(id) ON DELETE CASCADE
)
`)
	return err
}

func (s *Store) recreateMonitorHourlyRollupsTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DROP TABLE IF EXISTS monitor_hourly_rollups`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS monitor_hourly_rollups (
	monitor_id INTEGER NOT NULL,
	hour_bucket DATETIME NOT NULL,
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
	PRIMARY KEY (monitor_id, hour_bucket),
	FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
)
`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS idx_monitor_hourly_rollups_hour_bucket
ON monitor_hourly_rollups(hour_bucket DESC)
`)
	return err
}
