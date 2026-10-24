package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (s *Store) pruneOldNotificationRetries(ctx context.Context, now time.Time) error {
	cutoff := now.AddDate(0, 0, -7)
	_, err := s.db.ExecContext(ctx, `
DELETE FROM notification_retries
WHERE status IN ('succeeded', 'abandoned', 'superseded')
  AND updated_at < ?
`, cutoff)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("prune old notification retries: %w", err)
	}
	return nil
}

func (s *Store) pruneRawResultsIfDue(ctx context.Context, now time.Time, retentionDays int) (int64, error) {
	due, err := s.shouldRunAfter(ctx, lastRetentionRunSettingKey, retentionRunInterval, now)
	if err != nil {
		return 0, fmt.Errorf("check retention schedule: %w", err)
	}
	if !due {
		return 0, nil
	}

	cutoff := now.AddDate(0, 0, -retentionDays)
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

func (s *Store) pruneEventsIfDue(ctx context.Context, now time.Time, opts MaintenanceOptions) (int64, int64, error) {
	due, err := s.shouldRunAfter(ctx, lastEventRetentionRunSetting, retentionRunInterval, now)
	if err != nil {
		return 0, 0, fmt.Errorf("check event retention schedule: %w", err)
	}
	if !due {
		return 0, 0, nil
	}

	stateCutoff := now.AddDate(0, 0, -opts.StateEventRetentionDays)
	stateResult, err := s.db.ExecContext(ctx, `
DELETE FROM monitor_state_events
WHERE checked_at < ?
`, stateCutoff)
	if err != nil {
		return 0, 0, fmt.Errorf("delete expired monitor state events: %w", err)
	}
	deletedStateEvents, err := stateResult.RowsAffected()
	if err != nil {
		return 0, 0, fmt.Errorf("read deleted monitor state event rows: %w", err)
	}

	notificationCutoff := now.AddDate(0, 0, -opts.NotificationEventRetentionDays)
	notificationResult, err := s.db.ExecContext(ctx, `
DELETE FROM notification_events
WHERE created_at < ?
`, notificationCutoff)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return deletedStateEvents, 0, nil
		}
		return 0, 0, fmt.Errorf("delete expired notification events: %w", err)
	}
	deletedNotificationEvents, err := notificationResult.RowsAffected()
	if err != nil {
		return 0, 0, fmt.Errorf("read deleted notification event rows: %w", err)
	}

	if err := s.setSetting(ctx, lastEventRetentionRunSetting, now.Format(time.RFC3339Nano)); err != nil {
		return 0, 0, fmt.Errorf("store event retention run timestamp: %w", err)
	}

	return deletedStateEvents, deletedNotificationEvents, nil
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
