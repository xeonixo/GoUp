package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

// ensurePhase2Columns adds the data-quality columns: rollup unknown/maintenance counters,
// per-monitor flapping protection and mute catch-up state, and the suppressed notification flag.
func (s *Store) ensurePhase2Columns(ctx context.Context) error {
	if _, err := s.ensureColumn(ctx, "monitors", "confirm_after", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}
	if _, err := s.ensureColumn(ctx, "monitors", "mute_start_status", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := s.ensureColumn(ctx, "notification_events", "suppressed", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	addedUnknown, err := s.ensureColumn(ctx, "monitor_hourly_rollups", "unknown_checks", "INTEGER NOT NULL DEFAULT 0")
	if err != nil {
		return err
	}
	// maintenance_checks is filled by maintenance windows (Phase 6); checks inside a window
	// count towards total_checks and this column only, never towards up/down/degraded.
	if _, err := s.ensureColumn(ctx, "monitor_hourly_rollups", "maintenance_checks", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if addedUnknown {
		// Before this column existed unknown checks were counted in total_checks only.
		if _, err := s.db.ExecContext(ctx, `
UPDATE monitor_hourly_rollups
SET unknown_checks = total_checks - up_checks - down_checks - degraded_checks
WHERE total_checks > up_checks + down_checks + degraded_checks
`); err != nil {
			return fmt.Errorf("backfill rollup unknown_checks: %w", err)
		}
	}
	return nil
}

func (s *Store) ensurePhase2Indexes(ctx context.Context) error {
	for _, stmt := range []string{
		`CREATE INDEX IF NOT EXISTS idx_notification_events_monitor_created ON notification_events(monitor_id, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_notification_events_created ON notification_events(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_monitor ON incidents(monitor_id)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}
	return nil
}

func (s *Store) ensureNotificationRetriesTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS notification_retries (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id       INTEGER NOT NULL,
    endpoint_id      INTEGER NOT NULL,
    event_type       TEXT NOT NULL,
    monitor_name     TEXT NOT NULL DEFAULT '',
    monitor_kind     TEXT NOT NULL DEFAULT '',
    monitor_target   TEXT NOT NULL DEFAULT '',
    monitor_group    TEXT NOT NULL DEFAULT '',
    previous_status  TEXT NOT NULL DEFAULT '',
    current_status   TEXT NOT NULL DEFAULT '',
    checked_at       DATETIME NOT NULL,
    result_detail    TEXT NOT NULL DEFAULT '',
    attempt_count    INTEGER NOT NULL DEFAULT 0,
    max_attempts     INTEGER NOT NULL DEFAULT 3,
    next_attempt_at  DATETIME NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    error_message    TEXT NOT NULL DEFAULT '',
    created_at       DATETIME NOT NULL,
    updated_at       DATETIME NOT NULL,
    FOREIGN KEY(monitor_id)  REFERENCES monitors(id) ON DELETE CASCADE,
    FOREIGN KEY(endpoint_id) REFERENCES notification_endpoints(id) ON DELETE CASCADE
)`)
	if err != nil {
		return fmt.Errorf("create notification_retries table: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS idx_notification_retries_due
ON notification_retries(status, next_attempt_at)
WHERE status = 'pending'`)
	if err != nil {
		return fmt.Errorf("create notification_retries index: %w", err)
	}
	return nil
}

func (s *Store) ensureMonitorGroupsTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS monitor_groups (
	name TEXT PRIMARY KEY,
	icon_slug TEXT NOT NULL DEFAULT '',
	sort_order INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
)
`); err != nil {
		return fmt.Errorf("create monitor groups table: %w", err)
	}

	return nil
}

func (s *Store) ensureMonitorGroupIconColumn(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(monitor_groups)`)
	if err != nil {
		return fmt.Errorf("inspect monitor_groups columns: %w", err)
	}

	hasIconSlug := false
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("scan monitor_groups column: %w", err)
		}
		if name == "icon_slug" {
			hasIconSlug = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate monitor_groups columns: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close monitor_groups inspection: %w", err)
	}

	if !hasIconSlug {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE monitor_groups ADD COLUMN icon_slug TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add monitor_groups icon_slug column: %w", err)
		}
	}

	return nil
}
