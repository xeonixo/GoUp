package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
)

// ensureMonitorConfigJSONColumn adds the optional HTTPS assertion JSON blob for older databases.
func (s *Store) ensureMonitorConfigJSONColumn(ctx context.Context) error {
	if _, err := s.ensureColumn(ctx, "monitors", "config_json", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return err
	}
	return nil
}

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

// ensureMonitorResultLatestIndex keeps latest-result lookups on a single index
// seek. The hot queries are `WHERE monitor_id = ? ORDER BY checked_at DESC, id DESC LIMIT n`
// (every check, and every monitor on each scheduler pass and dashboard refresh).
// The previous index stopped at checked_at, so SQLite sorted every historical
// row of that monitor into a temporary btree — a full read of the history,
// spilled to disk, several times a second.
//
// Existing databases already have idx_monitor_results_monitor_checked_at.
// Build the replacement first, then drop the redundant one so inserts do not
// maintain both.
func (s *Store) ensureMonitorResultLatestIndex(ctx context.Context) error {
	var name string
	err := s.db.QueryRowContext(ctx, `
SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_monitor_results_latest'
`).Scan(&name)
	if err == sql.ErrNoRows {
		// The one-time build sorts the whole history. The default container
		// mounts /tmp as a 64MB tmpfs, which cannot hold that spill, so put
		// the temporary files next to the database.
		s.useDatabaseDirForTempFiles(ctx)
		if _, err := s.db.ExecContext(ctx, `
CREATE INDEX idx_monitor_results_latest
ON monitor_results(monitor_id, checked_at DESC, id DESC)`); err != nil {
			return fmt.Errorf("create latest monitor result index: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("check latest monitor result index: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DROP INDEX IF EXISTS idx_monitor_results_monitor_checked_at`); err != nil {
		return fmt.Errorf("drop redundant monitor result index: %w", err)
	}
	return nil
}

// useDatabaseDirForTempFiles points SQLite's temporary files at the database
// directory. Failures are ignored: the pragma is deprecated, and a small
// database can still be indexed in the default temporary directory.
func (s *Store) useDatabaseDirForTempFiles(ctx context.Context) {
	path, err := mainDatabaseFile(ctx, s.db)
	if err != nil || strings.TrimSpace(path) == "" {
		return
	}
	dir := filepath.Dir(path)
	quoted := "'" + strings.ReplaceAll(dir, "'", "''") + "'"
	_, _ = s.db.ExecContext(ctx, `PRAGMA temp_store_directory = `+quoted)
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
