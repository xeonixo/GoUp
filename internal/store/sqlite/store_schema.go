package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *Store) initSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialize schema: %w", err)
	}
	if err := s.ensureMonitorGroupColumn(ctx); err != nil {
		return err
	}
	if err := s.ensureMonitorSortColumn(ctx); err != nil {
		return err
	}
	if err := s.ensureMonitorExecutorColumns(ctx); err != nil {
		return err
	}
	if err := s.ensureMonitorGroupsTable(ctx); err != nil {
		return err
	}
	if err := s.ensureMonitorGroupIconColumn(ctx); err != nil {
		return err
	}
	if err := s.ensureMonitorRetryColumns(ctx); err != nil {
		return err
	}
	if err := s.ensureNotificationRetriesTable(ctx); err != nil {
		return err
	}
	if err := s.repairCorruptedHistoryTables(ctx); err != nil {
		return err
	}
	if err := s.ensurePhase2Columns(ctx); err != nil {
		return err
	}
	if err := s.ensurePhase2Indexes(ctx); err != nil {
		return err
	}
	if err := s.ensureHeartbeatColumns(ctx); err != nil {
		return err
	}
	if err := s.ensureStatusPageTables(ctx); err != nil {
		return err
	}
	if err := s.ensurePhase6Schema(ctx); err != nil {
		return err
	}
	return nil
}

// tableHasColumn reports whether the table has the named column.
func (s *Store) tableHasColumn(ctx context.Context, table, column string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return false, fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, pk int
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return false, fmt.Errorf("scan %s column: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate %s columns: %w", table, err)
	}
	return false, nil
}

// ensureColumn adds a column when missing and reports whether it was added.
func (s *Store) ensureColumn(ctx context.Context, table, column, definition string) (bool, error) {
	exists, err := s.tableHasColumn(ctx, table, column)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+definition); err != nil {
		return false, fmt.Errorf("add %s.%s column: %w", table, column, err)
	}
	return true, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    oidc_subject TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'admin',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    last_login_at DATETIME
);

CREATE TABLE IF NOT EXISTS monitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
	group_name TEXT NOT NULL DEFAULT '',
	sort_order INTEGER NOT NULL DEFAULT 0,
	executor_kind TEXT NOT NULL DEFAULT 'local',
	executor_ref TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 60,
    timeout_seconds INTEGER NOT NULL DEFAULT 10,
    enabled INTEGER NOT NULL DEFAULT 1,
    tls_mode TEXT NOT NULL DEFAULT 'none',
    expected_status_code INTEGER,
    expected_text TEXT,
    notify_on_recovery INTEGER NOT NULL DEFAULT 1,
    retry_count INTEGER NOT NULL DEFAULT 0,
    retry_interval_seconds INTEGER NOT NULL DEFAULT 0,
    muted_until DATETIME,
    cert_warning_days INTEGER NOT NULL DEFAULT 7,
    confirm_after INTEGER NOT NULL DEFAULT 1,
    mute_start_status TEXT NOT NULL DEFAULT '',
    remind_every_minutes INTEGER NOT NULL DEFAULT 0,
    last_alert_at DATETIME,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    checked_at DATETIME NOT NULL,
    status TEXT NOT NULL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT '',
    http_status_code INTEGER,
    tls_valid INTEGER,
    tls_not_after DATETIME,
    tls_days_remaining INTEGER,
    in_maintenance INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_monitor_results_monitor_checked_at
ON monitor_results(monitor_id, checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_monitor_results_checked_at
ON monitor_results(checked_at);

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
);

CREATE INDEX IF NOT EXISTS idx_monitor_hourly_rollups_hour_bucket
ON monitor_hourly_rollups(hour_bucket DESC);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    started_at DATETIME NOT NULL,
    resolved_at DATETIME,
    cause TEXT NOT NULL DEFAULT '',
    last_state TEXT NOT NULL DEFAULT 'down',
    FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS monitor_state_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	monitor_id INTEGER NOT NULL,
	checked_at DATETIME NOT NULL,
	from_status TEXT NOT NULL,
	to_status TEXT NOT NULL,
	message TEXT NOT NULL DEFAULT '',
	FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_monitor_state_events_checked_at
ON monitor_state_events(checked_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS notification_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

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
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_groups (
	name TEXT PRIMARY KEY,
	icon_slug TEXT NOT NULL DEFAULT '',
	sort_order INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);
`
