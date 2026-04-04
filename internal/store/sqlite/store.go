package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type DashboardStats struct {
	MonitorCount        int
	EnabledMonitorCount int
	OpenIncidentCount   int
}

func Open(ctx context.Context, path string) (*Store, error) {
	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}

	store := &Store{db: db}
	if err := store.initSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Healthcheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) DashboardStats(ctx context.Context) (DashboardStats, error) {
	stats := DashboardStats{}

	queries := []struct {
		dest  *int
		query string
	}{
		{&stats.MonitorCount, `SELECT COUNT(*) FROM monitors`},
		{&stats.EnabledMonitorCount, `SELECT COUNT(*) FROM monitors WHERE enabled = 1`},
		{&stats.OpenIncidentCount, `
SELECT COUNT(*)
FROM incidents i
JOIN monitors m ON m.id = i.monitor_id
WHERE i.resolved_at IS NULL
  AND m.enabled = 1
`},
	}

	for _, item := range queries {
		if err := s.db.QueryRowContext(ctx, item.query).Scan(item.dest); err != nil {
			return DashboardStats{}, err
		}
	}

	return stats, nil
}

func (s *Store) UpsertUser(ctx context.Context, subject, email, displayName string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO users (oidc_subject, email, display_name, role, created_at, updated_at, last_login_at)
VALUES (?, ?, ?, 'admin', ?, ?, ?)
ON CONFLICT(oidc_subject) DO UPDATE SET
    email = excluded.email,
    display_name = excluded.display_name,
    updated_at = excluded.updated_at,
    last_login_at = excluded.last_login_at
`, subject, email, displayName, now, now, now)
	return err
}

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
	if err := s.ensureMonitorGroupsTable(ctx); err != nil {
		return err
	}
	if err := s.ensureMonitorGroupIconColumn(ctx); err != nil {
		return err
	}
	if err := s.repairCorruptedHistoryTables(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Store) repairCorruptedHistoryTables(ctx context.Context) error {
	if err := s.ensureTableReadable(ctx, "notification_events"); err != nil {
		if !isMalformedSQLiteError(err) {
			return fmt.Errorf("check notification_events: %w", err)
		}
		if recreateErr := s.recreateNotificationEventsTable(ctx); recreateErr != nil {
			return fmt.Errorf("recreate notification_events: %w", recreateErr)
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
	query := fmt.Sprintf("SELECT 1 FROM %s LIMIT 1", table)
	_, err := s.db.ExecContext(ctx, query)
	return err
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

func (s *Store) ensureMonitorGroupColumn(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(monitors)`)
	if err != nil {
		return fmt.Errorf("inspect monitor columns: %w", err)
	}

	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("scan monitor column: %w", err)
		}
		if name == "group_name" {
			if err := rows.Close(); err != nil {
				return fmt.Errorf("close monitor column inspection: %w", err)
			}
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate monitor columns: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close monitor column inspection: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `ALTER TABLE monitors ADD COLUMN group_name TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("add monitor group column: %w", err)
	}
	return nil
}

func (s *Store) ensureMonitorSortColumn(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(monitors)`)
	if err != nil {
		return fmt.Errorf("inspect monitor columns for sort order: %w", err)
	}

	hasSortOrder := false
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("scan monitor sort column: %w", err)
		}
		if name == "sort_order" {
			hasSortOrder = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate monitor columns for sort order: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close monitor sort-order inspection: %w", err)
	}

	if !hasSortOrder {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE monitors ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add monitor sort order column: %w", err)
		}
	}

	var missingSortOrderCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM monitors WHERE sort_order <= 0`).Scan(&missingSortOrderCount); err != nil {
		return fmt.Errorf("count monitors missing sort order: %w", err)
	}
	if missingSortOrderCount == 0 {
		return nil
	}

	rows, err = s.db.QueryContext(ctx, `
SELECT id
FROM monitors
ORDER BY enabled DESC, name COLLATE NOCASE ASC, id ASC
`)
	if err != nil {
		return fmt.Errorf("select monitors for sort backfill: %w", err)
	}
	defer rows.Close()

	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan monitor id for sort backfill: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate monitor ids for sort backfill: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close monitor sort backfill rows: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin monitor sort backfill transaction: %w", err)
	}
	defer tx.Rollback()
	for idx, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE monitors SET sort_order = ? WHERE id = ?`, idx+1, id); err != nil {
			return fmt.Errorf("update monitor sort order during backfill: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monitor sort backfill: %w", err)
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

func sqliteDSN(path string) string {
	values := url.Values{}
	values.Add("_pragma", "foreign_keys(1)")
	values.Add("_pragma", "busy_timeout(5000)")
	values.Add("_pragma", "journal_mode(WAL)")

	u := &url.URL{
		Scheme:   "file",
		Path:     filepath.Clean(path),
		RawQuery: values.Encode(),
	}
	return u.String()
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
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 60,
    timeout_seconds INTEGER NOT NULL DEFAULT 10,
    enabled INTEGER NOT NULL DEFAULT 1,
    tls_mode TEXT NOT NULL DEFAULT 'none',
    expected_status_code INTEGER,
    expected_text TEXT,
    notify_on_recovery INTEGER NOT NULL DEFAULT 1,
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
