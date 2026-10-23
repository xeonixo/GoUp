package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	statusPageTitleMaxRunes       = 120
	statusPageDescriptionMaxRunes = 500
	statusPageDisplayNameMaxRunes = 120
)

// StatusPageSettings is the per-tenant configuration of the public status page.
type StatusPageSettings struct {
	Enabled     bool
	Title       string
	Description string
	UpdatedAt   time.Time
}

// StatusPageMonitor selects one monitor for the public status page together with the
// name that is shown publicly (monitor names, targets and hosts are never exposed).
type StatusPageMonitor struct {
	MonitorID   int64
	DisplayName string
	SortOrder   int
}

func (s *Store) ensureStatusPageTables(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS status_page_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	enabled INTEGER NOT NULL DEFAULT 0,
	title TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS status_page_monitors (
	monitor_id INTEGER PRIMARY KEY,
	display_name TEXT NOT NULL DEFAULT '',
	sort_order INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);
`); err != nil {
		return fmt.Errorf("create status page tables: %w", err)
	}
	return nil
}

// GetStatusPageSettings returns the status page settings; a tenant that never configured the
// page gets the disabled defaults.
func (s *Store) GetStatusPageSettings(ctx context.Context) (StatusPageSettings, error) {
	var (
		item    StatusPageSettings
		enabled int
	)
	err := s.db.QueryRowContext(ctx, `SELECT enabled, title, description, updated_at FROM status_page_settings WHERE id = 1`).
		Scan(&enabled, &item.Title, &item.Description, &item.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return StatusPageSettings{}, nil
		}
		return StatusPageSettings{}, fmt.Errorf("load status page settings: %w", err)
	}
	item.Enabled = enabled == 1
	return item, nil
}

// SaveStatusPageSettings replaces the status page configuration, including the monitor selection.
// Monitors that no longer exist are ignored.
func (s *Store) SaveStatusPageSettings(ctx context.Context, settings StatusPageSettings, monitors []StatusPageMonitor) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin status page save: %w", err)
	}
	defer tx.Rollback()

	enabled := 0
	if settings.Enabled {
		enabled = 1
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO status_page_settings (id, enabled, title, description, updated_at)
VALUES (1, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	enabled = excluded.enabled,
	title = excluded.title,
	description = excluded.description,
	updated_at = excluded.updated_at
`, enabled, truncateRunes(strings.TrimSpace(settings.Title), statusPageTitleMaxRunes),
		truncateRunes(strings.TrimSpace(settings.Description), statusPageDescriptionMaxRunes), time.Now().UTC()); err != nil {
		return fmt.Errorf("save status page settings: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM status_page_monitors`); err != nil {
		return fmt.Errorf("clear status page monitors: %w", err)
	}
	for idx, item := range monitors {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO status_page_monitors (monitor_id, display_name, sort_order)
SELECT id, ?, ? FROM monitors WHERE id = ?
ON CONFLICT(monitor_id) DO UPDATE SET display_name = excluded.display_name, sort_order = excluded.sort_order
`, truncateRunes(strings.TrimSpace(item.DisplayName), statusPageDisplayNameMaxRunes), idx, item.MonitorID); err != nil {
			return fmt.Errorf("save status page monitor: %w", err)
		}
	}
	return tx.Commit()
}

// ListStatusPageMonitors returns the selected monitors in display order.
func (s *Store) ListStatusPageMonitors(ctx context.Context) ([]StatusPageMonitor, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT sp.monitor_id, sp.display_name, sp.sort_order
FROM status_page_monitors sp
JOIN monitors m ON m.id = sp.monitor_id
ORDER BY sp.sort_order ASC, sp.monitor_id ASC
`)
	if err != nil {
		return nil, fmt.Errorf("list status page monitors: %w", err)
	}
	defer rows.Close()
	items := make([]StatusPageMonitor, 0)
	for rows.Next() {
		var item StatusPageMonitor
		if err := rows.Scan(&item.MonitorID, &item.DisplayName, &item.SortOrder); err != nil {
			return nil, fmt.Errorf("scan status page monitor: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate status page monitors: %w", err)
	}
	return items, nil
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
