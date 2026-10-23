package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"goup/internal/monitor"
)

const maintenanceCacheTTL = 30 * time.Second

// ensurePhase6Schema adds reminders (monitors.remind_every_minutes / last_alert_at), the
// maintenance flag on results, reminder markers on the retry queue and the maintenance tables.
func (s *Store) ensurePhase6Schema(ctx context.Context) error {
	for _, col := range []struct{ table, name, def string }{
		{"monitors", "remind_every_minutes", "INTEGER NOT NULL DEFAULT 0"},
		{"monitors", "last_alert_at", "DATETIME"},
		{"monitor_results", "in_maintenance", "INTEGER NOT NULL DEFAULT 0"},
		{"notification_retries", "reminder", "INTEGER NOT NULL DEFAULT 0"},
		{"notification_retries", "outage_seconds", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if _, err := s.ensureColumn(ctx, col.table, col.name, col.def); err != nil {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS maintenance_windows (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	title TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	starts_at DATETIME NOT NULL,
	ends_at DATETIME NOT NULL,
	recurrence TEXT NOT NULL DEFAULT 'none',
	scope TEXT NOT NULL DEFAULT 'all',
	created_by INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS maintenance_window_targets (
	window_id INTEGER NOT NULL,
	target_type TEXT NOT NULL,
	monitor_id INTEGER NOT NULL DEFAULT 0,
	group_name TEXT NOT NULL DEFAULT '',
	FOREIGN KEY(window_id) REFERENCES maintenance_windows(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_maintenance_window_targets_window
ON maintenance_window_targets(window_id);
`); err != nil {
		return fmt.Errorf("create maintenance tables: %w", err)
	}
	return nil
}

// Validation errors of maintenance windows; callers map them to localized messages.
var (
	ErrMaintenanceTitle   = errors.New("maintenance title is required (max 120 characters)")
	ErrMaintenanceText    = errors.New("maintenance description must not exceed 1000 characters")
	ErrMaintenanceTimes   = errors.New("maintenance start and end are required")
	ErrMaintenanceOrder   = errors.New("maintenance end must be after its start")
	ErrMaintenanceTooLong = errors.New("a recurring maintenance window must not be longer than its period")
	ErrMaintenanceTargets = errors.New("select at least one monitor or group")
	ErrMaintenanceInvalid = errors.New("invalid maintenance recurrence or scope")
)

// ValidateMaintenanceWindow checks a window before it is stored.
func ValidateMaintenanceWindow(w monitor.MaintenanceWindow) error {
	if strings.TrimSpace(w.Title) == "" || len([]rune(strings.TrimSpace(w.Title))) > 120 {
		return ErrMaintenanceTitle
	}
	if len([]rune(w.Description)) > 1000 {
		return ErrMaintenanceText
	}
	if w.StartsAt.IsZero() || w.EndsAt.IsZero() {
		return ErrMaintenanceTimes
	}
	if !w.EndsAt.After(w.StartsAt) {
		return ErrMaintenanceOrder
	}
	length := w.EndsAt.Sub(w.StartsAt)
	switch w.Recurrence {
	case monitor.RecurrenceNone:
	case monitor.RecurrenceDaily:
		if length > 24*time.Hour {
			return ErrMaintenanceTooLong
		}
	case monitor.RecurrenceWeekly:
		if length > 7*24*time.Hour {
			return ErrMaintenanceTooLong
		}
	default:
		return ErrMaintenanceInvalid
	}
	switch w.Scope {
	case monitor.MaintenanceScopeAll:
	case monitor.MaintenanceScopeMonitors:
		if len(w.MonitorIDs) == 0 {
			return ErrMaintenanceTargets
		}
	case monitor.MaintenanceScopeGroups:
		if len(w.Groups) == 0 {
			return ErrMaintenanceTargets
		}
	default:
		return ErrMaintenanceInvalid
	}
	return nil
}

func normalizeMaintenanceWindow(w monitor.MaintenanceWindow) monitor.MaintenanceWindow {
	w.Title = strings.TrimSpace(w.Title)
	w.Description = strings.TrimSpace(w.Description)
	w.StartsAt = w.StartsAt.UTC()
	w.EndsAt = w.EndsAt.UTC()
	w.Recurrence = monitor.NormalizeRecurrence(w.Recurrence)
	w.Scope = monitor.NormalizeMaintenanceScope(w.Scope)
	return w
}

func (s *Store) invalidateMaintenanceCache() {
	s.maintenanceMu.Lock()
	s.maintenanceLoaded = time.Time{}
	s.maintenanceMu.Unlock()
}

func insertMaintenanceTargets(ctx context.Context, tx *sql.Tx, id int64, w monitor.MaintenanceWindow) error {
	switch w.Scope {
	case monitor.MaintenanceScopeMonitors:
		seen := map[int64]bool{}
		for _, monitorID := range w.MonitorIDs {
			if monitorID <= 0 || seen[monitorID] {
				continue
			}
			seen[monitorID] = true
			if _, err := tx.ExecContext(ctx, `INSERT INTO maintenance_window_targets (window_id, target_type, monitor_id) VALUES (?, 'monitor', ?)`, id, monitorID); err != nil {
				return fmt.Errorf("insert maintenance monitor target: %w", err)
			}
		}
	case monitor.MaintenanceScopeGroups:
		seen := map[string]bool{}
		for _, group := range w.Groups {
			group = strings.TrimSpace(group)
			if group == "" || seen[group] {
				continue
			}
			seen[group] = true
			if _, err := tx.ExecContext(ctx, `INSERT INTO maintenance_window_targets (window_id, target_type, group_name) VALUES (?, 'group', ?)`, id, group); err != nil {
				return fmt.Errorf("insert maintenance group target: %w", err)
			}
		}
	}
	return nil
}

// CreateMaintenanceWindow stores a new window and returns its id.
func (s *Store) CreateMaintenanceWindow(ctx context.Context, w monitor.MaintenanceWindow) (int64, error) {
	w = normalizeMaintenanceWindow(w)
	if err := ValidateMaintenanceWindow(w); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin maintenance create: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
INSERT INTO maintenance_windows (title, description, starts_at, ends_at, recurrence, scope, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`, w.Title, w.Description, w.StartsAt, w.EndsAt, w.Recurrence, w.Scope, w.CreatedBy, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("create maintenance window: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read maintenance window id: %w", err)
	}
	if err := insertMaintenanceTargets(ctx, tx, id, w); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit maintenance create: %w", err)
	}
	s.invalidateMaintenanceCache()
	return id, nil
}

// UpdateMaintenanceWindow replaces a window including its targets; sql.ErrNoRows if unknown.
func (s *Store) UpdateMaintenanceWindow(ctx context.Context, w monitor.MaintenanceWindow) error {
	w = normalizeMaintenanceWindow(w)
	if err := ValidateMaintenanceWindow(w); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin maintenance update: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
UPDATE maintenance_windows
SET title = ?, description = ?, starts_at = ?, ends_at = ?, recurrence = ?, scope = ?
WHERE id = ?
`, w.Title, w.Description, w.StartsAt, w.EndsAt, w.Recurrence, w.Scope, w.ID)
	if err != nil {
		return fmt.Errorf("update maintenance window: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM maintenance_window_targets WHERE window_id = ?`, w.ID); err != nil {
		return fmt.Errorf("clear maintenance targets: %w", err)
	}
	if err := insertMaintenanceTargets(ctx, tx, w.ID, w); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit maintenance update: %w", err)
	}
	s.invalidateMaintenanceCache()
	return nil
}

// DeleteMaintenanceWindow removes a window; sql.ErrNoRows if unknown.
func (s *Store) DeleteMaintenanceWindow(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM maintenance_window_targets WHERE window_id = ?`, id); err != nil {
		return fmt.Errorf("delete maintenance targets: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM maintenance_windows WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete maintenance window: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	s.invalidateMaintenanceCache()
	return nil
}

// GetMaintenanceWindow loads one window; sql.ErrNoRows if unknown.
func (s *Store) GetMaintenanceWindow(ctx context.Context, id int64) (monitor.MaintenanceWindow, error) {
	for _, w := range mustWindows(s.ListMaintenanceWindows(ctx)) {
		if w.ID == id {
			return w, nil
		}
	}
	return monitor.MaintenanceWindow{}, sql.ErrNoRows
}

func mustWindows(items []monitor.MaintenanceWindow, _ error) []monitor.MaintenanceWindow {
	return items
}

// ListMaintenanceWindows returns every window with its targets, newest start first.
func (s *Store) ListMaintenanceWindows(ctx context.Context) ([]monitor.MaintenanceWindow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, title, description, starts_at, ends_at, recurrence, scope, created_by, created_at
FROM maintenance_windows
ORDER BY starts_at DESC, id DESC
`)
	if err != nil {
		return nil, fmt.Errorf("list maintenance windows: %w", err)
	}
	var items []monitor.MaintenanceWindow
	index := map[int64]int{}
	for rows.Next() {
		var w monitor.MaintenanceWindow
		if err := rows.Scan(&w.ID, &w.Title, &w.Description, &w.StartsAt, &w.EndsAt, &w.Recurrence, &w.Scope, &w.CreatedBy, &w.CreatedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan maintenance window: %w", err)
		}
		w.StartsAt, w.EndsAt = w.StartsAt.UTC(), w.EndsAt.UTC()
		w.Recurrence = monitor.NormalizeRecurrence(w.Recurrence)
		w.Scope = monitor.NormalizeMaintenanceScope(w.Scope)
		index[w.ID] = len(items)
		items = append(items, w)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate maintenance windows: %w", err)
	}
	rows.Close()

	targets, err := s.db.QueryContext(ctx, `SELECT window_id, target_type, monitor_id, group_name FROM maintenance_window_targets ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("list maintenance targets: %w", err)
	}
	defer targets.Close()
	for targets.Next() {
		var windowID, monitorID int64
		var kind, group string
		if err := targets.Scan(&windowID, &kind, &monitorID, &group); err != nil {
			return nil, fmt.Errorf("scan maintenance target: %w", err)
		}
		i, ok := index[windowID]
		if !ok {
			continue
		}
		if kind == "monitor" {
			items[i].MonitorIDs = append(items[i].MonitorIDs, monitorID)
		} else {
			items[i].Groups = append(items[i].Groups, group)
		}
	}
	return items, targets.Err()
}

// MaintenanceSet returns the windows from a cache that is refreshed every 30 seconds and
// dropped whenever a window is created, changed or deleted through this store.
func (s *Store) MaintenanceSet(ctx context.Context) monitor.MaintenanceSet {
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	if !s.maintenanceLoaded.IsZero() && time.Since(s.maintenanceLoaded) < maintenanceCacheTTL {
		return s.maintenanceCache
	}
	items, err := s.ListMaintenanceWindows(ctx)
	if err != nil {
		// Keep serving the previous snapshot; retry on the next call.
		return s.maintenanceCache
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	s.maintenanceCache = monitor.MaintenanceSet{Windows: items}
	s.maintenanceLoaded = time.Now()
	return s.maintenanceCache
}

// ActiveMaintenance implements monitor.MaintenanceChecker.
func (s *Store) ActiveMaintenance(ctx context.Context, monitorID int64, group string, now time.Time) bool {
	_, ok := s.MaintenanceSet(ctx).Active(monitorID, group, now)
	return ok
}

// SetMonitorMuteStartStatus stores the catch-up marker.
func (s *Store) SetMonitorMuteStartStatus(ctx context.Context, monitorID int64, status monitor.Status) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE monitors SET mute_start_status = ? WHERE id = ?`, string(status), monitorID); err != nil {
		return fmt.Errorf("set monitor mute_start_status: %w", err)
	}
	return nil
}

// SetMonitorLastAlert records when the current outage was last announced; nil clears it.
func (s *Store) SetMonitorLastAlert(ctx context.Context, monitorID int64, at *time.Time) error {
	var value any
	if at != nil {
		value = at.UTC()
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE monitors SET last_alert_at = ? WHERE id = ?`, value, monitorID); err != nil {
		return fmt.Errorf("set monitor last_alert_at: %w", err)
	}
	return nil
}

// CurrentOutageStart returns the time of the first result of the ongoing run of down results.
func (s *Store) CurrentOutageStart(ctx context.Context, monitorID int64) (time.Time, bool, error) {
	var raw any
	err := s.db.QueryRowContext(ctx, `
SELECT MIN(checked_at) FROM monitor_results
WHERE monitor_id = ? AND status = 'down'
  AND checked_at > COALESCE((SELECT MAX(checked_at) FROM monitor_results WHERE monitor_id = ? AND status != 'down'), '')
`, monitorID, monitorID).Scan(&raw)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, fmt.Errorf("load outage start: %w", err)
	}
	switch v := raw.(type) {
	case time.Time:
		return v.UTC(), true, nil
	case string:
		// The driver stores times in Go's default format ("... +0000 UTC", optionally with a
		// monotonic clock suffix).
		if i := strings.Index(v, " m="); i >= 0 {
			v = v[:i]
		}
		for _, layout := range []string{"2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05.999999999-07:00", time.RFC3339Nano} {
			if t, err := time.Parse(layout, v); err == nil {
				return t.UTC(), true, nil
			}
		}
	}
	return time.Time{}, false, nil
}

var _ monitor.MaintenanceChecker = (*Store)(nil)
