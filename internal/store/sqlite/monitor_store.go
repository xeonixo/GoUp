package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"goup/internal/monitor"
)

type CreateMonitorParams struct {
	Name               string
	Group              string
	Kind               monitor.Kind
	Target             string
	Interval           time.Duration
	Timeout            time.Duration
	Enabled            bool
	TLSMode            monitor.TLSMode
	ExpectedStatusCode *int
	ExpectedText       string
	NotifyOnRecovery   bool
}

type UpdateMonitorParams struct {
	ID int64
	CreateMonitorParams
}

type MonitorHourlyRollup struct {
	MonitorID      int64
	HourBucket     time.Time
	TotalChecks    int
	UpChecks       int
	DownChecks     int
	DegradedChecks int
	LatencySumMS   int
	LatencyMinMS   int
	LatencyMaxMS   int
	FirstCheckedAt time.Time
	LastCheckedAt  time.Time
}

type GroupOrder struct {
	Name      string
	SortOrder int
}

type MonitorGroup struct {
	Name      string
	IconSlug  string
	SortOrder int
}

func (s *Store) CreateMonitor(ctx context.Context, params CreateMonitorParams) (int64, error) {
	if err := validateCreateMonitorParams(params); err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	if err := s.ensureMonitorGroupExists(ctx, strings.TrimSpace(params.Group)); err != nil {
		return 0, err
	}
	nextSortOrder, err := s.nextMonitorSortOrder(ctx)
	if err != nil {
		return 0, err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO monitors (
	name, group_name, sort_order, kind, target, interval_seconds, timeout_seconds, enabled,
    tls_mode, expected_status_code, expected_text, notify_on_recovery,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, params.Name, strings.TrimSpace(params.Group), nextSortOrder, string(params.Kind), params.Target, int(params.Interval.Seconds()), int(params.Timeout.Seconds()), boolToInt(params.Enabled), string(params.TLSMode), params.ExpectedStatusCode, strings.TrimSpace(params.ExpectedText), boolToInt(params.NotifyOnRecovery), now, now)
	if err != nil {
		return 0, fmt.Errorf("create monitor: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read monitor id: %w", err)
	}

	return id, nil
}

func (s *Store) UpdateMonitor(ctx context.Context, params UpdateMonitorParams) error {
	if params.ID <= 0 {
		return errors.New("monitor id is required")
	}

	if err := validateCreateMonitorParams(params.CreateMonitorParams); err != nil {
		return err
	}

	now := time.Now().UTC()
	if err := s.ensureMonitorGroupExists(ctx, strings.TrimSpace(params.Group)); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE monitors
SET
    name = ?,
	group_name = ?,
    kind = ?,
    target = ?,
    interval_seconds = ?,
    timeout_seconds = ?,
    enabled = ?,
    tls_mode = ?,
    expected_status_code = ?,
    expected_text = ?,
    notify_on_recovery = ?,
    updated_at = ?
WHERE id = ?
`,
		params.Name,
		strings.TrimSpace(params.Group),
		string(params.Kind),
		params.Target,
		int(params.Interval.Seconds()),
		int(params.Timeout.Seconds()),
		boolToInt(params.Enabled),
		string(params.TLSMode),
		params.ExpectedStatusCode,
		strings.TrimSpace(params.ExpectedText),
		boolToInt(params.NotifyOnRecovery),
		now,
		params.ID,
	)
	if err != nil {
		return fmt.Errorf("update monitor: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update monitor rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (s *Store) DeleteMonitor(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM monitors WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete monitor: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete monitor rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (s *Store) DeleteMonitorGroup(ctx context.Context, groupName string) error {
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return errors.New("group name is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete monitor group transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM monitors WHERE TRIM(group_name) = ?`, groupName); err != nil {
		return fmt.Errorf("delete monitors in group: %w", err)
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM monitor_groups WHERE name = ?`, groupName)
	if err != nil {
		return fmt.Errorf("delete monitor group metadata: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete monitor group rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete monitor group transaction: %w", err)
	}

	return nil
}

func (s *Store) SetMonitorEnabled(ctx context.Context, id int64, enabled bool) error {
	if id <= 0 {
		return errors.New("monitor id is required")
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE monitors
SET enabled = ?, updated_at = ?
WHERE id = ?
`, boolToInt(enabled), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("set monitor enabled: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("set monitor enabled rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (s *Store) UpdateMonitorTarget(ctx context.Context, id int64, target string) error {
	var kindRaw string
	var tlsModeRaw string
	err := s.db.QueryRowContext(ctx, `
SELECT kind, tls_mode
FROM monitors
WHERE id = ?
`, id).Scan(&kindRaw, &tlsModeRaw)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.ErrNoRows
		}
		return fmt.Errorf("load monitor for target update: %w", err)
	}

	kind := monitor.Kind(kindRaw)
	tlsMode := monitor.TLSMode(tlsModeRaw)
	if err := validateMonitorKindSettings(kind, strings.TrimSpace(target), tlsMode, nil); err != nil {
		return err
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE monitors
SET target = ?, updated_at = ?
WHERE id = ?
`, strings.TrimSpace(target), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update monitor target: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update monitor target rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (s *Store) ListMonitorSnapshots(ctx context.Context) ([]monitor.Snapshot, error) {
	snapshots, err := s.listMonitorSnapshotsWithResults(ctx)
	if err == nil {
		return snapshots, nil
	}
	if !isMalformedSQLiteError(err) {
		return nil, err
	}

	return s.listMonitorSnapshotsWithoutResults(ctx)
}

func (s *Store) listMonitorSnapshotsWithResults(ctx context.Context) ([]monitor.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
    m.id,
    m.name,
	m.group_name,
	m.sort_order,
    m.kind,
    m.target,
    m.interval_seconds,
    m.timeout_seconds,
    m.enabled,
    m.tls_mode,
    m.expected_status_code,
    m.expected_text,
    m.notify_on_recovery,
    m.created_at,
    m.updated_at,
    r.id,
    r.checked_at,
    r.status,
    r.latency_ms,
    r.message,
    r.http_status_code,
    r.tls_valid,
    r.tls_not_after,
    r.tls_days_remaining
FROM monitors m
LEFT JOIN monitor_results r ON r.id = (
    SELECT mr.id
    FROM monitor_results mr
    WHERE mr.monitor_id = m.id
    ORDER BY mr.checked_at DESC, mr.id DESC
    LIMIT 1
)
ORDER BY m.sort_order ASC, m.id ASC
`)
	if err != nil {
		return nil, fmt.Errorf("list monitors: %w", err)
	}
	defer rows.Close()

	var snapshots []monitor.Snapshot
	for rows.Next() {
		snapshot, err := scanMonitorSnapshot(rows)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate monitors: %w", err)
	}

	return snapshots, nil
}

func (s *Store) listMonitorSnapshotsWithoutResults(ctx context.Context) ([]monitor.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
    id,
    name,
    group_name,
    sort_order,
    kind,
    target,
    interval_seconds,
    timeout_seconds,
    enabled,
    tls_mode,
    expected_status_code,
    expected_text,
    notify_on_recovery,
    created_at,
    updated_at
FROM monitors
ORDER BY sort_order ASC, id ASC
`)
	if err != nil {
		return nil, fmt.Errorf("list monitors fallback: %w", err)
	}
	defer rows.Close()

	snapshots := make([]monitor.Snapshot, 0)
	for rows.Next() {
		var (
			item               monitor.Snapshot
			kindRaw            string
			tlsModeRaw         string
			intervalSeconds    int
			timeoutSeconds     int
			enabledRaw         int
			notifyOnRecovery   int
			expectedStatusCode sql.NullInt64
		)

		if err := rows.Scan(
			&item.Monitor.ID,
			&item.Monitor.Name,
			&item.Monitor.Group,
			&item.Monitor.SortOrder,
			&kindRaw,
			&item.Monitor.Target,
			&intervalSeconds,
			&timeoutSeconds,
			&enabledRaw,
			&tlsModeRaw,
			&expectedStatusCode,
			&item.Monitor.ExpectedText,
			&notifyOnRecovery,
			&item.Monitor.CreatedAt,
			&item.Monitor.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan monitor fallback: %w", err)
		}

		item.Monitor.Kind = monitor.Kind(kindRaw)
		item.Monitor.TLSMode = monitor.TLSMode(tlsModeRaw)
		item.Monitor.Interval = time.Duration(intervalSeconds) * time.Second
		item.Monitor.Timeout = time.Duration(timeoutSeconds) * time.Second
		item.Monitor.Enabled = enabledRaw == 1
		item.Monitor.NotifyOnRecovery = notifyOnRecovery == 1
		if expectedStatusCode.Valid {
			value := int(expectedStatusCode.Int64)
			item.Monitor.ExpectedStatusCode = &value
		}

		snapshots = append(snapshots, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate monitors fallback: %w", err)
	}

	return snapshots, nil
}

func isMalformedSQLiteError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database disk image is malformed")
}

func (s *Store) ListMonitorHourlyRollupsSince(ctx context.Context, since time.Time) ([]MonitorHourlyRollup, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
    monitor_id,
    hour_bucket,
    total_checks,
    up_checks,
    down_checks,
    degraded_checks,
    latency_sum_ms,
    latency_min_ms,
    latency_max_ms,
    first_checked_at,
    last_checked_at
FROM monitor_hourly_rollups
WHERE hour_bucket >= ?
ORDER BY hour_bucket ASC, monitor_id ASC
`, since.UTC())
	if err != nil {
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
			&item.LatencySumMS,
			&item.LatencyMinMS,
			&item.LatencyMaxMS,
			&item.FirstCheckedAt,
			&item.LastCheckedAt,
		); err != nil {
			return nil, fmt.Errorf("scan monitor hourly rollup: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate monitor hourly rollups: %w", err)
	}

	return items, nil
}

func (s *Store) ListMonitorGroups(ctx context.Context) ([]string, error) {
	items, err := s.ListMonitorGroupMetadata(ctx)
	if err != nil {
		return nil, err
	}
	groups := make([]string, 0, len(items))
	for _, item := range items {
		groups = append(groups, item.Name)
	}
	return groups, nil
}

func (s *Store) ListMonitorGroupMetadata(ctx context.Context) ([]MonitorGroup, error) {
	if err := s.syncMonitorGroups(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT name, icon_slug, sort_order
FROM monitor_groups
ORDER BY sort_order ASC, name COLLATE NOCASE ASC
`)
	if err != nil {
		return nil, fmt.Errorf("list monitor group metadata: %w", err)
	}
	defer rows.Close()

	groups := make([]MonitorGroup, 0)
	for rows.Next() {
		var group MonitorGroup
		if err := rows.Scan(&group.Name, &group.IconSlug, &group.SortOrder); err != nil {
			return nil, fmt.Errorf("scan monitor group metadata: %w", err)
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate monitor group metadata: %w", err)
	}

	return groups, nil
}

func (s *Store) MoveMonitorGroup(ctx context.Context, groupName string, direction string) error {
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return errors.New("group name is required")
	}
	if err := s.ensureMonitorGroupExists(ctx, groupName); err != nil {
		return err
	}
	if err := s.syncMonitorGroups(ctx); err != nil {
		return err
	}

	var currentSort int
	err := s.db.QueryRowContext(ctx, `SELECT sort_order FROM monitor_groups WHERE name = ?`, groupName).Scan(&currentSort)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.ErrNoRows
		}
		return fmt.Errorf("load monitor group for move: %w", err)
	}

	comparator := "<"
	order := "DESC"
	if direction == "down" {
		comparator = ">"
		order = "ASC"
	} else if direction != "up" {
		return errors.New("invalid move direction")
	}

	var otherName string
	var otherSort int
	err = s.db.QueryRowContext(ctx, `
SELECT name, sort_order
FROM monitor_groups
WHERE sort_order `+comparator+` ?
ORDER BY sort_order `+order+`, name COLLATE NOCASE `+order+`
LIMIT 1
`, currentSort).Scan(&otherName, &otherSort)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("find monitor group move target: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin monitor group move transaction: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE monitor_groups SET sort_order = ?, updated_at = ? WHERE name = ?`, otherSort, now, groupName); err != nil {
		return fmt.Errorf("update current group sort order: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE monitor_groups SET sort_order = ?, updated_at = ? WHERE name = ?`, currentSort, now, otherName); err != nil {
		return fmt.Errorf("update other group sort order: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monitor group move transaction: %w", err)
	}

	return nil
}

func (s *Store) UpdateMonitorGroupIcon(ctx context.Context, groupName string, iconSlug string) error {
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return errors.New("group name is required")
	}
	if err := s.ensureMonitorGroupExists(ctx, groupName); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE monitor_groups
SET icon_slug = ?, updated_at = ?
WHERE name = ?
`, strings.TrimSpace(iconSlug), time.Now().UTC(), groupName)
	if err != nil {
		return fmt.Errorf("update monitor group icon: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update monitor group icon rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ReorderMonitorGroups(ctx context.Context, draggedGroup string, targetGroup string) error {
	draggedGroup = strings.TrimSpace(draggedGroup)
	targetGroup = strings.TrimSpace(targetGroup)
	if draggedGroup == "" || targetGroup == "" {
		return errors.New("dragged and target groups are required")
	}
	if err := s.ensureMonitorGroupExists(ctx, draggedGroup); err != nil {
		return err
	}
	if err := s.ensureMonitorGroupExists(ctx, targetGroup); err != nil {
		return err
	}
	items, err := s.ListMonitorGroupMetadata(ctx)
	if err != nil {
		return err
	}
	ordered := make([]string, 0, len(items))
	for _, item := range items {
		ordered = append(ordered, item.Name)
	}
	reordered, ok := reorderStrings(ordered, draggedGroup, targetGroup)
	if !ok {
		return sql.ErrNoRows
	}
	return s.setMonitorGroupOrder(ctx, reordered)
}

func (s *Store) syncMonitorGroups(ctx context.Context) error {
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
INSERT OR IGNORE INTO monitor_groups (name, icon_slug, sort_order, created_at, updated_at)
SELECT
	TRIM(group_name) AS name,
	'',
	COALESCE((SELECT MAX(sort_order) FROM monitor_groups), 0) + ROW_NUMBER() OVER (ORDER BY TRIM(group_name) COLLATE NOCASE ASC),
	?,
	?
FROM monitors
WHERE TRIM(group_name) <> ''
GROUP BY TRIM(group_name)
`, now, now); err != nil {
		return fmt.Errorf("sync monitor groups insert: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT name
FROM monitor_groups
ORDER BY sort_order ASC, name COLLATE NOCASE ASC
`)
	if err != nil {
		return fmt.Errorf("select monitor groups for normalize: %w", err)
	}
	defer rows.Close()

	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan monitor group for normalize: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate monitor groups for normalize: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close monitor groups normalize rows: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin monitor groups normalize transaction: %w", err)
	}
	defer tx.Rollback()
	for idx, name := range names {
		if _, err := tx.ExecContext(ctx, `UPDATE monitor_groups SET sort_order = ? WHERE name = ?`, idx+1, name); err != nil {
			return fmt.Errorf("update monitor group sort order during normalize: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monitor groups normalize transaction: %w", err)
	}

	return nil
}

func (s *Store) ensureMonitorGroupExists(ctx context.Context, groupName string) error {
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return nil
	}

	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO monitor_groups (name, icon_slug, sort_order, created_at, updated_at)
VALUES (?, '', COALESCE((SELECT MAX(sort_order) + 1 FROM monitor_groups), 1), ?, ?)
ON CONFLICT(name) DO UPDATE SET updated_at = excluded.updated_at
`, groupName, now, now)
	if err != nil {
		return fmt.Errorf("ensure monitor group exists: %w", err)
	}
	return nil
}

func (s *Store) nextMonitorSortOrder(ctx context.Context) (int, error) {
	var next int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(sort_order), 0) + 1 FROM monitors`).Scan(&next)
	if err != nil {
		return 0, fmt.Errorf("next monitor sort order: %w", err)
	}
	return next, nil
}

func (s *Store) SwapMonitors(ctx context.Context, firstID int64, secondID int64) error {
	if firstID <= 0 || secondID <= 0 {
		return errors.New("both monitor ids are required")
	}
	var firstSort int
	err := s.db.QueryRowContext(ctx, `SELECT sort_order FROM monitors WHERE id = ?`, firstID).Scan(&firstSort)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.ErrNoRows
		}
		return fmt.Errorf("load first monitor sort order: %w", err)
	}
	var secondSort int
	err = s.db.QueryRowContext(ctx, `SELECT sort_order FROM monitors WHERE id = ?`, secondID).Scan(&secondSort)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.ErrNoRows
		}
		return fmt.Errorf("load second monitor sort order: %w", err)
	}
	return s.swapMonitorSortOrder(ctx, firstID, firstSort, secondID, secondSort)
}

func (s *Store) ReorderMonitors(ctx context.Context, orderedMonitorIDs []int64) error {
	if len(orderedMonitorIDs) < 2 {
		return nil
	}
	placeholders := make([]string, 0, len(orderedMonitorIDs))
	args := make([]any, 0, len(orderedMonitorIDs))
	for _, id := range orderedMonitorIDs {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, sort_order
FROM monitors
WHERE id IN (`+strings.Join(placeholders, ",")+`)
ORDER BY sort_order ASC, id ASC
`, args...)
	if err != nil {
		return fmt.Errorf("load monitor sort orders for reorder: %w", err)
	}
	defer rows.Close()

	sortOrders := make([]int, 0, len(orderedMonitorIDs))
	count := 0
	for rows.Next() {
		var id int64
		var sortOrder int
		if err := rows.Scan(&id, &sortOrder); err != nil {
			return fmt.Errorf("scan monitor sort order for reorder: %w", err)
		}
		sortOrders = append(sortOrders, sortOrder)
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate monitor sort orders for reorder: %w", err)
	}
	if count != len(orderedMonitorIDs) {
		return sql.ErrNoRows
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin monitor reorder transaction: %w", err)
	}
	defer tx.Rollback()

	for idx, id := range orderedMonitorIDs {
		if _, err := tx.ExecContext(ctx, `UPDATE monitors SET sort_order = ? WHERE id = ?`, sortOrders[idx], id); err != nil {
			return fmt.Errorf("update monitor sort order during reorder: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monitor reorder transaction: %w", err)
	}
	return nil
}

func (s *Store) setMonitorGroupOrder(ctx context.Context, orderedNames []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin monitor group reorder transaction: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	for idx, name := range orderedNames {
		if _, err := tx.ExecContext(ctx, `UPDATE monitor_groups SET sort_order = ?, updated_at = ? WHERE name = ?`, idx+1, now, name); err != nil {
			return fmt.Errorf("update monitor group order: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monitor group reorder transaction: %w", err)
	}
	return nil
}

func reorderStrings(items []string, dragged string, target string) ([]string, bool) {
	if dragged == target {
		return items, true
	}
	draggedIndex := -1
	targetIndex := -1
	for idx, item := range items {
		if item == dragged {
			draggedIndex = idx
		}
		if item == target {
			targetIndex = idx
		}
	}
	if draggedIndex == -1 || targetIndex == -1 {
		return nil, false
	}
	reordered := make([]string, 0, len(items))
	for idx, item := range items {
		if idx == draggedIndex {
			continue
		}
		reordered = append(reordered, item)
	}
	if draggedIndex < targetIndex {
		targetIndex--
	}
	updated := make([]string, 0, len(items))
	updated = append(updated, reordered[:targetIndex]...)
	updated = append(updated, dragged)
	updated = append(updated, reordered[targetIndex:]...)
	return updated, true
}

func reorderInt64(items []int64, dragged int64, target int64) ([]int64, bool) {
	if dragged == target {
		return items, true
	}
	draggedIndex := -1
	targetIndex := -1
	for idx, item := range items {
		if item == dragged {
			draggedIndex = idx
		}
		if item == target {
			targetIndex = idx
		}
	}
	if draggedIndex == -1 || targetIndex == -1 {
		return nil, false
	}
	reordered := make([]int64, 0, len(items))
	for idx, item := range items {
		if idx == draggedIndex {
			continue
		}
		reordered = append(reordered, item)
	}
	if draggedIndex < targetIndex {
		targetIndex--
	}
	updated := make([]int64, 0, len(items))
	updated = append(updated, reordered[:targetIndex]...)
	updated = append(updated, dragged)
	updated = append(updated, reordered[targetIndex:]...)
	return updated, true
}

func (s *Store) swapMonitorSortOrder(ctx context.Context, firstID int64, firstSort int, secondID int64, secondSort int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin monitor move transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `UPDATE monitors SET sort_order = ? WHERE id = ?`, secondSort, firstID); err != nil {
		return fmt.Errorf("update first monitor sort order: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE monitors SET sort_order = ? WHERE id = ?`, firstSort, secondID); err != nil {
		return fmt.Errorf("update second monitor sort order: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monitor move transaction: %w", err)
	}
	return nil
}

func (s *Store) SaveMonitorResult(ctx context.Context, result monitor.Result) error {
	checkedAt := result.CheckedAt.UTC()
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin result transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
INSERT INTO monitor_results (
    monitor_id, checked_at, status, latency_ms, message,
    http_status_code, tls_valid, tls_not_after, tls_days_remaining
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`, result.MonitorID, checkedAt, string(result.Status), int(result.Latency.Milliseconds()), strings.TrimSpace(result.Message), result.HTTPStatusCode, nullableBoolInt(result.TLSValid), result.TLSNotAfter, result.TLSDaysRemaining)
	if err != nil {
		return fmt.Errorf("save monitor result: %w", err)
	}

	if err := upsertHourlyRollup(ctx, tx, result.MonitorID, checkedAt, result.Status, int(result.Latency.Milliseconds())); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit monitor result transaction: %w", err)
	}

	return nil
}

func (s *Store) RecordMonitorState(ctx context.Context, monitorID int64, status monitor.Status, message string, checkedAt time.Time) error {
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}

	if status == monitor.StatusUp {
		result, err := s.db.ExecContext(ctx, `
UPDATE incidents
SET resolved_at = ?, last_state = 'up'
WHERE monitor_id = ? AND resolved_at IS NULL
`, checkedAt.UTC(), monitorID)
		if err != nil {
			return fmt.Errorf("resolve incident: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("resolve incident rows affected: %w", err)
		}
		if affected > 0 {
			return nil
		}

		var fallbackID int64
		var fallbackResolvedAt sql.NullTime
		err = s.db.QueryRowContext(ctx, `
SELECT id, resolved_at
FROM incidents
WHERE monitor_id = ?
ORDER BY started_at DESC
LIMIT 1
`, monitorID).Scan(&fallbackID, &fallbackResolvedAt)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil
			}
			return fmt.Errorf("fallback lookup incident: %w", err)
		}
		if fallbackResolvedAt.Valid {
			return nil
		}

		_, err = s.db.ExecContext(ctx, `
UPDATE incidents
SET resolved_at = ?, last_state = 'up'
WHERE id = ?
`, checkedAt.UTC(), fallbackID)
		if err != nil {
			return fmt.Errorf("fallback resolve incident: %w", err)
		}
		return nil
	}

	var incidentID int64
	err := s.db.QueryRowContext(ctx, `
SELECT id
FROM incidents
WHERE monitor_id = ? AND resolved_at IS NULL
ORDER BY started_at DESC
LIMIT 1
`, monitorID).Scan(&incidentID)
	if err != nil {
		if err == sql.ErrNoRows {
			_, insertErr := s.db.ExecContext(ctx, `
INSERT INTO incidents (monitor_id, started_at, resolved_at, cause, last_state)
VALUES (?, ?, NULL, ?, ?)
`, monitorID, checkedAt.UTC(), strings.TrimSpace(message), string(status))
			if insertErr != nil {
				return fmt.Errorf("create incident: %w", insertErr)
			}
			return nil
		}
		return fmt.Errorf("lookup open incident: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
UPDATE incidents
SET cause = ?, last_state = ?
WHERE id = ?
`, strings.TrimSpace(message), string(status), incidentID)
	if err != nil {
		return fmt.Errorf("update incident: %w", err)
	}

	return nil
}

func validateCreateMonitorParams(params CreateMonitorParams) error {
	if strings.TrimSpace(params.Name) == "" {
		return errors.New("monitor name is required")
	}
	if len([]rune(strings.TrimSpace(params.Group))) > 80 {
		return errors.New("monitor group must not exceed 80 characters")
	}
	if params.Interval < 15*time.Second {
		return errors.New("interval must be at least 15 seconds")
	}
	if params.Timeout < 1*time.Second {
		return errors.New("timeout must be at least 1 second")
	}
	if params.Timeout > params.Interval {
		return errors.New("timeout must not exceed interval")
	}
	return validateMonitorKindSettings(params.Kind, params.Target, params.TLSMode, params.ExpectedStatusCode)
}

func validateMonitorKindSettings(kind monitor.Kind, target string, tlsMode monitor.TLSMode, expectedStatusCode *int) error {
	switch kind {
	case monitor.KindHTTPS:
		parsedTarget, err := url.Parse(target)
		if err != nil || parsedTarget == nil || parsedTarget.Scheme != "https" || parsedTarget.Host == "" {
			return errors.New("target must be a valid https URL")
		}
		if tlsMode != "" && tlsMode != monitor.TLSModeTLS {
			return errors.New("https monitors only support tls mode")
		}
	case monitor.KindTCP:
		if _, _, err := net.SplitHostPort(strings.TrimSpace(target)); err != nil {
			return errors.New("target must be a valid host:port for TCP monitors")
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
		if tlsMode != "" && tlsMode != monitor.TLSModeNone {
			return errors.New("tcp monitors do not support tls mode")
		}
	case monitor.KindICMP:
		if strings.TrimSpace(target) == "" {
			return errors.New("target must be a valid hostname or IP for ICMP monitors")
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
		if tlsMode != "" && tlsMode != monitor.TLSModeNone {
			return errors.New("icmp monitors do not support tls mode")
		}
	case monitor.KindSMTP, monitor.KindIMAP, monitor.KindDovecot:
		if _, _, err := net.SplitHostPort(strings.TrimSpace(target)); err != nil {
			return errors.New("target must be a valid host:port for mail monitors")
		}
		if expectedStatusCode != nil {
			return errors.New("expected HTTP status is only valid for HTTPS monitors")
		}
		if tlsMode != monitor.TLSModeTLS && tlsMode != monitor.TLSModeSTARTTLS {
			return errors.New("mail monitors require tls or starttls mode")
		}
	default:
		return fmt.Errorf("unsupported monitor kind %q", kind)
	}

	return nil
}

func scanMonitorSnapshot(scanner interface{ Scan(dest ...any) error }) (monitor.Snapshot, error) {
	var item monitor.Snapshot
	var intervalSeconds int
	var timeoutSeconds int
	var enabled int
	var notifyOnRecovery int
	var sortOrder int
	var kind string
	var tlsMode string
	var expectedStatusCode sql.NullInt64
	var expectedText string
	var resultID sql.NullInt64
	var checkedAt sql.NullTime
	var status sql.NullString
	var latencyMS sql.NullInt64
	var message sql.NullString
	var httpStatusCode sql.NullInt64
	var tlsValid sql.NullInt64
	var tlsNotAfter sql.NullTime
	var tlsDaysRemaining sql.NullInt64

	if err := scanner.Scan(
		&item.Monitor.ID,
		&item.Monitor.Name,
		&item.Monitor.Group,
		&sortOrder,
		&kind,
		&item.Monitor.Target,
		&intervalSeconds,
		&timeoutSeconds,
		&enabled,
		&tlsMode,
		&expectedStatusCode,
		&expectedText,
		&notifyOnRecovery,
		&item.Monitor.CreatedAt,
		&item.Monitor.UpdatedAt,
		&resultID,
		&checkedAt,
		&status,
		&latencyMS,
		&message,
		&httpStatusCode,
		&tlsValid,
		&tlsNotAfter,
		&tlsDaysRemaining,
	); err != nil {
		return monitor.Snapshot{}, fmt.Errorf("scan monitor snapshot: %w", err)
	}

	item.Monitor.Kind = monitor.Kind(kind)
	item.Monitor.SortOrder = sortOrder
	item.Monitor.Interval = time.Duration(intervalSeconds) * time.Second
	item.Monitor.Timeout = time.Duration(timeoutSeconds) * time.Second
	item.Monitor.Enabled = enabled == 1
	item.Monitor.TLSMode = monitor.TLSMode(tlsMode)
	item.Monitor.ExpectedText = expectedText
	item.Monitor.NotifyOnRecovery = notifyOnRecovery == 1
	if expectedStatusCode.Valid {
		value := int(expectedStatusCode.Int64)
		item.Monitor.ExpectedStatusCode = &value
	}

	if resultID.Valid {
		result := &monitor.Result{
			ID:        resultID.Int64,
			MonitorID: item.Monitor.ID,
			CheckedAt: checkedAt.Time,
			Status:    monitor.Status(status.String),
			Latency:   time.Duration(latencyMS.Int64) * time.Millisecond,
			Message:   message.String,
		}
		if httpStatusCode.Valid {
			value := int(httpStatusCode.Int64)
			result.HTTPStatusCode = &value
		}
		if tlsValid.Valid {
			value := tlsValid.Int64 == 1
			result.TLSValid = &value
		}
		if tlsNotAfter.Valid {
			value := tlsNotAfter.Time
			result.TLSNotAfter = &value
		}
		if tlsDaysRemaining.Valid {
			value := int(tlsDaysRemaining.Int64)
			result.TLSDaysRemaining = &value
		}
		item.LastResult = result
	}

	return item, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableBoolInt(value *bool) any {
	if value == nil {
		return nil
	}
	if *value {
		return 1
	}
	return 0
}
