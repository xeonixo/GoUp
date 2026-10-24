package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type GroupOrder struct {
	Name      string
	SortOrder int
}

type MonitorGroup struct {
	Name      string
	IconSlug  string
	SortOrder int
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

func (s *Store) RenameMonitorGroup(ctx context.Context, oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == "" || newName == "" {
		return errors.New("group name is required")
	}
	if oldName == newName {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `
INSERT INTO monitor_groups (name, icon_slug, sort_order, created_at, updated_at)
SELECT ?, icon_slug, sort_order, created_at, ?
FROM monitor_groups WHERE name = ?
`, newName, now, oldName); err != nil {
		return fmt.Errorf("insert renamed group: %w", err)
	}
	if _, err = tx.ExecContext(ctx,
		`UPDATE monitors SET group_name = ?, updated_at = ? WHERE TRIM(group_name) = ?`,
		newName, now, oldName,
	); err != nil {
		return fmt.Errorf("update monitor group_name: %w", err)
	}
	if _, err = tx.ExecContext(ctx,
		`DELETE FROM monitor_groups WHERE name = ?`, oldName,
	); err != nil {
		return fmt.Errorf("delete old group: %w", err)
	}
	return tx.Commit()
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
