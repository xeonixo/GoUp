package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

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
