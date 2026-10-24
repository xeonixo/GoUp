package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

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

func (s *Store) ensureMonitorExecutorColumns(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(monitors)`)
	if err != nil {
		return fmt.Errorf("inspect monitor columns for executor: %w", err)
	}

	hasExecutorKind := false
	hasExecutorRef := false
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("scan monitor executor column: %w", err)
		}
		switch name {
		case "executor_kind":
			hasExecutorKind = true
		case "executor_ref":
			hasExecutorRef = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate monitor columns for executor: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close monitor executor inspection: %w", err)
	}

	if !hasExecutorKind {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE monitors ADD COLUMN executor_kind TEXT NOT NULL DEFAULT 'local'`); err != nil {
			return fmt.Errorf("add monitor executor_kind column: %w", err)
		}
	}
	if !hasExecutorRef {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE monitors ADD COLUMN executor_ref TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add monitor executor_ref column: %w", err)
		}
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE monitors SET executor_kind = 'local' WHERE TRIM(executor_kind) = ''`); err != nil {
		return fmt.Errorf("normalize monitor executor_kind values: %w", err)
	}

	return nil
}

func (s *Store) ensureMonitorRetryColumns(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(monitors)`)
	if err != nil {
		return fmt.Errorf("inspect monitor columns for retry: %w", err)
	}

	hasRetryCount := false
	hasRetryInterval := false
	hasMutedUntil := false
	hasCertWarningDays := false
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("scan monitor retry column: %w", err)
		}
		switch name {
		case "retry_count":
			hasRetryCount = true
		case "retry_interval_seconds":
			hasRetryInterval = true
		case "muted_until":
			hasMutedUntil = true
		case "cert_warning_days":
			hasCertWarningDays = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate monitor columns for retry: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close monitor retry inspection: %w", err)
	}

	if !hasRetryCount {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE monitors ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add monitor retry_count column: %w", err)
		}
	}
	if !hasRetryInterval {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE monitors ADD COLUMN retry_interval_seconds INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add monitor retry_interval_seconds column: %w", err)
		}
	}
	if !hasMutedUntil {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE monitors ADD COLUMN muted_until DATETIME`); err != nil {
			return fmt.Errorf("add monitor muted_until column: %w", err)
		}
	}
	if !hasCertWarningDays {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE monitors ADD COLUMN cert_warning_days INTEGER NOT NULL DEFAULT 7`); err != nil {
			return fmt.Errorf("add monitor cert_warning_days column: %w", err)
		}
	}

	return nil
}
