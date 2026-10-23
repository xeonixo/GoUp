package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	sqliteAutoVacuumIncremental = 2
	// compactionSpaceHeadroom is required on top of twice the live data size,
	// because VACUUM writes a full copy of the database into the WAL first.
	compactionSpaceHeadroom = 64 << 20
)

// ErrInsufficientDiskSpace is returned when a full VACUUM was skipped because
// the database directory does not have enough free space for the rewrite.
var ErrInsufficientDiskSpace = errors.New("insufficient free disk space for sqlite vacuum")

// compactDatabase switches a database to incremental auto-vacuum once, which
// needs a full VACUUM, and afterwards hands free pages back to the filesystem
// incrementally. Without this, deleted rows never shrink the database file.
// It reports whether the one-time full VACUUM ran.
func compactDatabase(ctx context.Context, db *sql.DB) (bool, error) {
	var autoVacuum int
	if err := db.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&autoVacuum); err != nil {
		return false, fmt.Errorf("read auto_vacuum mode: %w", err)
	}

	if autoVacuum == sqliteAutoVacuumIncremental {
		if _, err := db.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
			return false, fmt.Errorf("incremental vacuum: %w", err)
		}
		return false, nil
	}

	if err := ensureVacuumSpace(ctx, db); err != nil {
		return false, err
	}
	if _, err := db.ExecContext(ctx, `PRAGMA auto_vacuum = INCREMENTAL`); err != nil {
		return false, fmt.Errorf("enable incremental auto_vacuum: %w", err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
		return false, fmt.Errorf("vacuum: %w", err)
	}
	// VACUUM leaves a WAL as large as the database; truncate it right away.
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return true, fmt.Errorf("checkpoint after vacuum: %w", err)
	}
	return true, nil
}

func ensureVacuumSpace(ctx context.Context, db *sql.DB) error {
	path, err := mainDatabaseFile(ctx, db)
	if err != nil {
		return err
	}
	if path == "" {
		// In-memory or temporary database: nothing on disk to check.
		return nil
	}

	var pageCount, freelistCount, pageSize int64
	if err := db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount); err != nil {
		return fmt.Errorf("read page_count: %w", err)
	}
	if err := db.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&freelistCount); err != nil {
		return fmt.Errorf("read freelist_count: %w", err)
	}
	if err := db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return fmt.Errorf("read page_size: %w", err)
	}

	required := uint64((pageCount-freelistCount)*pageSize)*2 + compactionSpaceHeadroom
	available, err := freeDiskSpace(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("read free disk space: %w", err)
	}
	if available < required {
		return fmt.Errorf("%w: need %d MiB, have %d MiB in %s", ErrInsufficientDiskSpace, required>>20, available>>20, filepath.Dir(path))
	}
	return nil
}

func mainDatabaseFile(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA database_list`)
	if err != nil {
		return "", fmt.Errorf("read database_list: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return "", fmt.Errorf("scan database_list: %w", err)
		}
		if name == "main" {
			return strings.TrimSpace(file), nil
		}
	}
	return "", rows.Err()
}
