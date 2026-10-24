package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"goup/internal/monitor"
	_ "modernc.org/sqlite"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Store struct {
	db *sql.DB

	maintenanceMu     sync.Mutex
	maintenanceCache  monitor.MaintenanceSet
	maintenanceLoaded time.Time
}

type DashboardStats struct {
	MonitorCount        int
	EnabledMonitorCount int
	OpenIncidentCount   int
}

func Open(ctx context.Context, path string) (*Store, error) {
	defer SecureDBFiles(path)
	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		if isMalformedSQLiteError(err) {
			store := &Store{db: db}
			if initErr := store.initSchema(ctx); initErr != nil {
				db.Close()
				if _, recreateErr := recreateStoreAfterCorruption(ctx, path); recreateErr == nil {
					return Open(ctx, path)
				} else {
					return nil, fmt.Errorf("repair malformed sqlite database after ping failure: %w (recreate failed: %v)", initErr, recreateErr)
				}
			}
			return store, nil
		}
		db.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}

	store := &Store{db: db}
	if err := store.initSchema(ctx); err != nil {
		if isMalformedSQLiteError(err) {
			db.Close()
			backupPath, recreateErr := recreateStoreAfterCorruption(ctx, path)
			if recreateErr != nil {
				return nil, fmt.Errorf("initialize schema: %w (recreate failed: %v)", err, recreateErr)
			}
			_ = backupPath
			return Open(ctx, path)
		}
		db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func recreateStoreAfterCorruption(ctx context.Context, path string) (string, error) {
	backupPath, err := quarantineSQLiteFile(path)
	if err != nil {
		return "", err
	}
	recreated, err := OpenFresh(ctx, path)
	if err != nil {
		return backupPath, err
	}
	if closeErr := recreated.Close(); closeErr != nil {
		return backupPath, closeErr
	}
	return backupPath, nil
}

func OpenFresh(ctx context.Context, path string) (*Store, error) {
	defer SecureDBFiles(path)
	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open fresh sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	store := &Store{db: db}
	if err := store.initSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func quarantineSQLiteFile(path string) (string, error) {
	timestamp := time.Now().UTC().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.corrupt-%s", path, timestamp)
	if err := os.Rename(path, backupPath); err != nil {
		return "", fmt.Errorf("quarantine corrupted sqlite db: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		source := path + suffix
		if _, err := os.Stat(source); err == nil {
			if renameErr := os.Rename(source, backupPath+suffix); renameErr != nil {
				return backupPath, fmt.Errorf("quarantine corrupted sqlite sidecar %s: %w", suffix, renameErr)
			}
		}
	}
	return backupPath, nil
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

func sqliteDSN(path string) string {
	values := url.Values{}
	values.Add("_pragma", "foreign_keys(1)")
	values.Add("_pragma", "busy_timeout(5000)")
	values.Add("_pragma", "journal_mode(WAL)")
	values.Add("_pragma", "synchronous(FULL)")
	values.Add("_pragma", "wal_autocheckpoint(1000)")

	u := &url.URL{
		Scheme:   "file",
		Path:     filepath.Clean(path),
		RawQuery: values.Encode(),
	}
	return u.String()
}

// SecureDBFiles restricts a SQLite database and its sidecar files to the
// owner (0600). Errors are ignored: this is best-effort hardening.
func SecureDBFiles(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			_ = os.Chmod(path+suffix, 0o600)
		}
	}
}

// HardenDataDir makes the data directory owner-only (0700) and every database
// file below it owner-read/write only (0600). Best-effort.
func HardenDataDir(root string) {
	root = strings.TrimSpace(root)
	if root == "" {
		return
	}
	_ = os.Chmod(root, 0o700)
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && strings.Count(strings.TrimPrefix(p, root), string(os.PathSeparator)) <= 2 {
				// Tenant directories contain databases and uploaded icons.
				_ = os.Chmod(p, 0o700)
			}
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".db") || strings.HasSuffix(name, ".db-wal") || strings.HasSuffix(name, ".db-shm") || strings.Contains(name, ".db.corrupt-") {
			_ = os.Chmod(p, 0o600)
		}
		return nil
	})
}
