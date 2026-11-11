package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BackupDatabase writes a consistent online snapshot of db to destPath using
// SQLite's VACUUM INTO. Parent directories of destPath are created as needed.
// The destination file must not already exist.
func BackupDatabase(ctx context.Context, db *sql.DB, destPath string) error {
	if db == nil {
		return fmt.Errorf("backup database: db is nil")
	}
	destPath = strings.TrimSpace(destPath)
	if destPath == "" {
		return fmt.Errorf("backup database: destination path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("backup destination already exists: %s", destPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat backup destination: %w", err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, destPath); err != nil {
		return fmt.Errorf("vacuum into %s: %w", destPath, err)
	}
	SecureDBFiles(destPath)
	return nil
}

// BackupAll writes online snapshots of the control-plane database and every
// tenant database that exists on disk into
// `{outputBaseDir}/{YYYYMMDD-HHMMSS}/`. When outputBaseDir is empty it defaults
// to `{dataDir}/backups`. Returns the created backup directory path.
func BackupAll(ctx context.Context, dataDir, controlDBPath string, controlDB *sql.DB, tenants []Tenant, outputBaseDir string) (string, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return "", fmt.Errorf("backup all: data dir is empty")
	}
	outputBaseDir = strings.TrimSpace(outputBaseDir)
	if outputBaseDir == "" {
		outputBaseDir = filepath.Join(dataDir, "backups")
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	backupDir := filepath.Join(outputBaseDir, stamp)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}

	controlName := "controlplane.db"
	if base := filepath.Base(strings.TrimSpace(controlDBPath)); base != "" && base != "." {
		controlName = base
	}
	if err := BackupDatabase(ctx, controlDB, filepath.Join(backupDir, controlName)); err != nil {
		return "", fmt.Errorf("backup control plane: %w", err)
	}

	usedNames := map[string]struct{}{controlName: {}}
	for _, tenant := range tenants {
		dbPath := strings.TrimSpace(tenant.DBPath)
		if dbPath == "" {
			continue
		}
		info, err := os.Stat(dbPath)
		if err != nil || info.IsDir() {
			continue
		}
		name := backupTenantFileName(tenant, usedNames)
		usedNames[name] = struct{}{}

		tenantDB, err := openBackupSourceDB(dbPath)
		if err != nil {
			return "", fmt.Errorf("open tenant db %s: %w", tenant.Slug, err)
		}
		err = BackupDatabase(ctx, tenantDB, filepath.Join(backupDir, name))
		_ = tenantDB.Close()
		if err != nil {
			return "", fmt.Errorf("backup tenant %s: %w", tenant.Slug, err)
		}
	}

	return backupDir, nil
}

func backupTenantFileName(tenant Tenant, used map[string]struct{}) string {
	candidates := []string{}
	if base := filepath.Base(strings.TrimSpace(tenant.DBPath)); base != "" && base != "." {
		candidates = append(candidates, base)
	}
	slug := strings.TrimSpace(tenant.Slug)
	if slug != "" {
		candidates = append(candidates, slug+".db")
	}
	candidates = append(candidates, fmt.Sprintf("tenant-%d.db", tenant.ID))

	for _, name := range candidates {
		if _, exists := used[name]; !exists {
			return name
		}
	}
	return fmt.Sprintf("tenant-%d-%d.db", tenant.ID, time.Now().UnixNano())
}

func openBackupSourceDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// DB returns the underlying *sql.DB for online backup tooling.
func (s *ControlPlaneStore) DB() *sql.DB {
	return s.db
}
