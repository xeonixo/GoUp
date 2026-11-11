package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupDatabaseVacuumIntoRoundtrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "source.db")

	db, err := sql.Open("sqlite", sqliteDSN(srcPath))
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()

	if _, err := db.ExecContext(ctx, `CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO items (name) VALUES ('alpha'), ('beta')`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	destPath := filepath.Join(dir, "snapshots", "copy.db")
	if err := BackupDatabase(ctx, db, destPath); err != nil {
		t.Fatalf("BackupDatabase: %v", err)
	}
	if _, err := os.Stat(destPath); err != nil {
		t.Fatalf("dest missing: %v", err)
	}

	restored, err := sql.Open("sqlite", sqliteDSN(destPath))
	if err != nil {
		t.Fatalf("open restored: %v", err)
	}
	defer restored.Close()

	var count int
	if err := restored.QueryRowContext(ctx, `SELECT COUNT(*) FROM items`).Scan(&count); err != nil {
		t.Fatalf("count restored: %v", err)
	}
	if count != 2 {
		t.Fatalf("restored count = %d, want 2", count)
	}
	var name string
	if err := restored.QueryRowContext(ctx, `SELECT name FROM items WHERE id = 1`).Scan(&name); err != nil || name != "alpha" {
		t.Fatalf("row = %q err=%v", name, err)
	}
}

func TestBackupAllControlAndTenant(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "controlplane.db")

	cp, err := OpenControlPlane(ctx, controlPath)
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	tenantPath := filepath.Join(dir, "acme.db")
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme", tenantPath)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenantStore, err := Open(ctx, tenantPath)
	if err != nil {
		t.Fatalf("open tenant store: %v", err)
	}
	defer tenantStore.Close()

	backupDir, err := BackupAll(ctx, dir, controlPath, cp.DB(), []Tenant{tenant}, "")
	if err != nil {
		t.Fatalf("BackupAll: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "controlplane.db")); err != nil {
		t.Fatalf("control backup missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "acme.db")); err != nil {
		t.Fatalf("tenant backup missing: %v", err)
	}

	restoredCP, err := OpenControlPlane(ctx, filepath.Join(backupDir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open restored control plane: %v", err)
	}
	defer restoredCP.Close()
	got, err := restoredCP.GetTenantBySlug(ctx, "acme")
	if err != nil || got.Slug != "acme" {
		t.Fatalf("restored tenant = %+v err=%v", got, err)
	}
}
