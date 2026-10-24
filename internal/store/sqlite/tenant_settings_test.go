package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestTenantAdminNotificationTargetsExcludeViewers(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "controlplane.db")

	cp, err := OpenControlPlane(ctx, controlPath)
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()
	if err := cp.ConfigureSecretKey("test-secret-key-for-notifications"); err != nil {
		t.Fatalf("configure secret key: %v", err)
	}

	tenant, err := cp.CreateTenant(ctx, "notify-admins", "Notify Admins", filepath.Join(dir, "notify-admins.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	adminUser, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "admin", "password-123456", "admin@example.com", "Admin", "admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	viewerUser, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "viewer", "password-123456", "viewer@example.com", "Viewer", "viewer")
	if err != nil {
		t.Fatalf("create viewer user: %v", err)
	}

	if err := cp.SaveUserNotificationSettings(ctx, tenant.ID, adminUser.UserID, true, true, "https://matrix.example", "!admin:example", "admin-token"); err != nil {
		t.Fatalf("save admin notifications: %v", err)
	}
	if err := cp.SaveUserNotificationSettings(ctx, tenant.ID, viewerUser.UserID, true, true, "https://matrix.example", "!viewer:example", "viewer-token"); err != nil {
		t.Fatalf("save viewer notifications: %v", err)
	}

	allRecipients, err := cp.ListTenantNotificationRecipients(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list all recipients: %v", err)
	}
	if len(allRecipients) != 2 {
		t.Fatalf("all recipients length = %d, want 2", len(allRecipients))
	}

	adminRecipients, err := cp.ListTenantAdminNotificationRecipients(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list admin recipients: %v", err)
	}
	if len(adminRecipients) != 1 || adminRecipients[0].Email != "admin@example.com" {
		t.Fatalf("admin recipients = %#v, want only admin@example.com", adminRecipients)
	}

	allMatrixTargets, err := cp.ListTenantMatrixNotificationTargets(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list all matrix targets: %v", err)
	}
	if len(allMatrixTargets) != 2 {
		t.Fatalf("all matrix targets length = %d, want 2", len(allMatrixTargets))
	}

	adminMatrixTargets, err := cp.ListTenantAdminMatrixNotificationTargets(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list admin matrix targets: %v", err)
	}
	if len(adminMatrixTargets) != 1 || adminMatrixTargets[0].UserID != adminUser.UserID || adminMatrixTargets[0].RoomID != "!admin:example" {
		t.Fatalf("admin matrix targets = %#v, want only admin target", adminMatrixTargets)
	}
}

func TestMatrixNotificationTargetsCanUseLegacySecretFallback(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	legacyKey := "legacy-session-key-1234567890"
	newKey := "new-sso-secret-key-1234567890"
	if err := cp.ConfigureSecretKey(legacyKey); err != nil {
		t.Fatalf("configure legacy secret key: %v", err)
	}
	tenant, err := cp.CreateTenant(ctx, "legacy-matrix", "Legacy Matrix", filepath.Join(dir, "legacy-matrix.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	user, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "admin", "password-123456", "admin@example.com", "Admin", "admin")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := cp.SaveUserNotificationSettings(ctx, tenant.ID, user.UserID, true, true, "https://matrix.example", "!admin:example", "legacy-token"); err != nil {
		t.Fatalf("save matrix notification settings: %v", err)
	}

	if err := cp.ConfigureSecretKeys(newKey, legacyKey); err != nil {
		t.Fatalf("configure new secret key with fallback: %v", err)
	}
	targets, err := cp.ListTenantMatrixNotificationTargets(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list matrix targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("matrix targets length = %d, want 1", len(targets))
	}
	if targets[0].AccessToken != "legacy-token" {
		t.Fatalf("matrix access token = %q, want legacy-token", targets[0].AccessToken)
	}
}

func TestTenantRetentionDefaultsAndPersistence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "controlplane.db")

	cp, err := OpenControlPlane(ctx, controlPath)
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	tenant, err := cp.CreateTenant(ctx, "default-retention", "Default Retention", filepath.Join(dir, "default-retention.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if tenant.StateEventRetentionDays != 365 {
		t.Fatalf("unexpected state retention default: %d", tenant.StateEventRetentionDays)
	}
	if tenant.NotificationEventRetentionDays != 365 {
		t.Fatalf("unexpected notification retention default: %d", tenant.NotificationEventRetentionDays)
	}

	updated, err := cp.UpdateTenantWithRetention(ctx, tenant.ID, tenant.Name, tenant.DBPath, true, 730, 90)
	if err != nil {
		t.Fatalf("update tenant retention: %v", err)
	}
	if updated.StateEventRetentionDays != 730 {
		t.Fatalf("unexpected state retention: %d", updated.StateEventRetentionDays)
	}
	if updated.NotificationEventRetentionDays != 90 {
		t.Fatalf("unexpected notification retention: %d", updated.NotificationEventRetentionDays)
	}
}

func TestTenantSessionVersionInvalidatesOnRoleAndPasswordChange(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "controlplane.db")

	cp, err := OpenControlPlane(ctx, controlPath)
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	tenant, err := cp.CreateTenant(ctx, "session-version", "Session Version", filepath.Join(dir, "session-version.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	user, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "alice", "initial-password", "alice@example.com", "Alice", "viewer")
	if err != nil {
		t.Fatalf("create local user: %v", err)
	}
	initial, err := cp.GetTenantMembershipSessionVersion(ctx, tenant.ID, user.UserID)
	if err != nil {
		t.Fatalf("get initial session version: %v", err)
	}
	if initial != 1 {
		t.Fatalf("initial session version = %d, want 1", initial)
	}

	if err := cp.UpdateTenantUserRole(ctx, tenant.ID, user.UserID, "admin"); err != nil {
		t.Fatalf("update role: %v", err)
	}
	afterRole, err := cp.GetTenantMembershipSessionVersion(ctx, tenant.ID, user.UserID)
	if err != nil {
		t.Fatalf("get session version after role: %v", err)
	}
	if afterRole <= initial {
		t.Fatalf("session version did not increase after role update: before=%d after=%d", initial, afterRole)
	}

	if err := cp.ResetLocalUserPassword(ctx, tenant.ID, user.UserID, "next-password"); err != nil {
		t.Fatalf("reset password: %v", err)
	}
	afterPassword, err := cp.GetTenantMembershipSessionVersion(ctx, tenant.ID, user.UserID)
	if err != nil {
		t.Fatalf("get session version after password: %v", err)
	}
	if afterPassword <= afterRole {
		t.Fatalf("session version did not increase after password reset: before=%d after=%d", afterRole, afterPassword)
	}
}

func TestTenantRetentionMigrationDefaultsExistingRows(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "legacy-controlplane.db")

	db, err := sql.Open("sqlite", sqliteDSN(controlPath))
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
CREATE TABLE tenants (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	slug TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	db_path TEXT NOT NULL,
	active INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
)
`); err != nil {
		t.Fatalf("create legacy tenants table: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO tenants (slug, name, db_path, active, created_at, updated_at)
VALUES ('legacy', 'Legacy', ?, 1, ?, ?)
`, filepath.Join(dir, "legacy.db"), time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatalf("insert legacy tenant: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close initial control plane: %v", err)
	}

	reopened, err := OpenControlPlane(ctx, controlPath)
	if err != nil {
		t.Fatalf("reopen control plane: %v", err)
	}
	defer reopened.Close()

	tenant, err := reopened.GetTenantBySlug(ctx, "legacy")
	if err != nil {
		t.Fatalf("get migrated tenant: %v", err)
	}
	if tenant.StateEventRetentionDays != 365 || tenant.NotificationEventRetentionDays != 365 {
		t.Fatalf("unexpected migrated retention values: state=%d notification=%d", tenant.StateEventRetentionDays, tenant.NotificationEventRetentionDays)
	}
}

func TestTenantRawResultRetentionDefaultsAndPersistence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	tenant, err := cp.CreateTenant(ctx, "raw-retention", "Raw Retention", filepath.Join(dir, "raw-retention.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if tenant.RawResultRetentionDays != 30 {
		t.Fatalf("unexpected raw retention default: %d", tenant.RawResultRetentionDays)
	}

	for input, want := range map[int]int{14: 14, 3: 7, 500: 90, 0: 30} {
		if err := cp.SetTenantRawResultRetentionDays(ctx, tenant.ID, input); err != nil {
			t.Fatalf("set raw retention: %v", err)
		}
		reloaded, err := cp.GetTenantByID(ctx, tenant.ID)
		if err != nil {
			t.Fatalf("reload tenant: %v", err)
		}
		if reloaded.RawResultRetentionDays != want {
			t.Fatalf("raw retention %d: got %d, want %d", input, reloaded.RawResultRetentionDays, want)
		}
	}
}
