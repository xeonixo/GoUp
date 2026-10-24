package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *ControlPlaneStore) ensureMembershipBlockedColumn(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "tenant_memberships", "blocked")
	if err != nil {
		return fmt.Errorf("inspect tenant_memberships blocked column: %w", err)
	}
	if hasColumn {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE tenant_memberships ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("add tenant_memberships blocked column: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ensureAuthProviderPolicyColumns(ctx context.Context) error {
	columns := []struct {
		name string
		sql  string
	}{
		{"default_role", `ALTER TABLE auth_providers ADD COLUMN default_role TEXT NOT NULL DEFAULT 'viewer'`},
		{"allowed_email_domains", `ALTER TABLE auth_providers ADD COLUMN allowed_email_domains TEXT NOT NULL DEFAULT ''`},
		{"allowed_groups", `ALTER TABLE auth_providers ADD COLUMN allowed_groups TEXT NOT NULL DEFAULT ''`},
		{"require_email_verified", `ALTER TABLE auth_providers ADD COLUMN require_email_verified INTEGER NOT NULL DEFAULT 0`},
	}
	for _, column := range columns {
		hasColumn, err := s.tableHasColumn(ctx, "auth_providers", column.name)
		if err != nil {
			return fmt.Errorf("inspect auth_providers %s column: %w", column.name, err)
		}
		if hasColumn {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.sql); err != nil {
			return fmt.Errorf("add auth_providers %s column: %w", column.name, err)
		}
	}
	return nil
}

// ensureUserIdentitiesTenantScoped rebuilds user_identities so that the unique
// key is (tenant_id, provider_key, provider_subject). Previously the key was
// (provider_key, provider_subject); provider keys such as "oidc-primary" are
// shared by every tenant, so an identity of one tenant's IdP could be resolved
// to the user of another tenant's IdP. Existing rows are copied once per tenant
// the user is a member of (rows of users without any membership keep tenant 0).
func (s *ControlPlaneStore) ensureUserIdentitiesTenantScoped(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "user_identities", "tenant_id")
	if err != nil {
		return fmt.Errorf("inspect user_identities tenant_id column: %w", err)
	}
	if hasColumn {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user_identities migration transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE user_identities_new (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	provider_key TEXT NOT NULL,
	provider_subject TEXT NOT NULL,
	email TEXT NOT NULL DEFAULT '',
	tenant_id INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	UNIQUE(tenant_id, provider_key, provider_subject),
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)
`); err != nil {
		return fmt.Errorf("create user_identities_new table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO user_identities_new (user_id, provider_key, provider_subject, email, tenant_id, created_at, updated_at)
SELECT ui.user_id, ui.provider_key, ui.provider_subject, ui.email, tm.tenant_id, ui.created_at, ui.updated_at
FROM user_identities ui
JOIN tenant_memberships tm ON tm.user_id = ui.user_id
`); err != nil {
		return fmt.Errorf("copy user_identities data: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO user_identities_new (user_id, provider_key, provider_subject, email, tenant_id, created_at, updated_at)
SELECT ui.user_id, ui.provider_key, ui.provider_subject, ui.email, 0, ui.created_at, ui.updated_at
FROM user_identities ui
WHERE NOT EXISTS (SELECT 1 FROM tenant_memberships tm WHERE tm.user_id = ui.user_id)
`); err != nil {
		return fmt.Errorf("copy orphan user_identities data: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE user_identities`); err != nil {
		return fmt.Errorf("drop old user_identities table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE user_identities_new RENAME TO user_identities`); err != nil {
		return fmt.Errorf("rename user_identities_new table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user_identities migration: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ensureTenantRetentionColumns(ctx context.Context) error {
	columns := []struct {
		name string
		sql  string
	}{
		{"state_event_retention_days", `ALTER TABLE tenants ADD COLUMN state_event_retention_days INTEGER NOT NULL DEFAULT 365`},
		{"notification_event_retention_days", `ALTER TABLE tenants ADD COLUMN notification_event_retention_days INTEGER NOT NULL DEFAULT 365`},
		{"raw_result_retention_days", `ALTER TABLE tenants ADD COLUMN raw_result_retention_days INTEGER NOT NULL DEFAULT 30`},
	}
	for _, column := range columns {
		hasColumn, err := s.tableHasColumn(ctx, "tenants", column.name)
		if err != nil {
			return fmt.Errorf("inspect tenants %s column: %w", column.name, err)
		}
		if hasColumn {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.sql); err != nil {
			return fmt.Errorf("add tenants %s column: %w", column.name, err)
		}
	}
	return nil
}

func (s *ControlPlaneStore) ensureUserPreferredLanguageColumn(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "users", "preferred_language")
	if err != nil {
		return fmt.Errorf("inspect users preferred_language column: %w", err)
	}
	if hasColumn {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, `ALTER TABLE users ADD COLUMN preferred_language TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("add users preferred_language column: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ensureUsersSuperAdminColumnRemoved(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "users", "is_super_admin")
	if err != nil {
		return fmt.Errorf("inspect users columns: %w", err)
	}
	if !hasColumn {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, `ALTER TABLE users DROP COLUMN is_super_admin`); err != nil {
		return fmt.Errorf("drop users is_super_admin column: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ensureTenantMembershipNotificationColumn(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "tenant_memberships", "notifications_email_enabled")
	if err != nil {
		return fmt.Errorf("inspect tenant_memberships columns: %w", err)
	}
	if hasColumn {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, `ALTER TABLE tenant_memberships ADD COLUMN notifications_email_enabled INTEGER NOT NULL DEFAULT 1`); err != nil {
		return fmt.Errorf("add tenant_memberships notifications_email_enabled column: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ensureTenantMembershipSessionVersionColumn(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "tenant_memberships", "session_version")
	if err != nil {
		return fmt.Errorf("inspect tenant_memberships session_version column: %w", err)
	}
	if hasColumn {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE tenant_memberships ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1`); err != nil {
		return fmt.Errorf("add tenant_memberships session_version column: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ensureControlPlaneAdminSessionVersionColumn(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "control_plane_admins", "session_version")
	if err != nil {
		return fmt.Errorf("inspect control_plane_admins session_version column: %w", err)
	}
	if hasColumn {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE control_plane_admins ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1`); err != nil {
		return fmt.Errorf("add control_plane_admins session_version column: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) tableHasColumn(ctx context.Context, tableName, columnName string) (bool, error) {
	switch tableName {
	case "tenants", "users", "tenant_memberships", "remote_nodes", "local_credentials", "control_plane_admins", "user_identities", "auth_providers":
	default:
		return false, fmt.Errorf("unsupported table inspection: %s", tableName)
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_info(%s)`, tableName))
	if err != nil {
		return false, err
	}

	hasColumn := false
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return false, fmt.Errorf("scan %s column: %w", tableName, err)
		}
		if name == columnName {
			hasColumn = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, fmt.Errorf("iterate %s columns: %w", tableName, err)
	}
	if err := rows.Close(); err != nil {
		return false, fmt.Errorf("close %s columns: %w", tableName, err)
	}
	return hasColumn, nil
}

func (s *ControlPlaneStore) ensureUserNotificationChannelsTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS user_notification_channels (
	tenant_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	kind TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 0,
	config_json TEXT NOT NULL DEFAULT '{}',
	secret_ciphertext TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (tenant_id, user_id, kind),
	FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)
`); err != nil {
		return fmt.Errorf("create user notification channels table: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ensureLocalCredentialsTenantScoped(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "local_credentials", "tenant_id")
	if err != nil {
		return fmt.Errorf("inspect local_credentials tenant_id column: %w", err)
	}
	if hasColumn {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin local_credentials migration transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE local_credentials_new (
	user_id INTEGER PRIMARY KEY,
	tenant_id INTEGER NOT NULL DEFAULT 0,
	login_name TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	UNIQUE(login_name, tenant_id),
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)
`); err != nil {
		return fmt.Errorf("create local_credentials_new table: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO local_credentials_new (user_id, tenant_id, login_name, password_hash, created_at, updated_at)
SELECT lc.user_id,
       COALESCE((SELECT tm.tenant_id FROM tenant_memberships tm WHERE tm.user_id = lc.user_id LIMIT 1), 0),
       lc.login_name, lc.password_hash, lc.created_at, lc.updated_at
FROM local_credentials lc
`); err != nil {
		return fmt.Errorf("copy local_credentials data: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DROP TABLE local_credentials`); err != nil {
		return fmt.Errorf("drop old local_credentials table: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `ALTER TABLE local_credentials_new RENAME TO local_credentials`); err != nil {
		return fmt.Errorf("rename local_credentials_new table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit local_credentials migration: %w", err)
	}
	return nil
}
