package sqlite

import (
	"context"
	"fmt"
)

const controlPlaneSchema = `
CREATE TABLE IF NOT EXISTS tenants (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	slug TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	db_path TEXT NOT NULL,
	active INTEGER NOT NULL DEFAULT 1,
	state_event_retention_days INTEGER NOT NULL DEFAULT 365,
	notification_event_retention_days INTEGER NOT NULL DEFAULT 365,
	raw_result_retention_days INTEGER NOT NULL DEFAULT 30,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT NOT NULL DEFAULT '',
	display_name TEXT NOT NULL DEFAULT '',
	preferred_language TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	last_login_at DATETIME
);

CREATE TABLE IF NOT EXISTS user_identities (
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
);

CREATE TABLE IF NOT EXISTS tenant_memberships (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	role TEXT NOT NULL DEFAULT 'viewer',
	session_version INTEGER NOT NULL DEFAULT 1,
	blocked INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	UNIQUE(tenant_id, user_id),
	FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_providers (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id INTEGER NOT NULL,
	provider_key TEXT NOT NULL,
	kind TEXT NOT NULL,
	display_name TEXT NOT NULL,
	issuer_url TEXT NOT NULL DEFAULT '',
	client_id TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	default_role TEXT NOT NULL DEFAULT 'viewer',
	allowed_email_domains TEXT NOT NULL DEFAULT '',
	allowed_groups TEXT NOT NULL DEFAULT '',
	require_email_verified INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	UNIQUE(tenant_id, provider_key),
	FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS local_credentials (
	user_id INTEGER PRIMARY KEY,
	tenant_id INTEGER NOT NULL DEFAULT 0,
	login_name TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	UNIQUE(login_name, tenant_id),
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_provider_secrets (
	tenant_id INTEGER NOT NULL,
	provider_key TEXT NOT NULL,
	secret_ciphertext TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (tenant_id, provider_key),
	FOREIGN KEY(tenant_id, provider_key) REFERENCES auth_providers(tenant_id, provider_key) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS global_smtp_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	host TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 587,
	username TEXT NOT NULL DEFAULT '',
	password_ciphertext TEXT NOT NULL DEFAULT '',
	from_email TEXT NOT NULL DEFAULT '',
	from_name TEXT NOT NULL DEFAULT '',
	tls_mode TEXT NOT NULL DEFAULT 'starttls',
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	actor TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL,
	target_type TEXT NOT NULL DEFAULT '',
	target_id INTEGER NOT NULL DEFAULT 0,
	details TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS control_plane_admins (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	username TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	totp_secret_ciphertext TEXT NOT NULL DEFAULT '',
	totp_enabled INTEGER NOT NULL DEFAULT 0,
	session_version INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS system_settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS tenant_notification_endpoint_secrets (
	tenant_id INTEGER NOT NULL,
	endpoint_id INTEGER NOT NULL,
	kind TEXT NOT NULL,
	secret_ciphertext TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (tenant_id, endpoint_id, kind),
	FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
`

func (s *ControlPlaneStore) initSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, controlPlaneSchema); err != nil {
		return fmt.Errorf("initialize control-plane schema: %w", err)
	}
	if err := s.ensureUserPreferredLanguageColumn(ctx); err != nil {
		return err
	}
	if err := s.ensureUsersSuperAdminColumnRemoved(ctx); err != nil {
		return err
	}
	if err := s.ensureTenantRetentionColumns(ctx); err != nil {
		return err
	}
	if err := s.ensureTenantMembershipNotificationColumn(ctx); err != nil {
		return err
	}
	if err := s.ensureTenantMembershipSessionVersionColumn(ctx); err != nil {
		return err
	}
	if err := s.ensureControlPlaneAdminSessionVersionColumn(ctx); err != nil {
		return err
	}
	if err := s.ensureUserNotificationChannelsTable(ctx); err != nil {
		return err
	}
	if err := s.ensurePushTables(ctx); err != nil {
		return err
	}
	if err := s.ensureRemoteNodesTable(ctx); err != nil {
		return err
	}
	if err := s.ensureAPITokensTable(ctx); err != nil {
		return err
	}
	if err := s.ensureLocalCredentialsTenantScoped(ctx); err != nil {
		return err
	}
	if err := s.ensureMembershipBlockedColumn(ctx); err != nil {
		return err
	}
	if err := s.ensureAuthProviderPolicyColumns(ctx); err != nil {
		return err
	}
	if err := s.ensureUserIdentitiesTenantScoped(ctx); err != nil {
		return err
	}
	return nil
}
