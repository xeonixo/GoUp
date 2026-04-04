package sqlite

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var tenantSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type ControlPlaneStore struct {
	db        *sql.DB
	secretKey []byte
}

type Tenant struct {
	ID     int64
	Slug   string
	Name   string
	DBPath string
	Active bool
}

type ResolvedUser struct {
	UserID       int64
	Email        string
	DisplayName  string
	SuperAdmin   bool
	TenantID     int64
	TenantSlug   string
	TenantName   string
	TenantDBPath string
	Role         string
}

type AuthProvider struct {
	ID          int64
	TenantID    int64
	ProviderKey string
	Kind        string // "oidc" or "local"
	DisplayName string
	IssuerURL   string // for OIDC
	ClientID    string // for OIDC
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type LocalUser struct {
	UserID      int64
	TenantID    int64
	LoginName   string
	Email       string
	DisplayName string
	Role        string
	SuperAdmin  bool
	LastLoginAt *time.Time
}

type TenantUser struct {
	UserID              int64
	TenantID            int64
	LoginName           string
	Email               string
	DisplayName         string
	Role                string
	SuperAdmin          bool
	LastLoginAt         *time.Time
	HasLocalCredentials bool
	HasOIDCIdentity     bool
}

type UserNotificationSettings struct {
	EmailEnabled       bool
	MatrixEnabled      bool
	MatrixHomeserver   string
	MatrixRoomID       string
	MatrixAccessToken  string
	HasLocalCredentials bool
}

type MatrixNotificationTarget struct {
	UserID        int64
	HomeserverURL string
	RoomID        string
	AccessToken   string
}

type GlobalSMTPSettings struct {
	Host               string
	Port               int
	Username           string
	FromEmail          string
	FromName           string
	TLSMode            string // none, starttls, tls
	PasswordConfigured bool
}

type GlobalSMTPDeliveryConfig struct {
	Settings GlobalSMTPSettings
	Password string
}

type AuditEvent struct {
	ID         int64
	Actor      string
	Action     string
	TargetType string
	TargetID   int64
	Details    string
	CreatedAt  time.Time
}

func OpenControlPlane(ctx context.Context, path string) (*ControlPlaneStore, error) {
	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open control-plane sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping control-plane sqlite database: %w", err)
	}

	store := &ControlPlaneStore{db: db}
	if err := store.initSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

func (s *ControlPlaneStore) Close() error {
	return s.db.Close()
}

func (s *ControlPlaneStore) Healthcheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// ConfigureSecretKey sets the encryption key used to store SSO client secrets.
func (s *ControlPlaneStore) ConfigureSecretKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("secret key must not be empty")
	}
	derived := sha256.Sum256([]byte(key))
	s.secretKey = derived[:]
	return nil
}

func (s *ControlPlaneStore) EnsureDefaultTenant(ctx context.Context, name, slug, dbPath string) (Tenant, error) {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO tenants (slug, name, db_path, active, created_at, updated_at)
VALUES (?, ?, ?, 1, ?, ?)
ON CONFLICT(slug) DO UPDATE SET
	name = excluded.name,
	db_path = excluded.db_path,
	active = 1,
	updated_at = excluded.updated_at
`, slug, name, dbPath, now, now)
	if err != nil {
		return Tenant{}, fmt.Errorf("ensure default tenant: %w", err)
	}
	return s.GetTenantBySlug(ctx, slug)
}

// EnsureDefaultOIDCProvider ensures the default OIDC provider exists for the default tenant
func (s *ControlPlaneStore) EnsureDefaultOIDCProvider(ctx context.Context, tenantID int64, issuerURL, clientID, clientSecret string) (AuthProvider, error) {
	now := time.Now().UTC()
	displayName := "Default OIDC"

	_, err := s.db.ExecContext(ctx, `
INSERT INTO auth_providers (tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
ON CONFLICT(tenant_id, provider_key) DO UPDATE SET
	display_name = excluded.display_name,
	issuer_url = excluded.issuer_url,
	client_id = excluded.client_id,
	enabled = 1,
	updated_at = excluded.updated_at
`, tenantID, "oidc-primary", "oidc", displayName, issuerURL, clientID, now, now)
	if err != nil {
		return AuthProvider{}, fmt.Errorf("ensure default oidc provider: %w", err)
	}
	if strings.TrimSpace(clientSecret) != "" {
		if err := s.UpdateAuthProviderSecret(ctx, tenantID, "oidc-primary", clientSecret); err != nil {
			return AuthProvider{}, fmt.Errorf("ensure default oidc provider secret: %w", err)
		}
	}

	return s.GetAuthProvider(ctx, tenantID, "oidc-primary")
}

func (s *ControlPlaneStore) GetTenantBySlug(ctx context.Context, slug string) (Tenant, error) {
	return s.getTenant(ctx, `
SELECT id, slug, name, db_path, active
FROM tenants
WHERE slug = ?
`, slug)
}

func (s *ControlPlaneStore) GetTenantByID(ctx context.Context, tenantID int64) (Tenant, error) {
	return s.getTenant(ctx, `
SELECT id, slug, name, db_path, active
FROM tenants
WHERE id = ?
`, tenantID)
}

func (s *ControlPlaneStore) getTenant(ctx context.Context, query string, args ...any) (Tenant, error) {
	var tenant Tenant
	var active int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&tenant.ID, &tenant.Slug, &tenant.Name, &tenant.DBPath, &active)
	if err != nil {
		return Tenant{}, fmt.Errorf("get tenant: %w", err)
	}
	tenant.Active = active == 1
	return tenant, nil
}

func (s *ControlPlaneStore) UpsertOIDCUserIdentity(ctx context.Context, providerKey, subject, email, displayName string, defaultTenantID int64) (ResolvedUser, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ResolvedUser{}, fmt.Errorf("begin control-plane user transaction: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	var userID int64
	err = tx.QueryRowContext(ctx, `
SELECT user_id
FROM user_identities
WHERE provider_key = ? AND provider_subject = ?
`, providerKey, subject).Scan(&userID)
	switch err {
	case nil:
		if _, err := tx.ExecContext(ctx, `
UPDATE users
SET email = ?, display_name = ?, updated_at = ?, last_login_at = ?
WHERE id = ?
`, email, displayName, now, now, userID); err != nil {
			return ResolvedUser{}, fmt.Errorf("update user from oidc identity: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE user_identities
SET email = ?, updated_at = ?
WHERE provider_key = ? AND provider_subject = ?
`, email, now, providerKey, subject); err != nil {
			return ResolvedUser{}, fmt.Errorf("update oidc identity: %w", err)
		}
	case sql.ErrNoRows:
		isSuperAdmin := 0
		var superAdminCount int
		if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM users
WHERE is_super_admin = 1
`).Scan(&superAdminCount); err != nil {
			return ResolvedUser{}, fmt.Errorf("count super admins: %w", err)
		}
		if superAdminCount == 0 {
			isSuperAdmin = 1
		}

		result, err := tx.ExecContext(ctx, `
INSERT INTO users (email, display_name, is_super_admin, created_at, updated_at, last_login_at)
VALUES (?, ?, ?, ?, ?, ?)
`, email, displayName, isSuperAdmin, now, now, now)
		if err != nil {
			return ResolvedUser{}, fmt.Errorf("insert user from oidc identity: %w", err)
		}
		userID, err = result.LastInsertId()
		if err != nil {
			return ResolvedUser{}, fmt.Errorf("last user id from oidc identity: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO user_identities (user_id, provider_key, provider_subject, email, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
`, userID, providerKey, subject, email, now, now); err != nil {
			return ResolvedUser{}, fmt.Errorf("insert oidc identity: %w", err)
		}
	default:
		return ResolvedUser{}, fmt.Errorf("lookup oidc identity: %w", err)
	}

	if defaultTenantID > 0 {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at, updated_at)
VALUES (?, ?, 'admin', ?, ?)
ON CONFLICT(tenant_id, user_id) DO UPDATE SET
	updated_at = excluded.updated_at
`, defaultTenantID, userID, now, now); err != nil {
			return ResolvedUser{}, fmt.Errorf("ensure default tenant membership: %w", err)
		}
	}

	resolved, err := loadResolvedUserTx(ctx, tx, userID)
	if err != nil {
		return ResolvedUser{}, err
	}

	if err := tx.Commit(); err != nil {
		return ResolvedUser{}, fmt.Errorf("commit control-plane user transaction: %w", err)
	}
	return resolved, nil
}

func (s *ControlPlaneStore) AuthenticateLocalUser(ctx context.Context, tenantID int64, loginName, password string) (ResolvedUser, error) {
	loginName = strings.TrimSpace(loginName)
	if loginName == "" || password == "" {
		return ResolvedUser{}, fmt.Errorf("login name and password are required")
	}

	var userID int64
	var passwordHash string
	err := s.db.QueryRowContext(ctx, `
SELECT u.id, lc.password_hash
FROM local_credentials lc
JOIN users u ON u.id = lc.user_id
JOIN tenant_memberships tm ON tm.user_id = u.id
JOIN tenants t ON t.id = tm.tenant_id
WHERE tm.tenant_id = ?
	AND t.active = 1
	AND lower(lc.login_name) = lower(?)
LIMIT 1
`, tenantID, loginName).Scan(&userID, &passwordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ResolvedUser{}, sql.ErrNoRows
		}
		return ResolvedUser{}, fmt.Errorf("find local user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return ResolvedUser{}, sql.ErrNoRows
	}

	resolved, err := s.resolveUserByID(ctx, userID)
	if err != nil {
		return ResolvedUser{}, err
	}

	if resolved.TenantID != tenantID {
		resolved.TenantID = tenantID
		tenant, err := s.GetTenantByID(ctx, tenantID)
		if err != nil {
			return ResolvedUser{}, fmt.Errorf("resolve tenant for local user: %w", err)
		}
		resolved.TenantSlug = tenant.Slug
		resolved.TenantName = tenant.Name
		resolved.TenantDBPath = tenant.DBPath
	}

	_, _ = s.db.ExecContext(ctx, `
UPDATE users
SET last_login_at = ?, updated_at = ?
WHERE id = ?
`, time.Now().UTC(), time.Now().UTC(), userID)

	return resolved, nil
}

func (s *ControlPlaneStore) resolveUserByID(ctx context.Context, userID int64) (ResolvedUser, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ResolvedUser{}, fmt.Errorf("begin user lookup transaction: %w", err)
	}
	defer tx.Rollback()

	resolved, err := loadResolvedUserTx(ctx, tx, userID)
	if err != nil {
		return ResolvedUser{}, err
	}

	if err := tx.Commit(); err != nil {
		return ResolvedUser{}, fmt.Errorf("commit user lookup transaction: %w", err)
	}

	return resolved, nil
}

func (s *ControlPlaneStore) ListLocalUsersByTenant(ctx context.Context, tenantID int64) ([]LocalUser, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT u.id, tm.tenant_id, lc.login_name, u.email, u.display_name, tm.role, u.is_super_admin, u.last_login_at
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
JOIN local_credentials lc ON lc.user_id = u.id
WHERE tm.tenant_id = ?
ORDER BY lc.login_name ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query local users by tenant: %w", err)
	}
	defer rows.Close()

	users := make([]LocalUser, 0)
	for rows.Next() {
		item, err := scanLocalUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate local users by tenant: %w", err)
	}

	return users, nil
}

func (s *ControlPlaneStore) GetLocalUserByID(ctx context.Context, tenantID, userID int64) (LocalUser, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT u.id, tm.tenant_id, lc.login_name, u.email, u.display_name, tm.role, u.is_super_admin, u.last_login_at
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
JOIN local_credentials lc ON lc.user_id = u.id
WHERE tm.tenant_id = ? AND u.id = ?
LIMIT 1
`, tenantID, userID)

	item, err := scanLocalUser(row)
	if err != nil {
		return LocalUser{}, err
	}
	return item, nil
}

func (s *ControlPlaneStore) ListTenantUsers(ctx context.Context, tenantID int64) ([]TenantUser, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
	u.id,
	tm.tenant_id,
	COALESCE(lc.login_name, ''),
	u.email,
	u.display_name,
	tm.role,
	u.is_super_admin,
	u.last_login_at,
	CASE WHEN lc.user_id IS NULL THEN 0 ELSE 1 END AS has_local_credentials,
	CASE WHEN EXISTS (SELECT 1 FROM user_identities ui WHERE ui.user_id = u.id) THEN 1 ELSE 0 END AS has_oidc_identity
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
LEFT JOIN local_credentials lc ON lc.user_id = u.id
WHERE tm.tenant_id = ?
ORDER BY lower(COALESCE(NULLIF(lc.login_name, ''), NULLIF(u.display_name, ''), u.email, '')), u.id ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query tenant users: %w", err)
	}
	defer rows.Close()

	items := make([]TenantUser, 0)
	for rows.Next() {
		item, err := scanTenantUser(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant users: %w", err)
	}

	return items, nil
}

func (s *ControlPlaneStore) CreateLocalUserForTenant(ctx context.Context, tenantID int64, loginName, password, email, displayName, role string) (LocalUser, error) {
	loginName = strings.TrimSpace(loginName)
	email = strings.TrimSpace(email)
	displayName = strings.TrimSpace(displayName)
	role = strings.TrimSpace(role)
	if loginName == "" || password == "" {
		return LocalUser{}, fmt.Errorf("login name and password are required")
	}
	if role == "" {
		role = "viewer"
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return LocalUser{}, fmt.Errorf("hash local user password: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LocalUser{}, fmt.Errorf("begin local user create transaction: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `
INSERT INTO users (email, display_name, is_super_admin, created_at, updated_at, last_login_at)
VALUES (?, ?, 0, ?, ?, NULL)
`, email, displayName, now, now)
	if err != nil {
		return LocalUser{}, fmt.Errorf("insert local user: %w", err)
	}
	userID, err := result.LastInsertId()
	if err != nil {
		return LocalUser{}, fmt.Errorf("read local user id: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
`, tenantID, userID, role, now, now); err != nil {
		return LocalUser{}, fmt.Errorf("insert local user tenant membership: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO local_credentials (user_id, login_name, password_hash, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
`, userID, loginName, string(passwordHash), now, now); err != nil {
		return LocalUser{}, fmt.Errorf("insert local user credentials: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return LocalUser{}, fmt.Errorf("commit local user create transaction: %w", err)
	}

	return s.GetLocalUserByID(ctx, tenantID, userID)
}

func (s *ControlPlaneStore) UpdateLocalUserForTenant(ctx context.Context, tenantID, userID int64, loginName, password, email, displayName, role string) (LocalUser, error) {
	loginName = strings.TrimSpace(loginName)
	email = strings.TrimSpace(email)
	displayName = strings.TrimSpace(displayName)
	role = strings.TrimSpace(role)
	if loginName == "" {
		return LocalUser{}, fmt.Errorf("login name is required")
	}
	if role == "" {
		role = "viewer"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LocalUser{}, fmt.Errorf("begin local user update transaction: %w", err)
	}
	defer tx.Rollback()

	var existing int
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM tenant_memberships tm
JOIN local_credentials lc ON lc.user_id = tm.user_id
WHERE tm.tenant_id = ? AND tm.user_id = ?
`, tenantID, userID).Scan(&existing); err != nil {
		return LocalUser{}, fmt.Errorf("check local user existence: %w", err)
	}
	if existing == 0 {
		return LocalUser{}, sql.ErrNoRows
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
UPDATE users
SET email = ?, display_name = ?, updated_at = ?
WHERE id = ?
`, email, displayName, now, userID); err != nil {
		return LocalUser{}, fmt.Errorf("update local user profile: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE tenant_memberships
SET role = ?, updated_at = ?
WHERE tenant_id = ? AND user_id = ?
`, role, now, tenantID, userID); err != nil {
		return LocalUser{}, fmt.Errorf("update local user role: %w", err)
	}

	if strings.TrimSpace(password) != "" {
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return LocalUser{}, fmt.Errorf("hash local user password: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE local_credentials
SET login_name = ?, password_hash = ?, updated_at = ?
WHERE user_id = ?
`, loginName, string(passwordHash), now, userID); err != nil {
			return LocalUser{}, fmt.Errorf("update local user credentials: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
UPDATE local_credentials
SET login_name = ?, updated_at = ?
WHERE user_id = ?
`, loginName, now, userID); err != nil {
			return LocalUser{}, fmt.Errorf("update local user login name: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return LocalUser{}, fmt.Errorf("commit local user update transaction: %w", err)
	}

	return s.GetLocalUserByID(ctx, tenantID, userID)
}

func (s *ControlPlaneStore) UpdateTenantUserRole(ctx context.Context, tenantID, userID int64, role string) error {
	role = strings.ToLower(strings.TrimSpace(role))
	if role != "viewer" && role != "admin" {
		return fmt.Errorf("invalid role %q", role)
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE tenant_memberships
SET role = ?, updated_at = ?
WHERE tenant_id = ? AND user_id = ?
`, role, time.Now().UTC(), tenantID, userID)
	if err != nil {
		return fmt.Errorf("update tenant user role: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update tenant user role rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *ControlPlaneStore) DeleteLocalUserFromTenant(ctx context.Context, tenantID, userID int64) error {
	var hasLocalCredentials int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM local_credentials lc
JOIN tenant_memberships tm ON tm.user_id = lc.user_id
WHERE tm.tenant_id = ? AND lc.user_id = ?
`, tenantID, userID).Scan(&hasLocalCredentials)
	if err != nil {
		return fmt.Errorf("check local user before delete: %w", err)
	}
	if hasLocalCredentials == 0 {
		return sql.ErrNoRows
	}

	return s.RemoveUserFromTenant(ctx, tenantID, userID)
}

func (s *ControlPlaneStore) RemoveUserFromTenant(ctx context.Context, tenantID, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tenant user remove transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
DELETE FROM tenant_memberships
WHERE tenant_id = ? AND user_id = ?
`, tenantID, userID)
	if err != nil {
		return fmt.Errorf("delete tenant user membership: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete tenant user membership rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	var membershipCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_memberships WHERE user_id = ?`, userID).Scan(&membershipCount); err != nil {
		return fmt.Errorf("count remaining tenant user memberships: %w", err)
	}
	var identityCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_identities WHERE user_id = ?`, userID).Scan(&identityCount); err != nil {
		return fmt.Errorf("count remaining tenant user identities: %w", err)
	}
	var localCredentialsCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_credentials WHERE user_id = ?`, userID).Scan(&localCredentialsCount); err != nil {
		return fmt.Errorf("count remaining tenant user local credentials: %w", err)
	}

	if membershipCount == 0 {
		if localCredentialsCount > 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM local_credentials WHERE user_id = ?`, userID); err != nil {
				return fmt.Errorf("delete tenant user local credentials: %w", err)
			}
		}
		if identityCount == 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID); err != nil {
				return fmt.Errorf("delete tenant user record: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tenant user remove transaction: %w", err)
	}

	return nil
}

func (s *ControlPlaneStore) FindLocalUserByEmail(ctx context.Context, tenantID int64, email string) (LocalUser, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return LocalUser{}, sql.ErrNoRows
	}

	row := s.db.QueryRowContext(ctx, `
SELECT u.id, tm.tenant_id, lc.login_name, u.email, u.display_name, tm.role, u.is_super_admin, u.last_login_at
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
JOIN local_credentials lc ON lc.user_id = u.id
WHERE tm.tenant_id = ?
	AND lower(u.email) = lower(?)
LIMIT 1
`, tenantID, email)

	item, err := scanLocalUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return LocalUser{}, sql.ErrNoRows
		}
		return LocalUser{}, fmt.Errorf("find local user by email: %w", err)
	}
	return item, nil
}

func (s *ControlPlaneStore) ResetLocalUserPassword(ctx context.Context, tenantID, userID int64, newPassword string) error {
	newPassword = strings.TrimSpace(newPassword)
	if newPassword == "" {
		return fmt.Errorf("password is required")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash local user password: %w", err)
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE local_credentials
SET password_hash = ?, updated_at = ?
WHERE user_id = ?
	AND EXISTS (
		SELECT 1
		FROM tenant_memberships tm
		WHERE tm.user_id = local_credentials.user_id
			AND tm.tenant_id = ?
	)
`, string(passwordHash), time.Now().UTC(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("reset local user password: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("reset local user password rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanLocalUser(scanner interface{ Scan(dest ...any) error }) (LocalUser, error) {
	var item LocalUser
	var superAdmin int
	var lastLogin sql.NullTime
	if err := scanner.Scan(&item.UserID, &item.TenantID, &item.LoginName, &item.Email, &item.DisplayName, &item.Role, &superAdmin, &lastLogin); err != nil {
		return LocalUser{}, fmt.Errorf("scan local user: %w", err)
	}
	item.SuperAdmin = superAdmin == 1
	if lastLogin.Valid {
		value := lastLogin.Time
		item.LastLoginAt = &value
	}
	return item, nil
}

func scanTenantUser(scanner interface{ Scan(dest ...any) error }) (TenantUser, error) {
	var item TenantUser
	var superAdmin int
	var hasLocalCredentials int
	var hasOIDCIdentity int
	var lastLogin sql.NullTime
	if err := scanner.Scan(&item.UserID, &item.TenantID, &item.LoginName, &item.Email, &item.DisplayName, &item.Role, &superAdmin, &lastLogin, &hasLocalCredentials, &hasOIDCIdentity); err != nil {
		return TenantUser{}, fmt.Errorf("scan tenant user: %w", err)
	}
	item.SuperAdmin = superAdmin == 1
	item.HasLocalCredentials = hasLocalCredentials == 1
	item.HasOIDCIdentity = hasOIDCIdentity == 1
	if lastLogin.Valid {
		value := lastLogin.Time
		item.LastLoginAt = &value
	}
	return item, nil
}

// GetAuthProvidersByTenant returns all enabled auth providers for a specific tenant
func (s *ControlPlaneStore) GetAuthProvidersByTenant(ctx context.Context, tenantID int64) ([]AuthProvider, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at
FROM auth_providers
WHERE tenant_id = ? AND enabled = 1
ORDER BY created_at ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query auth providers by tenant: %w", err)
	}
	defer rows.Close()

	var providers []AuthProvider
	for rows.Next() {
		var p AuthProvider
		var enabled int
		if err := rows.Scan(&p.ID, &p.TenantID, &p.ProviderKey, &p.Kind, &p.DisplayName, &p.IssuerURL, &p.ClientID, &enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan auth provider: %w", err)
		}
		p.Enabled = enabled == 1
		providers = append(providers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate auth providers: %w", err)
	}
	return providers, nil
}

// GetAllAuthProvidersByTenant returns all auth providers (enabled and disabled) for a tenant.
func (s *ControlPlaneStore) GetAllAuthProvidersByTenant(ctx context.Context, tenantID int64) ([]AuthProvider, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at
FROM auth_providers
WHERE tenant_id = ?
ORDER BY created_at ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query all auth providers by tenant: %w", err)
	}
	defer rows.Close()

	var providers []AuthProvider
	for rows.Next() {
		var p AuthProvider
		var enabled int
		if err := rows.Scan(&p.ID, &p.TenantID, &p.ProviderKey, &p.Kind, &p.DisplayName, &p.IssuerURL, &p.ClientID, &enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan auth provider: %w", err)
		}
		p.Enabled = enabled == 1
		providers = append(providers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate auth providers: %w", err)
	}
	return providers, nil
}

// UpsertAuthProvider inserts or updates an auth provider for a tenant
func (s *ControlPlaneStore) UpsertAuthProvider(ctx context.Context, tenantID int64, providerKey, kind, displayName, issuerURL, clientID string) (AuthProvider, error) {
	now := time.Now().UTC()
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT enabled FROM auth_providers WHERE tenant_id = ? AND provider_key = ?`, tenantID, providerKey).Scan(&enabled)

	var result sql.Result
	if err == sql.ErrNoRows {
		// Insert
		result, err = s.db.ExecContext(ctx, `
INSERT INTO auth_providers (tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
`, tenantID, providerKey, kind, displayName, issuerURL, clientID, now, now)
		if err != nil {
			return AuthProvider{}, fmt.Errorf("insert auth provider: %w", err)
		}
	} else if err == nil {
		// Update
		_, err = s.db.ExecContext(ctx, `
UPDATE auth_providers
SET kind = ?, display_name = ?, issuer_url = ?, client_id = ?, enabled = 1, updated_at = ?
WHERE tenant_id = ? AND provider_key = ?
`, kind, displayName, issuerURL, clientID, now, tenantID, providerKey)
		if err != nil {
			return AuthProvider{}, fmt.Errorf("update auth provider: %w", err)
		}
		// query newly updated provider
		return s.GetAuthProvider(ctx, tenantID, providerKey)
	} else {
		return AuthProvider{}, fmt.Errorf("query existing auth provider: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return AuthProvider{}, fmt.Errorf("get last auth provider id: %w", err)
	}

	return s.getAuthProviderByID(ctx, id)
}

// GetAuthProvider returns a single auth provider for a tenant
func (s *ControlPlaneStore) GetAuthProvider(ctx context.Context, tenantID int64, providerKey string) (AuthProvider, error) {
	var p AuthProvider
	var enabled int
	err := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at
FROM auth_providers
WHERE tenant_id = ? AND provider_key = ?
`, tenantID, providerKey).Scan(&p.ID, &p.TenantID, &p.ProviderKey, &p.Kind, &p.DisplayName, &p.IssuerURL, &p.ClientID, &enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return AuthProvider{}, fmt.Errorf("get auth provider: %w", err)
	}
	p.Enabled = enabled == 1
	return p, nil
}

func (s *ControlPlaneStore) getAuthProviderByID(ctx context.Context, id int64) (AuthProvider, error) {
	var p AuthProvider
	var enabled int
	err := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at
FROM auth_providers
WHERE id = ?
`, id).Scan(&p.ID, &p.TenantID, &p.ProviderKey, &p.Kind, &p.DisplayName, &p.IssuerURL, &p.ClientID, &enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return AuthProvider{}, fmt.Errorf("get auth provider by id: %w", err)
	}
	p.Enabled = enabled == 1
	return p, nil
}

// DeleteAuthProvider soft-deletes an auth provider
func (s *ControlPlaneStore) DeleteAuthProvider(ctx context.Context, tenantID int64, providerKey string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE auth_providers
SET enabled = 0, updated_at = ?
WHERE tenant_id = ? AND provider_key = ?
`, time.Now().UTC(), tenantID, providerKey)
	if err != nil {
		return fmt.Errorf("delete auth provider: %w", err)
	}
	return nil
}

func loadResolvedUserTx(ctx context.Context, tx *sql.Tx, userID int64) (ResolvedUser, error) {
	var resolved ResolvedUser
	var superAdmin int
	err := tx.QueryRowContext(ctx, `
SELECT id, email, display_name, is_super_admin
FROM users
WHERE id = ?
`, userID).Scan(&resolved.UserID, &resolved.Email, &resolved.DisplayName, &superAdmin)
	if err != nil {
		return ResolvedUser{}, fmt.Errorf("load resolved user: %w", err)
	}
	resolved.SuperAdmin = superAdmin == 1

	err = tx.QueryRowContext(ctx, `
SELECT t.id, t.slug, t.name, t.db_path, tm.role
FROM tenant_memberships tm
JOIN tenants t ON t.id = tm.tenant_id
WHERE tm.user_id = ? AND t.active = 1
ORDER BY tm.created_at ASC, tm.id ASC
LIMIT 1
`, userID).Scan(&resolved.TenantID, &resolved.TenantSlug, &resolved.TenantName, &resolved.TenantDBPath, &resolved.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return ResolvedUser{}, fmt.Errorf("user has no active tenant membership")
		}
		return ResolvedUser{}, fmt.Errorf("load resolved tenant membership: %w", err)
	}

	return resolved, nil
}

const controlPlaneSchema = `
CREATE TABLE IF NOT EXISTS tenants (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	slug TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	db_path TEXT NOT NULL,
	active INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT NOT NULL DEFAULT '',
	display_name TEXT NOT NULL DEFAULT '',
	is_super_admin INTEGER NOT NULL DEFAULT 0,
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
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	UNIQUE(provider_key, provider_subject),
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tenant_memberships (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	role TEXT NOT NULL DEFAULT 'viewer',
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
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	UNIQUE(tenant_id, provider_key),
	FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS local_credentials (
	user_id INTEGER PRIMARY KEY,
	login_name TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
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
`

func (s *ControlPlaneStore) initSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, controlPlaneSchema); err != nil {
		return fmt.Errorf("initialize control-plane schema: %w", err)
	}
	if err := s.ensureTenantMembershipNotificationColumn(ctx); err != nil {
		return err
	}
	if err := s.ensureUserNotificationChannelsTable(ctx); err != nil {
		return err
	}
	return nil
}

func (s *ControlPlaneStore) ensureTenantMembershipNotificationColumn(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(tenant_memberships)`)
	if err != nil {
		return fmt.Errorf("inspect tenant_memberships columns: %w", err)
	}
	defer rows.Close()

	hasColumn := false
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("scan tenant_memberships column: %w", err)
		}
		if name == "notifications_email_enabled" {
			hasColumn = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate tenant_memberships columns: %w", err)
	}

	if hasColumn {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, `ALTER TABLE tenant_memberships ADD COLUMN notifications_email_enabled INTEGER NOT NULL DEFAULT 1`); err != nil {
		return fmt.Errorf("add tenant_memberships notifications_email_enabled column: %w", err)
	}
	return nil
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

// Admin Methods for Tenant Management

// GetAllTenants returns all tenants, optionally filtered by active status
func (s *ControlPlaneStore) GetAllTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, slug, name, db_path, active
FROM tenants
ORDER BY created_at ASC
`)
	if err != nil {
		return nil, fmt.Errorf("query all tenants: %w", err)
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		var t Tenant
		var active int
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.DBPath, &active); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		t.Active = active == 1
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}
	return tenants, nil
}

// CreateTenant creates a new tenant and returns it
func (s *ControlPlaneStore) CreateTenant(ctx context.Context, slug, name, dbPath string) (Tenant, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if !tenantSlugPattern.MatchString(slug) {
		return Tenant{}, fmt.Errorf("invalid tenant slug %q (allowed: a-z, 0-9, -; length 2-63)", slug)
	}
	if strings.TrimSpace(name) == "" {
		return Tenant{}, fmt.Errorf("tenant name is required")
	}
	if strings.TrimSpace(dbPath) == "" {
		return Tenant{}, fmt.Errorf("tenant db_path is required")
	}

	// Validate slug is unique
	_, err := s.GetTenantBySlug(ctx, slug)
	if err == nil {
		return Tenant{}, fmt.Errorf("tenant slug already exists: %s", slug)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, fmt.Errorf("check slug uniqueness: %w", err)
	}

	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
INSERT INTO tenants (slug, name, db_path, active, created_at, updated_at)
VALUES (?, ?, ?, 1, ?, ?)
`, slug, name, dbPath, now, now)
	if err != nil {
		return Tenant{}, fmt.Errorf("insert tenant: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return Tenant{}, fmt.Errorf("get last tenant id: %w", err)
	}

	tenant, err := s.GetTenantByID(ctx, id)
	if err != nil {
		return Tenant{}, err
	}
	if err := ensureTenantDatabaseReady(ctx, tenant.DBPath); err != nil {
		return Tenant{}, err
	}

	return tenant, nil
}

// UpdateTenant updates an existing tenant
func (s *ControlPlaneStore) UpdateTenant(ctx context.Context, id int64, name, dbPath string, active bool) (Tenant, error) {
	now := time.Now().UTC()
	activeInt := 0
	if active {
		activeInt = 1
	}

	_, err := s.db.ExecContext(ctx, `
UPDATE tenants
SET name = ?, db_path = ?, active = ?, updated_at = ?
WHERE id = ?
`, name, dbPath, activeInt, now, id)
	if err != nil {
		return Tenant{}, fmt.Errorf("update tenant: %w", err)
	}

	tenant, err := s.GetTenantByID(ctx, id)
	if err != nil {
		return Tenant{}, err
	}
	if err := ensureTenantDatabaseReady(ctx, tenant.DBPath); err != nil {
		return Tenant{}, err
	}

	return tenant, nil
}

func ensureTenantDatabaseReady(ctx context.Context, dbPath string) error {
	trimmedPath := strings.TrimSpace(dbPath)
	if trimmedPath == "" {
		return fmt.Errorf("tenant db_path is required")
	}

	dir := filepath.Dir(trimmedPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create tenant db directory: %w", err)
		}
	}

	tenantStore, err := Open(ctx, trimmedPath)
	if err != nil {
		return fmt.Errorf("initialize tenant database %q: %w", trimmedPath, err)
	}
	if err := tenantStore.Close(); err != nil {
		return fmt.Errorf("close initialized tenant database %q: %w", trimmedPath, err)
	}

	return nil
}

// DeactivateTenant soft-deactivates a tenant without deleting
func (s *ControlPlaneStore) DeactivateTenant(ctx context.Context, id int64) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
UPDATE tenants
SET active = 0, updated_at = ?
WHERE id = ?
`, now, id)
	if err != nil {
		return fmt.Errorf("deactivate tenant: %w", err)
	}
	return nil
}

// PurgeTenant permanently deletes a tenant and all control-plane records, then removes the tenant DB file.
func (s *ControlPlaneStore) PurgeTenant(ctx context.Context, id int64) error {
	tenant, err := s.GetTenantByID(ctx, id)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tenant purge transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_provider_secrets WHERE tenant_id = ?`, id); err != nil {
		return fmt.Errorf("purge auth provider secrets: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_providers WHERE tenant_id = ?`, id); err != nil {
		return fmt.Errorf("purge auth providers: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM tenant_memberships WHERE tenant_id = ?`, id); err != nil {
		return fmt.Errorf("purge tenant memberships: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, id); err != nil {
		return fmt.Errorf("purge tenant record: %w", err)
	}

	// Cleanup users that are no longer referenced by any membership or external identity.
	if _, err := tx.ExecContext(ctx, `
DELETE FROM local_credentials
WHERE user_id IN (
	SELECT u.id
	FROM users u
	LEFT JOIN tenant_memberships tm ON tm.user_id = u.id
	LEFT JOIN user_identities ui ON ui.user_id = u.id
	WHERE tm.user_id IS NULL AND ui.user_id IS NULL
)
`); err != nil {
		return fmt.Errorf("purge orphan local credentials: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM users
WHERE id IN (
	SELECT u.id
	FROM users u
	LEFT JOIN tenant_memberships tm ON tm.user_id = u.id
	LEFT JOIN user_identities ui ON ui.user_id = u.id
	WHERE tm.user_id IS NULL AND ui.user_id IS NULL
)
`); err != nil {
		return fmt.Errorf("purge orphan users: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tenant purge transaction: %w", err)
	}

	dbPath := strings.TrimSpace(tenant.DBPath)
	if dbPath != "" {
		if err := os.Remove(dbPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove tenant db file: %w", err)
		}
		if err := os.Remove(dbPath + "-wal"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove tenant db wal file: %w", err)
		}
		if err := os.Remove(dbPath + "-shm"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove tenant db shm file: %w", err)
		}
	}

	return nil
}

// Admin Methods for Provider Management

// UpdateAuthProviderSecret updates a provider's client secret using encrypted storage.
func (s *ControlPlaneStore) UpdateAuthProviderSecret(ctx context.Context, tenantID int64, providerKey, clientSecret string) error {
	providerKey = strings.TrimSpace(providerKey)
	clientSecret = strings.TrimSpace(clientSecret)
	if tenantID <= 0 || providerKey == "" {
		return fmt.Errorf("tenant_id and provider_key are required")
	}
	if clientSecret == "" {
		return fmt.Errorf("client secret is required")
	}
	if len(s.secretKey) == 0 {
		return fmt.Errorf("secret key is not configured")
	}

	sealed, err := encryptProviderSecret(s.secretKey, clientSecret)
	if err != nil {
		return fmt.Errorf("encrypt provider secret: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO auth_provider_secrets (tenant_id, provider_key, secret_ciphertext, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, provider_key) DO UPDATE SET
	secret_ciphertext = excluded.secret_ciphertext,
	updated_at = excluded.updated_at
`, tenantID, providerKey, sealed, now, now)
	if err != nil {
		return fmt.Errorf("upsert auth provider secret: %w", err)
	}

	return nil
}

func (s *ControlPlaneStore) GetAuthProviderSecret(ctx context.Context, tenantID int64, providerKey string) (string, error) {
	providerKey = strings.TrimSpace(providerKey)
	if tenantID <= 0 || providerKey == "" {
		return "", fmt.Errorf("tenant_id and provider_key are required")
	}
	if len(s.secretKey) == 0 {
		return "", fmt.Errorf("secret key is not configured")
	}

	var ciphertext string
	err := s.db.QueryRowContext(ctx, `
SELECT secret_ciphertext
FROM auth_provider_secrets
WHERE tenant_id = ? AND provider_key = ?
`, tenantID, providerKey).Scan(&ciphertext)
	if err != nil {
		return "", err
	}

	plaintext, err := decryptProviderSecret(s.secretKey, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt auth provider secret: %w", err)
	}

	return plaintext, nil
}

func encryptProviderSecret(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	payload := append(nonce, sealed...)
	return base64.RawStdEncoding.EncodeToString(payload), nil
}

func decryptProviderSecret(key []byte, ciphertext string) (string, error) {
	payload, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := payload[:nonceSize]
	data := payload[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (s *ControlPlaneStore) GetGlobalSMTPSettings(ctx context.Context) (GlobalSMTPSettings, error) {
	var settings GlobalSMTPSettings
	var passwordCiphertext string
	err := s.db.QueryRowContext(ctx, `
SELECT host, port, username, password_ciphertext, from_email, from_name, tls_mode
FROM global_smtp_settings
WHERE id = 1
`).Scan(&settings.Host, &settings.Port, &settings.Username, &passwordCiphertext, &settings.FromEmail, &settings.FromName, &settings.TLSMode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			settings.Port = 587
			settings.TLSMode = "starttls"
			return settings, nil
		}
		return GlobalSMTPSettings{}, fmt.Errorf("get global smtp settings: %w", err)
	}
	settings.PasswordConfigured = strings.TrimSpace(passwordCiphertext) != ""
	if settings.Port <= 0 {
		settings.Port = 587
	}
	settings.TLSMode = normalizeSMTPMode(settings.TLSMode)
	return settings, nil
}

func (s *ControlPlaneStore) UpsertGlobalSMTPSettings(ctx context.Context, settings GlobalSMTPSettings, password string) error {
	settings.Host = strings.TrimSpace(settings.Host)
	settings.Username = strings.TrimSpace(settings.Username)
	settings.FromEmail = strings.TrimSpace(settings.FromEmail)
	settings.FromName = strings.TrimSpace(settings.FromName)
	settings.TLSMode = normalizeSMTPMode(settings.TLSMode)
	if settings.Port <= 0 {
		settings.Port = 587
	}

	password = strings.TrimSpace(password)
	if password != "" && len(s.secretKey) == 0 {
		return fmt.Errorf("secret key is not configured")
	}

	var existingCiphertext string
	err := s.db.QueryRowContext(ctx, `
SELECT password_ciphertext
FROM global_smtp_settings
WHERE id = 1
`).Scan(&existingCiphertext)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load existing smtp password: %w", err)
	}

	passwordCiphertext := existingCiphertext
	if password != "" {
		sealed, encErr := encryptProviderSecret(s.secretKey, password)
		if encErr != nil {
			return fmt.Errorf("encrypt smtp password: %w", encErr)
		}
		passwordCiphertext = sealed
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO global_smtp_settings (id, host, port, username, password_ciphertext, from_email, from_name, tls_mode, updated_at)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	host = excluded.host,
	port = excluded.port,
	username = excluded.username,
	password_ciphertext = excluded.password_ciphertext,
	from_email = excluded.from_email,
	from_name = excluded.from_name,
	tls_mode = excluded.tls_mode,
	updated_at = excluded.updated_at
`, settings.Host, settings.Port, settings.Username, passwordCiphertext, settings.FromEmail, settings.FromName, settings.TLSMode, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("upsert global smtp settings: %w", err)
	}

	return nil
}

func (s *ControlPlaneStore) GetGlobalSMTPDeliveryConfig(ctx context.Context) (GlobalSMTPDeliveryConfig, error) {
	settings, err := s.GetGlobalSMTPSettings(ctx)
	if err != nil {
		return GlobalSMTPDeliveryConfig{}, err
	}

	var passwordCiphertext string
	err = s.db.QueryRowContext(ctx, `
SELECT password_ciphertext
FROM global_smtp_settings
WHERE id = 1
`).Scan(&passwordCiphertext)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GlobalSMTPDeliveryConfig{Settings: settings}, nil
		}
		return GlobalSMTPDeliveryConfig{}, fmt.Errorf("load smtp password: %w", err)
	}

	cfg := GlobalSMTPDeliveryConfig{Settings: settings}
	if strings.TrimSpace(passwordCiphertext) == "" {
		return cfg, nil
	}
	if len(s.secretKey) == 0 {
		return GlobalSMTPDeliveryConfig{}, fmt.Errorf("secret key is not configured")
	}

	password, err := decryptProviderSecret(s.secretKey, passwordCiphertext)
	if err != nil {
		return GlobalSMTPDeliveryConfig{}, fmt.Errorf("decrypt smtp password: %w", err)
	}
	cfg.Password = password
	return cfg, nil
}

func normalizeSMTPMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "none", "tls":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "starttls"
	}
}

func (s *ControlPlaneStore) InsertAuditEvent(ctx context.Context, actor, action, targetType string, targetID int64, details string) error {
	if strings.TrimSpace(action) == "" {
		return fmt.Errorf("audit action is required")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_events (actor, action, target_type, target_id, details, created_at)
VALUES (?, ?, ?, ?, ?, ?)
`, strings.TrimSpace(actor), strings.TrimSpace(action), strings.TrimSpace(targetType), targetID, strings.TrimSpace(details), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ListRecentAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT id, actor, action, target_type, target_id, details, created_at
FROM audit_events
ORDER BY id DESC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	items := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(&event.ID, &event.Actor, &event.Action, &event.TargetType, &event.TargetID, &event.Details, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		items = append(items, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}

	return items, nil
}

func (s *ControlPlaneStore) ListAuditEventsFiltered(ctx context.Context, limit int, action, actor, targetType string) ([]AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	action = strings.TrimSpace(action)
	actor = strings.TrimSpace(actor)
	targetType = strings.TrimSpace(targetType)

	query := `
SELECT id, actor, action, target_type, target_id, details, created_at
FROM audit_events
WHERE 1=1
`
	args := make([]any, 0, 4)

	if action != "" {
		query += " AND lower(action) = lower(?)"
		args = append(args, action)
	}
	if actor != "" {
		query += " AND lower(actor) LIKE lower(?)"
		args = append(args, "%"+actor+"%")
	}
	if targetType != "" {
		query += " AND lower(target_type) = lower(?)"
		args = append(args, targetType)
	}

	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query filtered audit events: %w", err)
	}
	defer rows.Close()

	items := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(&event.ID, &event.Actor, &event.Action, &event.TargetType, &event.TargetID, &event.Details, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan filtered audit event: %w", err)
		}
		items = append(items, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate filtered audit events: %w", err)
	}

	return items, nil
}

func (s *ControlPlaneStore) ListAuditActionKeys(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT action
FROM audit_events
WHERE trim(action) <> ''
GROUP BY action
ORDER BY action ASC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit action keys: %w", err)
	}
	defer rows.Close()

	items := make([]string, 0, limit)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan audit action key: %w", err)
		}
		value = strings.TrimSpace(value)
		if value != "" {
			items = append(items, value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit action keys: %w", err)
	}
	return items, nil
}

func (s *ControlPlaneStore) ListAuditTargetTypes(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT target_type
FROM audit_events
WHERE trim(target_type) <> ''
GROUP BY target_type
ORDER BY target_type ASC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit target types: %w", err)
	}
	defer rows.Close()

	items := make([]string, 0, limit)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan audit target type: %w", err)
		}
		value = strings.TrimSpace(value)
		if value != "" {
			items = append(items, value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit target types: %w", err)
	}
	return items, nil
}

func (s *ControlPlaneStore) ListTenantNotificationEmails(ctx context.Context, tenantID int64) ([]string, error) {
	if tenantID <= 0 {
		return nil, fmt.Errorf("tenant id is required")
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT trim(u.email)
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
JOIN tenants t ON t.id = tm.tenant_id
WHERE tm.tenant_id = ?
	AND t.active = 1
	AND tm.notifications_email_enabled = 1
	AND trim(u.email) <> ''
ORDER BY lower(trim(u.email)) ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query tenant notification emails: %w", err)
	}
	defer rows.Close()

	items := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan tenant notification email: %w", err)
		}
		value = strings.TrimSpace(value)
		if value != "" {
			items = append(items, value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant notification emails: %w", err)
	}

	return items, nil
}

func (s *ControlPlaneStore) GetTenantUser(ctx context.Context, tenantID, userID int64) (TenantUser, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT
	u.id,
	tm.tenant_id,
	COALESCE(lc.login_name, ''),
	u.email,
	u.display_name,
	tm.role,
	u.is_super_admin,
	u.last_login_at,
	CASE WHEN lc.user_id IS NULL THEN 0 ELSE 1 END AS has_local_credentials,
	CASE WHEN EXISTS (SELECT 1 FROM user_identities ui WHERE ui.user_id = u.id) THEN 1 ELSE 0 END AS has_oidc_identity
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
LEFT JOIN local_credentials lc ON lc.user_id = u.id
WHERE tm.tenant_id = ? AND u.id = ?
LIMIT 1
`, tenantID, userID)
	item, err := scanTenantUser(row)
	if err != nil {
		return TenantUser{}, err
	}
	return item, nil
}

func (s *ControlPlaneStore) GetUserNotificationSettings(ctx context.Context, tenantID, userID int64) (UserNotificationSettings, error) {
	if tenantID <= 0 || userID <= 0 {
		return UserNotificationSettings{}, fmt.Errorf("tenant id and user id are required")
	}

	var settings UserNotificationSettings
	var emailEnabled int
	var hasLocal int
	err := s.db.QueryRowContext(ctx, `
SELECT tm.notifications_email_enabled,
	CASE WHEN lc.user_id IS NULL THEN 0 ELSE 1 END AS has_local_credentials
FROM tenant_memberships tm
LEFT JOIN local_credentials lc ON lc.user_id = tm.user_id
WHERE tm.tenant_id = ? AND tm.user_id = ?
LIMIT 1
`, tenantID, userID).Scan(&emailEnabled, &hasLocal)
	if err != nil {
		if err == sql.ErrNoRows {
			return UserNotificationSettings{}, sql.ErrNoRows
		}
		return UserNotificationSettings{}, fmt.Errorf("load email notification setting: %w", err)
	}
	settings.EmailEnabled = emailEnabled == 1
	settings.HasLocalCredentials = hasLocal == 1

	var (
		enabled          int
		configJSON       string
		secretCiphertext string
	)
	err = s.db.QueryRowContext(ctx, `
SELECT enabled, config_json, secret_ciphertext
FROM user_notification_channels
WHERE tenant_id = ? AND user_id = ? AND kind = 'matrix'
LIMIT 1
`, tenantID, userID).Scan(&enabled, &configJSON, &secretCiphertext)
	if err != nil {
		if err != sql.ErrNoRows {
			return UserNotificationSettings{}, fmt.Errorf("load matrix notification setting: %w", err)
		}
		return settings, nil
	}

	var parsed struct {
		HomeserverURL string `json:"homeserver_url"`
		RoomID        string `json:"room_id"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(configJSON)), &parsed); err == nil {
		settings.MatrixHomeserver = strings.TrimSpace(parsed.HomeserverURL)
		settings.MatrixRoomID = strings.TrimSpace(parsed.RoomID)
	}
	if strings.TrimSpace(secretCiphertext) != "" && len(s.secretKey) > 0 {
		if token, err := decryptProviderSecret(s.secretKey, secretCiphertext); err == nil {
			settings.MatrixAccessToken = token
		}
	}
	settings.MatrixEnabled = enabled == 1

	return settings, nil
}

func (s *ControlPlaneStore) SaveUserNotificationSettings(ctx context.Context, tenantID, userID int64, emailEnabled bool, matrixEnabled bool, homeserverURL, roomID, accessToken string) error {
	if tenantID <= 0 || userID <= 0 {
		return fmt.Errorf("tenant id and user id are required")
	}

	homeserverURL = strings.TrimSpace(strings.TrimRight(homeserverURL, "/"))
	roomID = strings.TrimSpace(roomID)
	accessToken = strings.TrimSpace(accessToken)
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin save user notification settings transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
UPDATE tenant_memberships
SET notifications_email_enabled = ?, updated_at = ?
WHERE tenant_id = ? AND user_id = ?
`, boolToInt(emailEnabled), now, tenantID, userID)
	if err != nil {
		return fmt.Errorf("update email notification opt-in: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update email notification rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	configJSONBytes, err := json.Marshal(map[string]string{
		"homeserver_url": homeserverURL,
		"room_id":        roomID,
	})
	if err != nil {
		return fmt.Errorf("marshal matrix config: %w", err)
	}

	var secretCiphertext string
	if accessToken != "" {
		if len(s.secretKey) == 0 {
			return fmt.Errorf("secret key is not configured")
		}
		sealed, err := encryptProviderSecret(s.secretKey, accessToken)
		if err != nil {
			return fmt.Errorf("encrypt matrix access token: %w", err)
		}
		secretCiphertext = sealed
	} else {
		err = tx.QueryRowContext(ctx, `
SELECT secret_ciphertext
FROM user_notification_channels
WHERE tenant_id = ? AND user_id = ? AND kind = 'matrix'
LIMIT 1
`, tenantID, userID).Scan(&secretCiphertext)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("load existing matrix access token: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO user_notification_channels (tenant_id, user_id, kind, enabled, config_json, secret_ciphertext, created_at, updated_at)
VALUES (?, ?, 'matrix', ?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, user_id, kind) DO UPDATE SET
	enabled = excluded.enabled,
	config_json = excluded.config_json,
	secret_ciphertext = excluded.secret_ciphertext,
	updated_at = excluded.updated_at
`, tenantID, userID, boolToInt(matrixEnabled), string(configJSONBytes), secretCiphertext, now, now); err != nil {
		return fmt.Errorf("upsert matrix notification channel: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit save user notification settings: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ListTenantMatrixNotificationTargets(ctx context.Context, tenantID int64) ([]MatrixNotificationTarget, error) {
	if tenantID <= 0 {
		return nil, fmt.Errorf("tenant id is required")
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT unc.user_id, unc.config_json, unc.secret_ciphertext
FROM user_notification_channels unc
JOIN tenant_memberships tm ON tm.tenant_id = unc.tenant_id AND tm.user_id = unc.user_id
JOIN tenants t ON t.id = tm.tenant_id
WHERE unc.tenant_id = ?
	AND unc.kind = 'matrix'
	AND unc.enabled = 1
	AND t.active = 1
ORDER BY unc.user_id ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query tenant matrix notification targets: %w", err)
	}
	defer rows.Close()

	items := make([]MatrixNotificationTarget, 0)
	for rows.Next() {
		var (
			userID           int64
			configJSON       string
			secretCiphertext string
		)
		if err := rows.Scan(&userID, &configJSON, &secretCiphertext); err != nil {
			return nil, fmt.Errorf("scan matrix notification target: %w", err)
		}
		if strings.TrimSpace(secretCiphertext) == "" || len(s.secretKey) == 0 {
			continue
		}
		token, err := decryptProviderSecret(s.secretKey, secretCiphertext)
		if err != nil {
			continue
		}
		var cfg struct {
			HomeserverURL string `json:"homeserver_url"`
			RoomID        string `json:"room_id"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(configJSON)), &cfg); err != nil {
			continue
		}
		homeserverURL := strings.TrimSpace(cfg.HomeserverURL)
		roomID := strings.TrimSpace(cfg.RoomID)
		if homeserverURL == "" || roomID == "" || strings.TrimSpace(token) == "" {
			continue
		}
		items = append(items, MatrixNotificationTarget{
			UserID:        userID,
			HomeserverURL: homeserverURL,
			RoomID:        roomID,
			AccessToken:   token,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate matrix notification targets: %w", err)
	}

	return items, nil
}

func (s *ControlPlaneStore) UpdateUserProfileForTenant(ctx context.Context, tenantID, userID int64, email, displayName string) error {
	email = strings.TrimSpace(email)
	displayName = strings.TrimSpace(displayName)

	result, err := s.db.ExecContext(ctx, `
UPDATE users
SET email = ?, display_name = ?, updated_at = ?
WHERE id = ?
	AND EXISTS (
		SELECT 1
		FROM tenant_memberships tm
		WHERE tm.user_id = users.id AND tm.tenant_id = ?
	)
`, email, displayName, time.Now().UTC(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("update user profile: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update user profile rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *ControlPlaneStore) ChangeOwnLocalPassword(ctx context.Context, tenantID, userID int64, currentPassword, newPassword string) error {
	currentPassword = strings.TrimSpace(currentPassword)
	newPassword = strings.TrimSpace(newPassword)
	if currentPassword == "" || newPassword == "" {
		return fmt.Errorf("current password and new password are required")
	}

	var passwordHash string
	err := s.db.QueryRowContext(ctx, `
SELECT lc.password_hash
FROM local_credentials lc
JOIN tenant_memberships tm ON tm.user_id = lc.user_id
WHERE lc.user_id = ? AND tm.tenant_id = ?
LIMIT 1
`, userID, tenantID).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.ErrNoRows
		}
		return fmt.Errorf("load current local password hash: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(currentPassword)); err != nil {
		return fmt.Errorf("current password is invalid")
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE local_credentials
SET password_hash = ?, updated_at = ?
WHERE user_id = ?
`, string(newPasswordHash), time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("update local password: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update local password rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
