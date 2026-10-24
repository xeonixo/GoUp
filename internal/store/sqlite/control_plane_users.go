package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type ResolvedUser struct {
	UserID            int64
	Email             string
	DisplayName       string
	PreferredLanguage string
	TenantID          int64
	TenantSlug        string
	TenantName        string
	TenantDBPath      string
	Role              string
	SessionVersion    int64
}

type LocalUser struct {
	UserID      int64
	TenantID    int64
	LoginName   string
	Email       string
	DisplayName string
	Role        string
	LastLoginAt *time.Time
}

type TenantUser struct {
	UserID              int64
	TenantID            int64
	LoginName           string
	Email               string
	DisplayName         string
	PreferredLanguage   string
	Role                string
	SessionVersion      int64
	LastLoginAt         *time.Time
	HasLocalCredentials bool
	HasOIDCIdentity     bool
	Blocked             bool
}

func (s *ControlPlaneStore) ListLocalUsersByTenant(ctx context.Context, tenantID int64) ([]LocalUser, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT u.id, tm.tenant_id, lc.login_name, u.email, u.display_name, tm.role, u.last_login_at
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
JOIN local_credentials lc ON lc.user_id = u.id
WHERE tm.blocked = 0 AND tm.tenant_id = ?
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
SELECT u.id, tm.tenant_id, lc.login_name, u.email, u.display_name, tm.role, u.last_login_at
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
JOIN local_credentials lc ON lc.user_id = u.id
WHERE tm.blocked = 0 AND tm.tenant_id = ? AND u.id = ?
LIMIT 1
`, tenantID, userID)

	item, err := scanLocalUser(row)
	if err != nil {
		return LocalUser{}, err
	}
	return item, nil
}

func (s *ControlPlaneStore) CreateLocalUserForTenant(ctx context.Context, tenantID int64, loginName, password, email, displayName, role string) (LocalUser, error) {
	loginName = strings.TrimSpace(loginName)
	email = strings.TrimSpace(email)
	displayName = strings.TrimSpace(displayName)
	role = strings.TrimSpace(role)
	if loginName == "" || password == "" {
		return LocalUser{}, fmt.Errorf("login name and password are required")
	}
	if err := validateNewPassword(password); err != nil {
		return LocalUser{}, err
	}
	if role == "" {
		role = "viewer"
	}
	if !isValidTenantRole(role) {
		return LocalUser{}, fmt.Errorf("invalid role %q", role)
	}
	role = NormalizeTenantRole(role)

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
INSERT INTO users (email, display_name, preferred_language, created_at, updated_at, last_login_at)
VALUES (?, ?, '', ?, ?, NULL)
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
INSERT INTO local_credentials (user_id, tenant_id, login_name, password_hash, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
`, userID, tenantID, loginName, string(passwordHash), now, now); err != nil {
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
	if !isValidTenantRole(role) {
		return LocalUser{}, fmt.Errorf("invalid role %q", role)
	}
	role = NormalizeTenantRole(role)
	if strings.TrimSpace(password) != "" {
		if err := validateNewPassword(password); err != nil {
			return LocalUser{}, err
		}
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
SET role = ?, session_version = session_version + 1, updated_at = ?
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
SET role = ?, session_version = session_version + 1, updated_at = ?
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
WHERE lc.tenant_id = ? AND lc.user_id = ?
`, tenantID, userID).Scan(&hasLocalCredentials)
	if err != nil {
		return fmt.Errorf("check local user before delete: %w", err)
	}
	if hasLocalCredentials == 0 {
		return sql.ErrNoRows
	}

	return s.RemoveUserFromTenant(ctx, tenantID, userID)
}

func (s *ControlPlaneStore) FindLocalUserByEmail(ctx context.Context, tenantID int64, email string) (LocalUser, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return LocalUser{}, sql.ErrNoRows
	}

	row := s.db.QueryRowContext(ctx, `
SELECT u.id, tm.tenant_id, lc.login_name, u.email, u.display_name, tm.role, u.last_login_at
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
JOIN local_credentials lc ON lc.user_id = u.id
WHERE tm.blocked = 0 AND tm.tenant_id = ?
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

func scanLocalUser(scanner interface{ Scan(dest ...any) error }) (LocalUser, error) {
	var item LocalUser
	var lastLogin sql.NullTime
	if err := scanner.Scan(&item.UserID, &item.TenantID, &item.LoginName, &item.Email, &item.DisplayName, &item.Role, &lastLogin); err != nil {
		return LocalUser{}, fmt.Errorf("scan local user: %w", err)
	}
	if lastLogin.Valid {
		value := lastLogin.Time
		item.LastLoginAt = &value
	}
	return item, nil
}

func scanTenantUser(scanner interface{ Scan(dest ...any) error }) (TenantUser, error) {
	var item TenantUser
	var hasLocalCredentials int
	var hasOIDCIdentity int
	var lastLogin sql.NullTime
	if err := scanner.Scan(&item.UserID, &item.TenantID, &item.LoginName, &item.Email, &item.DisplayName, &item.PreferredLanguage, &item.Role, &item.SessionVersion, &lastLogin, &hasLocalCredentials, &hasOIDCIdentity); err != nil {
		return TenantUser{}, fmt.Errorf("scan tenant user: %w", err)
	}
	item.PreferredLanguage = normalizePreferredLanguage(item.PreferredLanguage)
	item.HasLocalCredentials = hasLocalCredentials == 1
	item.HasOIDCIdentity = hasOIDCIdentity == 1
	if lastLogin.Valid {
		value := lastLogin.Time
		item.LastLoginAt = &value
	}
	return item, nil
}
