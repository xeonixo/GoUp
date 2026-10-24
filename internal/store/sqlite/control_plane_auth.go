package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// MinLocalPasswordLength is the minimum length for new or changed local passwords.
const MinLocalPasswordLength = 12

// ErrPasswordTooShort is returned when a new local password is too short.
var ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinLocalPasswordLength)

// ErrMembershipBlocked is returned when a removed (blocked) user tries to sign in again.
var ErrMembershipBlocked = errors.New("tenant membership is blocked")

// ErrOIDCAccessDenied is returned when the identity does not satisfy the provider access policy.
var ErrOIDCAccessDenied = errors.New("oidc identity not allowed by provider policy")

func validateNewPassword(password string) error {
	if len([]rune(password)) < MinLocalPasswordLength {
		return ErrPasswordTooShort
	}
	return nil
}

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// burnPasswordCompare spends the same CPU time as a real password check so
// that unknown users cannot be distinguished by timing.
func burnPasswordCompare(password string) {
	dummyHashOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("goup-dummy-password"), bcrypt.DefaultCost)
	})
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}

func (s *ControlPlaneStore) UpsertOIDCUserIdentity(ctx context.Context, providerKey, subject, email, displayName string, defaultTenantID int64, defaultRole string) (ResolvedUser, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ResolvedUser{}, fmt.Errorf("begin control-plane user transaction: %w", err)
	}
	defer tx.Rollback()

	defaultRole = NormalizeTenantRole(defaultRole)
	now := time.Now().UTC()
	var userID int64
	err = tx.QueryRowContext(ctx, `
SELECT user_id
FROM user_identities
WHERE tenant_id = ? AND provider_key = ? AND provider_subject = ?
`, defaultTenantID, providerKey, subject).Scan(&userID)
	switch err {
	case nil:
		if defaultTenantID > 0 {
			var blocked int
			berr := tx.QueryRowContext(ctx, `SELECT blocked FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?`, defaultTenantID, userID).Scan(&blocked)
			if berr == nil && blocked == 1 {
				return ResolvedUser{}, ErrMembershipBlocked
			}
		}
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
WHERE tenant_id = ? AND provider_key = ? AND provider_subject = ?
`, email, now, defaultTenantID, providerKey, subject); err != nil {
			return ResolvedUser{}, fmt.Errorf("update oidc identity: %w", err)
		}
	case sql.ErrNoRows:
		result, err := tx.ExecContext(ctx, `
INSERT INTO users (email, display_name, preferred_language, created_at, updated_at, last_login_at)
VALUES (?, ?, '', ?, ?, ?)
`, email, displayName, now, now, now)
		if err != nil {
			return ResolvedUser{}, fmt.Errorf("insert user from oidc identity: %w", err)
		}
		userID, err = result.LastInsertId()
		if err != nil {
			return ResolvedUser{}, fmt.Errorf("last user id from oidc identity: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO user_identities (user_id, provider_key, provider_subject, email, tenant_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
`, userID, providerKey, subject, email, defaultTenantID, now, now); err != nil {
			return ResolvedUser{}, fmt.Errorf("insert oidc identity: %w", err)
		}
	default:
		return ResolvedUser{}, fmt.Errorf("lookup oidc identity: %w", err)
	}

	if defaultTenantID > 0 {
		// New members get the provider's default role (viewer unless configured
		// otherwise). Existing memberships keep their role.
		if _, err := tx.ExecContext(ctx, `
INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, user_id) DO UPDATE SET
	updated_at = excluded.updated_at
`, defaultTenantID, userID, defaultRole, now, now); err != nil {
			return ResolvedUser{}, fmt.Errorf("ensure default tenant membership: %w", err)
		}
		var blocked int
		if err := tx.QueryRowContext(ctx, `SELECT blocked FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?`, defaultTenantID, userID).Scan(&blocked); err != nil {
			return ResolvedUser{}, fmt.Errorf("check tenant membership state: %w", err)
		}
		if blocked == 1 {
			return ResolvedUser{}, ErrMembershipBlocked
		}
	}

	var resolved ResolvedUser
	if defaultTenantID > 0 {
		resolved, err = loadResolvedUserForTenantTx(ctx, tx, userID, defaultTenantID)
	} else {
		resolved, err = loadResolvedUserTx(ctx, tx, userID)
	}
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
WHERE tm.blocked = 0 AND tm.tenant_id = ?
	AND lc.tenant_id = ?
	AND t.active = 1
	AND lower(lc.login_name) = lower(?)
LIMIT 1
`, tenantID, tenantID, loginName).Scan(&userID, &passwordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			burnPasswordCompare(password)
			return ResolvedUser{}, sql.ErrNoRows
		}
		return ResolvedUser{}, fmt.Errorf("find local user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return ResolvedUser{}, sql.ErrNoRows
	}

	resolved, err := s.resolveUserByIDForTenant(ctx, userID, tenantID)
	if err != nil {
		return ResolvedUser{}, err
	}

	_, _ = s.db.ExecContext(ctx, `
UPDATE users
SET last_login_at = ?, updated_at = ?
WHERE id = ?
`, time.Now().UTC(), time.Now().UTC(), userID)

	return resolved, nil
}

func (s *ControlPlaneStore) resolveUserByIDForTenant(ctx context.Context, userID, tenantID int64) (ResolvedUser, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ResolvedUser{}, fmt.Errorf("begin user lookup transaction: %w", err)
	}
	defer tx.Rollback()

	resolved, err := loadResolvedUserForTenantTx(ctx, tx, userID, tenantID)
	if err != nil {
		return ResolvedUser{}, err
	}

	if err := tx.Commit(); err != nil {
		return ResolvedUser{}, fmt.Errorf("commit user lookup transaction: %w", err)
	}

	return resolved, nil
}

func (s *ControlPlaneStore) ResetLocalUserPassword(ctx context.Context, tenantID, userID int64, newPassword string) error {
	newPassword = strings.TrimSpace(newPassword)
	if newPassword == "" {
		return fmt.Errorf("password is required")
	}
	if err := validateNewPassword(newPassword); err != nil {
		return err
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
			AND tm.blocked = 0 AND tm.tenant_id = ?
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
	if err := s.bumpTenantMembershipSessionVersion(ctx, tenantID, userID); err != nil {
		return err
	}
	return nil
}

func loadResolvedUserTx(ctx context.Context, tx *sql.Tx, userID int64) (ResolvedUser, error) {
	var resolved ResolvedUser
	err := tx.QueryRowContext(ctx, `
SELECT id, email, display_name, preferred_language
FROM users
WHERE id = ?
`, userID).Scan(&resolved.UserID, &resolved.Email, &resolved.DisplayName, &resolved.PreferredLanguage)
	if err != nil {
		return ResolvedUser{}, fmt.Errorf("load resolved user: %w", err)
	}
	resolved.PreferredLanguage = normalizePreferredLanguage(resolved.PreferredLanguage)

	err = tx.QueryRowContext(ctx, `
SELECT t.id, t.slug, t.name, t.db_path, tm.role, tm.session_version
FROM tenant_memberships tm
JOIN tenants t ON t.id = tm.tenant_id
WHERE tm.blocked = 0 AND tm.user_id = ? AND t.active = 1
ORDER BY tm.created_at ASC, tm.id ASC
LIMIT 1
`, userID).Scan(&resolved.TenantID, &resolved.TenantSlug, &resolved.TenantName, &resolved.TenantDBPath, &resolved.Role, &resolved.SessionVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			return ResolvedUser{}, fmt.Errorf("user has no active tenant membership")
		}
		return ResolvedUser{}, fmt.Errorf("load resolved tenant membership: %w", err)
	}

	return resolved, nil
}

func loadResolvedUserForTenantTx(ctx context.Context, tx *sql.Tx, userID, tenantID int64) (ResolvedUser, error) {
	var resolved ResolvedUser
	err := tx.QueryRowContext(ctx, `
SELECT id, email, display_name, preferred_language
FROM users
WHERE id = ?
`, userID).Scan(&resolved.UserID, &resolved.Email, &resolved.DisplayName, &resolved.PreferredLanguage)
	if err != nil {
		return ResolvedUser{}, fmt.Errorf("load resolved user: %w", err)
	}
	resolved.PreferredLanguage = normalizePreferredLanguage(resolved.PreferredLanguage)

	err = tx.QueryRowContext(ctx, `
SELECT t.id, t.slug, t.name, t.db_path, tm.role, tm.session_version
FROM tenant_memberships tm
JOIN tenants t ON t.id = tm.tenant_id
WHERE tm.blocked = 0 AND tm.user_id = ? AND tm.tenant_id = ? AND t.active = 1
LIMIT 1
`, userID, tenantID).Scan(&resolved.TenantID, &resolved.TenantSlug, &resolved.TenantName, &resolved.TenantDBPath, &resolved.Role, &resolved.SessionVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			return ResolvedUser{}, fmt.Errorf("user has no active tenant membership")
		}
		return ResolvedUser{}, fmt.Errorf("load resolved tenant membership: %w", err)
	}
	return resolved, nil
}

func (s *ControlPlaneStore) ChangeOwnLocalPassword(ctx context.Context, tenantID, userID int64, currentPassword, newPassword string) error {
	currentPassword = strings.TrimSpace(currentPassword)
	newPassword = strings.TrimSpace(newPassword)
	if currentPassword == "" || newPassword == "" {
		return fmt.Errorf("current password and new password are required")
	}
	if err := validateNewPassword(newPassword); err != nil {
		return err
	}

	var passwordHash string
	err := s.db.QueryRowContext(ctx, `
SELECT lc.password_hash
FROM local_credentials lc
JOIN tenant_memberships tm ON tm.user_id = lc.user_id
WHERE tm.blocked = 0 AND lc.user_id = ? AND tm.tenant_id = ?
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
	if err := s.bumpTenantMembershipSessionVersion(ctx, tenantID, userID); err != nil {
		return err
	}
	return nil
}
