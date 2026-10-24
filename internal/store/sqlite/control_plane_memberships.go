package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// NormalizeTenantRole returns "admin" or "viewer"; anything else yields "viewer".
func NormalizeTenantRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return "admin"
	default:
		return "viewer"
	}
}

func isValidTenantRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "viewer":
		return true
	}
	return false
}

// RemoveUserFromTenant removes a user from a tenant. Users that have an OIDC
// identity for this tenant are kept as blocked memberships so that a later SSO
// login does not silently re-create the membership. All other users are
// deleted (and orphaned user records are cleaned up).
func (s *ControlPlaneStore) RemoveUserFromTenant(ctx context.Context, tenantID, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tenant user remove transaction: %w", err)
	}
	defer tx.Rollback()

	var tenantIdentityCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_identities WHERE user_id = ? AND tenant_id = ?`, userID, tenantID).Scan(&tenantIdentityCount); err != nil {
		return fmt.Errorf("count tenant user identities: %w", err)
	}

	if tenantIdentityCount > 0 {
		result, err := tx.ExecContext(ctx, `
UPDATE tenant_memberships
SET blocked = 1, session_version = session_version + 1, updated_at = ?
WHERE tenant_id = ? AND user_id = ?
`, time.Now().UTC(), tenantID, userID)
		if err != nil {
			return fmt.Errorf("block tenant user membership: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("block tenant user membership rows affected: %w", err)
		}
		if affected == 0 {
			return sql.ErrNoRows
		}
		// Local credentials of this tenant are removed; the identity row stays
		// so the block can be enforced.
		if _, err := tx.ExecContext(ctx, `DELETE FROM local_credentials WHERE user_id = ? AND tenant_id = ?`, userID, tenantID); err != nil {
			return fmt.Errorf("delete blocked user local credentials: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit tenant user block transaction: %w", err)
		}
		return nil
	}

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

func (s *ControlPlaneStore) bumpTenantMembershipSessionVersion(ctx context.Context, tenantID, userID int64) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE tenant_memberships
SET session_version = session_version + 1, updated_at = ?
WHERE tenant_id = ? AND user_id = ?
`, time.Now().UTC(), tenantID, userID)
	if err != nil {
		return fmt.Errorf("bump tenant membership session version: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("bump tenant membership session version rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *ControlPlaneStore) GetTenantMembershipSessionVersion(ctx context.Context, tenantID, userID int64) (int64, error) {
	var version int64
	err := s.db.QueryRowContext(ctx, `
SELECT tm.session_version
FROM tenant_memberships tm
JOIN tenants t ON t.id = tm.tenant_id
WHERE tm.blocked = 0 AND tm.tenant_id = ? AND tm.user_id = ? AND t.active = 1
LIMIT 1
`, tenantID, userID).Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, sql.ErrNoRows
		}
		return 0, fmt.Errorf("get tenant membership session version: %w", err)
	}
	return version, nil
}
