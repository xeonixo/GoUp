package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func normalizePreferredLanguage(language string) string {
	language = strings.ToLower(strings.TrimSpace(language))
	if language == "" {
		return ""
	}
	if strings.HasPrefix(language, "de") {
		return "de"
	}
	if strings.HasPrefix(language, "en") {
		return "en"
	}
	parts := strings.Split(language, "-")
	if len(parts) > 0 {
		base := strings.TrimSpace(parts[0])
		if base != "" {
			return base
		}
	}
	return "en"
}

func (s *ControlPlaneStore) ListTenantUsers(ctx context.Context, tenantID int64) ([]TenantUser, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
	u.id,
	tm.tenant_id,
	COALESCE(lc.login_name, ''),
	u.email,
	u.display_name,
	COALESCE(NULLIF(u.preferred_language, ''), 'en') AS preferred_language,
	tm.role,
	tm.session_version,
	u.last_login_at,
	CASE WHEN lc.user_id IS NULL THEN 0 ELSE 1 END AS has_local_credentials,
	CASE WHEN EXISTS (SELECT 1 FROM user_identities ui WHERE ui.user_id = u.id) THEN 1 ELSE 0 END AS has_oidc_identity
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
LEFT JOIN local_credentials lc ON lc.user_id = u.id
WHERE tm.blocked = 0 AND tm.tenant_id = ?
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

func (s *ControlPlaneStore) GetTenantUser(ctx context.Context, tenantID, userID int64) (TenantUser, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT
	u.id,
	tm.tenant_id,
	COALESCE(lc.login_name, ''),
	u.email,
	u.display_name,
	COALESCE(NULLIF(u.preferred_language, ''), 'en') AS preferred_language,
	tm.role,
	tm.session_version,
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

func (s *ControlPlaneStore) UpdateUserProfileForTenant(ctx context.Context, tenantID, userID int64, email, displayName, preferredLanguage string) error {
	email = strings.TrimSpace(email)
	displayName = strings.TrimSpace(displayName)
	preferredLanguage = normalizePreferredLanguage(preferredLanguage)
	if preferredLanguage == "" {
		preferredLanguage = "en"
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE users
SET email = ?, display_name = ?, preferred_language = ?, updated_at = ?
WHERE id = ?
	AND EXISTS (
		SELECT 1
		FROM tenant_memberships tm
		WHERE tm.user_id = users.id AND tm.tenant_id = ?
	)
`, email, displayName, preferredLanguage, time.Now().UTC(), userID, tenantID)
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

func (s *ControlPlaneStore) UpdateUserPreferredLanguageForTenant(ctx context.Context, tenantID, userID int64, preferredLanguage string) error {
	preferredLanguage = normalizePreferredLanguage(preferredLanguage)
	if preferredLanguage == "" {
		preferredLanguage = "en"
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE users
SET preferred_language = ?, updated_at = ?
WHERE id = ?
	AND EXISTS (
		SELECT 1
		FROM tenant_memberships tm
		WHERE tm.user_id = users.id AND tm.tenant_id = ?
	)
`, preferredLanguage, time.Now().UTC(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("update user preferred language: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update user preferred language rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
