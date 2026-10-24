package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// OIDCClaims are the identity attributes relevant for the provider access policy.
type OIDCClaims struct {
	Email string
	// EmailVerified is nil when the IdP did not send the email_verified claim.
	EmailVerified *bool
	Groups        []string
}

// SplitPolicyList splits a comma/newline/semicolon/space separated list.
func SplitPolicyList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// NormalizePolicyList canonicalizes a list for storage (comma separated).
func NormalizePolicyList(raw string, lower bool) string {
	items := SplitPolicyList(raw)
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if lower {
			item = strings.ToLower(strings.TrimPrefix(item, "@"))
		}
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return strings.Join(out, ",")
}

// CheckOIDCAccess evaluates the provider's access policy for an identity.
//   - with RequireEmailVerified, the email_verified claim must be present and true.
//   - allowed_email_domains requires an email in one of the domains (verified only
//     when RequireEmailVerified is set).
//   - allowed_groups requires membership in at least one listed group.
func (p AuthProvider) CheckOIDCAccess(claims OIDCClaims) error {
	if p.RequireEmailVerified && (claims.EmailVerified == nil || !*claims.EmailVerified) {
		return fmt.Errorf("%w: email is not verified", ErrOIDCAccessDenied)
	}
	if domains := SplitPolicyList(p.AllowedEmailDomains); len(domains) > 0 {
		email := strings.ToLower(strings.TrimSpace(claims.Email))
		at := strings.LastIndexByte(email, '@')
		if at <= 0 || at == len(email)-1 {
			return fmt.Errorf("%w: email missing", ErrOIDCAccessDenied)
		}
		domain := email[at+1:]
		allowed := false
		for _, d := range domains {
			if strings.EqualFold(strings.TrimPrefix(d, "@"), domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: email domain not allowed", ErrOIDCAccessDenied)
		}
	}
	if groups := SplitPolicyList(p.AllowedGroups); len(groups) > 0 {
		allowed := false
		for _, want := range groups {
			for _, have := range claims.Groups {
				if strings.TrimSpace(have) == want {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: required group missing", ErrOIDCAccessDenied)
		}
	}
	return nil
}

// UpdateAuthProviderPolicy stores the OIDC access policy of a provider.
func (s *ControlPlaneStore) UpdateAuthProviderPolicy(ctx context.Context, tenantID int64, providerKey, defaultRole, allowedEmailDomains, allowedGroups string, requireEmailVerified bool) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE auth_providers
SET default_role = ?, allowed_email_domains = ?, allowed_groups = ?, require_email_verified = ?, updated_at = ?
WHERE tenant_id = ? AND provider_key = ?
`, NormalizeTenantRole(defaultRole), NormalizePolicyList(allowedEmailDomains, true), NormalizePolicyList(allowedGroups, false), boolToInt(requireEmailVerified), time.Now().UTC(), tenantID, strings.TrimSpace(providerKey))
	if err != nil {
		return fmt.Errorf("update auth provider policy: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListBlockedTenantUsers returns users removed from the tenant (blocked
// memberships). They cannot sign in until re-added with UnblockTenantUser.
func (s *ControlPlaneStore) ListBlockedTenantUsers(ctx context.Context, tenantID int64) ([]TenantUser, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
	u.id,
	tm.tenant_id,
	COALESCE(lc.login_name, ''),
	u.email,
	u.display_name,
	COALESCE(NULLIF(u.preferred_language, ''), 'en'),
	tm.role,
	tm.session_version,
	u.last_login_at,
	CASE WHEN lc.user_id IS NULL THEN 0 ELSE 1 END,
	CASE WHEN EXISTS (SELECT 1 FROM user_identities ui WHERE ui.user_id = u.id) THEN 1 ELSE 0 END
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
LEFT JOIN local_credentials lc ON lc.user_id = u.id AND lc.tenant_id = tm.tenant_id
WHERE tm.blocked = 1 AND tm.tenant_id = ?
ORDER BY lower(COALESCE(NULLIF(u.email, ''), NULLIF(u.display_name, ''), '')), u.id ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query blocked tenant users: %w", err)
	}
	defer rows.Close()
	items := make([]TenantUser, 0)
	for rows.Next() {
		item, err := scanTenantUser(rows)
		if err != nil {
			return nil, err
		}
		item.Blocked = true
		items = append(items, item)
	}
	return items, rows.Err()
}

// UnblockTenantUser re-adds a previously removed user with the given role.
func (s *ControlPlaneStore) UnblockTenantUser(ctx context.Context, tenantID, userID int64, role string) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE tenant_memberships
SET blocked = 0, role = ?, session_version = session_version + 1, updated_at = ?
WHERE tenant_id = ? AND user_id = ? AND blocked = 1
`, NormalizeTenantRole(role), time.Now().UTC(), tenantID, userID)
	if err != nil {
		return fmt.Errorf("unblock tenant user: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// BumpTenantMembershipSessionVersion invalidates all existing sessions of a
// member (used on logout and security-relevant changes).
func (s *ControlPlaneStore) BumpTenantMembershipSessionVersion(ctx context.Context, tenantID, userID int64) error {
	return s.bumpTenantMembershipSessionVersion(ctx, tenantID, userID)
}

// LocalPasswordHash returns the stored bcrypt hash of a tenant member's local
// credentials. It is used to bind password reset tokens to the current password.
func (s *ControlPlaneStore) LocalPasswordHash(ctx context.Context, tenantID, userID int64) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `
SELECT lc.password_hash
FROM local_credentials lc
JOIN tenant_memberships tm ON tm.user_id = lc.user_id AND tm.tenant_id = lc.tenant_id
WHERE lc.tenant_id = ? AND lc.user_id = ? AND tm.blocked = 0
`, tenantID, userID).Scan(&hash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", sql.ErrNoRows
		}
		return "", fmt.Errorf("load local password hash: %w", err)
	}
	return hash, nil
}

// BumpControlPlaneAdminSessionVersion invalidates all control-plane admin sessions.
func (s *ControlPlaneStore) BumpControlPlaneAdminSessionVersion(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE control_plane_admins SET session_version = session_version + 1, updated_at = ? WHERE id = 1`, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("bump control plane admin session version: %w", err)
	}
	return nil
}
