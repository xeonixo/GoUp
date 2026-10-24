package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

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

	// OIDC access policy.
	DefaultRole         string // role granted to newly provisioned members ("viewer" or "admin")
	AllowedEmailDomains string // comma/newline separated; empty = any
	AllowedGroups       string // comma/newline separated; empty = any (matched against the "groups" claim)
	// RequireEmailVerified rejects identities whose email_verified claim is not true.
	// Off by default because several IdPs (e.g. Authentik) send email_verified=false.
	RequireEmailVerified bool
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

// GetAuthProvidersByTenant returns all enabled auth providers for a specific tenant
// TenantHasProviders reports whether the tenant requires authentication.
// A tenant is considered protected when it has at least one enabled
// auth_providers row OR at least one user membership (legacy safety-net for
// data created before the auth_providers table was introduced).
// Used by the auth middleware to decide whether a request must be
// authenticated regardless of the global GOUP_AUTH_MODE setting.
func (s *ControlPlaneStore) TenantHasProviders(ctx context.Context, tenantID int64) (bool, error) {
	var protected bool
	err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(
    SELECT 1 FROM auth_providers    WHERE tenant_id = ? AND enabled = 1
    UNION ALL
    SELECT 1 FROM tenant_memberships WHERE tenant_id = ?          LIMIT 1
)`, tenantID, tenantID).Scan(&protected)
	if err != nil {
		return false, fmt.Errorf("check tenant protection: %w", err)
	}
	return protected, nil
}

func (s *ControlPlaneStore) GetAuthProvidersByTenant(ctx context.Context, tenantID int64) ([]AuthProvider, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at, default_role, allowed_email_domains, allowed_groups, require_email_verified
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
		if err := rows.Scan(&p.ID, &p.TenantID, &p.ProviderKey, &p.Kind, &p.DisplayName, &p.IssuerURL, &p.ClientID, &enabled, &p.CreatedAt, &p.UpdatedAt, &p.DefaultRole, &p.AllowedEmailDomains, &p.AllowedGroups, &p.RequireEmailVerified); err != nil {
			return nil, fmt.Errorf("scan auth provider: %w", err)
		}
		p.Enabled = enabled == 1
		p.DefaultRole = NormalizeTenantRole(p.DefaultRole)
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
SELECT id, tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at, default_role, allowed_email_domains, allowed_groups, require_email_verified
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
		if err := rows.Scan(&p.ID, &p.TenantID, &p.ProviderKey, &p.Kind, &p.DisplayName, &p.IssuerURL, &p.ClientID, &enabled, &p.CreatedAt, &p.UpdatedAt, &p.DefaultRole, &p.AllowedEmailDomains, &p.AllowedGroups, &p.RequireEmailVerified); err != nil {
			return nil, fmt.Errorf("scan auth provider: %w", err)
		}
		p.Enabled = enabled == 1
		p.DefaultRole = NormalizeTenantRole(p.DefaultRole)
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
SELECT id, tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at, default_role, allowed_email_domains, allowed_groups, require_email_verified
FROM auth_providers
WHERE tenant_id = ? AND provider_key = ?
`, tenantID, providerKey).Scan(&p.ID, &p.TenantID, &p.ProviderKey, &p.Kind, &p.DisplayName, &p.IssuerURL, &p.ClientID, &enabled, &p.CreatedAt, &p.UpdatedAt, &p.DefaultRole, &p.AllowedEmailDomains, &p.AllowedGroups, &p.RequireEmailVerified)
	if err != nil {
		return AuthProvider{}, fmt.Errorf("get auth provider: %w", err)
	}
	p.Enabled = enabled == 1
	p.DefaultRole = NormalizeTenantRole(p.DefaultRole)
	return p, nil
}

func (s *ControlPlaneStore) getAuthProviderByID(ctx context.Context, id int64) (AuthProvider, error) {
	var p AuthProvider
	var enabled int
	err := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, provider_key, kind, display_name, issuer_url, client_id, enabled, created_at, updated_at, default_role, allowed_email_domains, allowed_groups, require_email_verified
FROM auth_providers
WHERE id = ?
`, id).Scan(&p.ID, &p.TenantID, &p.ProviderKey, &p.Kind, &p.DisplayName, &p.IssuerURL, &p.ClientID, &enabled, &p.CreatedAt, &p.UpdatedAt, &p.DefaultRole, &p.AllowedEmailDomains, &p.AllowedGroups, &p.RequireEmailVerified)
	if err != nil {
		return AuthProvider{}, fmt.Errorf("get auth provider by id: %w", err)
	}
	p.Enabled = enabled == 1
	p.DefaultRole = NormalizeTenantRole(p.DefaultRole)
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

	plaintext, err := s.decryptSecret(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt auth provider secret: %w", err)
	}

	return plaintext, nil
}
