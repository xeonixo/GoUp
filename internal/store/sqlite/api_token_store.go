package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// API token scopes.
const (
	APITokenScopeMetrics       = "metrics"
	APITokenScopeMonitorsRead  = "monitors:read"
	APITokenScopeMonitorsWrite = "monitors:write"
)

const (
	apiTokenPrefix          = "goup_"
	apiTokenNameMaxRunes    = 80
	apiTokenLastUsedRefresh = time.Minute
	apiTokenMaxTTLDays      = 3650
)

// APIToken is a tenant-scoped bearer token. Only the SHA-256 hash is stored; the plain token is
// shown once at creation time.
type APIToken struct {
	ID         int64
	TenantID   int64
	Name       string
	Scope      string
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
}

func (s *ControlPlaneStore) ensureAPITokensTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS api_tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	scope TEXT NOT NULL,
	created_by TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL,
	last_used_at DATETIME,
	FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
)
`); err != nil {
		return fmt.Errorf("create api tokens table: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant ON api_tokens(tenant_id)`); err != nil {
		return fmt.Errorf("create api tokens index: %w", err)
	}
	if err := s.ensureAPITokenExpiresAtColumn(ctx); err != nil {
		return err
	}
	return nil
}

func (s *ControlPlaneStore) ensureAPITokenExpiresAtColumn(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "api_tokens", "expires_at")
	if err != nil {
		return err
	}
	if hasColumn {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE api_tokens ADD COLUMN expires_at DATETIME`); err != nil {
		return fmt.Errorf("add api_tokens.expires_at column: %w", err)
	}
	return nil
}

func hashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// NormalizeAPITokenScope returns a known scope or an empty string when unsupported.
func NormalizeAPITokenScope(scope string) string {
	switch strings.TrimSpace(scope) {
	case APITokenScopeMetrics:
		return APITokenScopeMetrics
	case APITokenScopeMonitorsRead:
		return APITokenScopeMonitorsRead
	case APITokenScopeMonitorsWrite:
		return APITokenScopeMonitorsWrite
	default:
		return ""
	}
}

func apiTokenScopeSatisfies(have, want string) bool {
	have = NormalizeAPITokenScope(have)
	want = NormalizeAPITokenScope(want)
	if have == "" || want == "" {
		return false
	}
	if have == want {
		return true
	}
	// monitors:write implies monitors:read
	return have == APITokenScopeMonitorsWrite && want == APITokenScopeMonitorsRead
}

func expiresAtFromTTLDays(ttlDays int) *time.Time {
	if ttlDays <= 0 {
		return nil
	}
	if ttlDays > apiTokenMaxTTLDays {
		ttlDays = apiTokenMaxTTLDays
	}
	t := time.Now().UTC().Add(time.Duration(ttlDays) * 24 * time.Hour)
	return &t
}

// CreateAPIToken stores a new token and returns the plain value, which cannot be recovered later.
// ttlDays <= 0 creates a non-expiring token.
func (s *ControlPlaneStore) CreateAPIToken(ctx context.Context, tenantID int64, name, scope, createdBy string, ttlDays int) (string, APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", APIToken{}, errors.New("token name is required")
	}
	if len([]rune(name)) > apiTokenNameMaxRunes {
		name = string([]rune(name)[:apiTokenNameMaxRunes])
	}
	scope = NormalizeAPITokenScope(scope)
	if scope == "" {
		return "", APIToken{}, errors.New("unsupported token scope")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", APIToken{}, fmt.Errorf("generate api token: %w", err)
	}
	plain := apiTokenPrefix + hex.EncodeToString(raw)
	now := time.Now().UTC()
	expiresAt := expiresAtFromTTLDays(ttlDays)
	var expires any
	if expiresAt != nil {
		expires = *expiresAt
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO api_tokens (tenant_id, name, token_hash, scope, created_by, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
`, tenantID, name, hashAPIToken(plain), scope, strings.TrimSpace(createdBy), now, expires)
	if err != nil {
		return "", APIToken{}, fmt.Errorf("insert api token: %w", err)
	}
	id, _ := result.LastInsertId()
	item := APIToken{ID: id, TenantID: tenantID, Name: name, Scope: scope, CreatedBy: strings.TrimSpace(createdBy), CreatedAt: now, ExpiresAt: expiresAt}
	return plain, item, nil
}

// ListAPITokens returns the tenant's tokens, newest first.
func (s *ControlPlaneStore) ListAPITokens(ctx context.Context, tenantID int64) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, name, scope, created_by, created_at, last_used_at, expires_at
FROM api_tokens
WHERE tenant_id = ?
ORDER BY created_at DESC, id DESC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()
	items := make([]APIToken, 0)
	for rows.Next() {
		var (
			item     APIToken
			lastUsed sql.NullTime
			expires  sql.NullTime
		)
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.Scope, &item.CreatedBy, &item.CreatedAt, &lastUsed, &expires); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		if lastUsed.Valid {
			t := lastUsed.Time
			item.LastUsedAt = &t
		}
		if expires.Valid {
			t := expires.Time
			item.ExpiresAt = &t
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api tokens: %w", err)
	}
	return items, nil
}

// RevokeAPIToken deletes a token of the tenant; it reports whether a token was removed.
func (s *ControlPlaneStore) RevokeAPIToken(ctx context.Context, tenantID, tokenID int64) (bool, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ? AND tenant_id = ?`, tokenID, tenantID)
	if err != nil {
		return false, fmt.Errorf("revoke api token: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// RotateAPIToken creates a replacement token with the same name/scope/expiry and revokes the old one.
func (s *ControlPlaneStore) RotateAPIToken(ctx context.Context, tenantID, tokenID int64, createdBy string) (string, APIToken, error) {
	var (
		name    string
		scope   string
		expires sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
SELECT name, scope, expires_at FROM api_tokens WHERE id = ? AND tenant_id = ?
`, tokenID, tenantID).Scan(&name, &scope, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", APIToken{}, sql.ErrNoRows
		}
		return "", APIToken{}, fmt.Errorf("lookup api token for rotate: %w", err)
	}
	ttlDays := 0
	if expires.Valid {
		remaining := time.Until(expires.Time)
		if remaining <= 0 {
			return "", APIToken{}, errors.New("token already expired")
		}
		ttlDays = int((remaining + 24*time.Hour - time.Nanosecond) / (24 * time.Hour))
		if ttlDays < 1 {
			ttlDays = 1
		}
	}
	plain, token, err := s.CreateAPIToken(ctx, tenantID, name, scope, createdBy, ttlDays)
	if err != nil {
		return "", APIToken{}, err
	}
	if removed, err := s.RevokeAPIToken(ctx, tenantID, tokenID); err != nil {
		_, _ = s.RevokeAPIToken(ctx, tenantID, token.ID)
		return "", APIToken{}, err
	} else if !removed {
		_, _ = s.RevokeAPIToken(ctx, tenantID, token.ID)
		return "", APIToken{}, sql.ErrNoRows
	}
	return plain, token, nil
}

// AuthenticateAPIToken reports whether token is a valid token of the tenant with the given scope.
// The token is looked up by its SHA-256 hash (unique index), so no secret-dependent comparison
// happens on the plain value. Expired tokens are rejected.
func (s *ControlPlaneStore) AuthenticateAPIToken(ctx context.Context, tenantID int64, scope, token string) (bool, error) {
	return s.AuthenticateAPITokenWithScopes(ctx, tenantID, token, scope)
}

// AuthenticateAPITokenWithScopes accepts a bearer token when its scope satisfies any required scope.
// monitors:write satisfies monitors:read.
func (s *ControlPlaneStore) AuthenticateAPITokenWithScopes(ctx context.Context, tenantID int64, token string, requiredScopes ...string) (bool, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(requiredScopes) == 0 {
		return false, nil
	}
	var (
		id        int64
		scope     string
		lastUsed  sql.NullTime
		expiresAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, scope, last_used_at, expires_at FROM api_tokens WHERE token_hash = ? AND tenant_id = ?
`, hashAPIToken(token), tenantID).Scan(&id, &scope, &lastUsed, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("lookup api token: %w", err)
	}
	now := time.Now().UTC()
	if expiresAt.Valid && !expiresAt.Time.After(now) {
		return false, nil
	}
	ok := false
	for _, want := range requiredScopes {
		if apiTokenScopeSatisfies(scope, want) {
			ok = true
			break
		}
	}
	if !ok {
		return false, nil
	}
	if !lastUsed.Valid || now.Sub(lastUsed.Time) >= apiTokenLastUsedRefresh {
		_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now, id)
	}
	return true, nil
}
