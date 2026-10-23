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

// APITokenScopeMetrics grants read access to the tenant's Prometheus metrics endpoint.
const APITokenScopeMetrics = "metrics"

const (
	apiTokenPrefix          = "goup_"
	apiTokenNameMaxRunes    = 80
	apiTokenLastUsedRefresh = time.Minute
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
	return nil
}

func hashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// CreateAPIToken stores a new token and returns the plain value, which cannot be recovered later.
func (s *ControlPlaneStore) CreateAPIToken(ctx context.Context, tenantID int64, name, scope, createdBy string) (string, APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", APIToken{}, errors.New("token name is required")
	}
	if len([]rune(name)) > apiTokenNameMaxRunes {
		name = string([]rune(name)[:apiTokenNameMaxRunes])
	}
	if scope != APITokenScopeMetrics {
		return "", APIToken{}, errors.New("unsupported token scope")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", APIToken{}, fmt.Errorf("generate api token: %w", err)
	}
	plain := apiTokenPrefix + hex.EncodeToString(raw)
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
INSERT INTO api_tokens (tenant_id, name, token_hash, scope, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?)
`, tenantID, name, hashAPIToken(plain), scope, strings.TrimSpace(createdBy), now)
	if err != nil {
		return "", APIToken{}, fmt.Errorf("insert api token: %w", err)
	}
	id, _ := result.LastInsertId()
	return plain, APIToken{ID: id, TenantID: tenantID, Name: name, Scope: scope, CreatedBy: strings.TrimSpace(createdBy), CreatedAt: now}, nil
}

// ListAPITokens returns the tenant's tokens, newest first.
func (s *ControlPlaneStore) ListAPITokens(ctx context.Context, tenantID int64) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, name, scope, created_by, created_at, last_used_at
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
		)
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.Scope, &item.CreatedBy, &item.CreatedAt, &lastUsed); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		if lastUsed.Valid {
			t := lastUsed.Time
			item.LastUsedAt = &t
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

// AuthenticateAPIToken reports whether token is a valid token of the tenant with the given scope.
// The token is looked up by its SHA-256 hash (unique index), so no secret-dependent comparison
// happens on the plain value.
func (s *ControlPlaneStore) AuthenticateAPIToken(ctx context.Context, tenantID int64, scope, token string) (bool, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return false, nil
	}
	var (
		id       int64
		lastUsed sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, last_used_at FROM api_tokens WHERE token_hash = ? AND tenant_id = ? AND scope = ?
`, hashAPIToken(token), tenantID, scope).Scan(&id, &lastUsed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("lookup api token: %w", err)
	}
	now := time.Now().UTC()
	if !lastUsed.Valid || now.Sub(lastUsed.Time) >= apiTokenLastUsedRefresh {
		_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now, id)
	}
	return true, nil
}
