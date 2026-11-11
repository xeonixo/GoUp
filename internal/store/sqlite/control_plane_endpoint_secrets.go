package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const tenantNotificationEndpointPreviousSecretGrace = 24 * time.Hour

type TenantNotificationEndpointSecret struct {
	TenantID   int64
	EndpointID int64
	Kind       string
}

// TenantNotificationEndpointSigningSecrets holds the current signing secret and, during
// rotate grace, the previous secret that receivers may still verify against.
type TenantNotificationEndpointSigningSecrets struct {
	Current             string
	Previous            string
	PreviousExpiresAt   *time.Time
	PreviousGraceActive bool
}

func (s *ControlPlaneStore) ensureTenantNotificationEndpointPreviousSecretColumns(ctx context.Context) error {
	columns := []struct {
		name string
		ddl  string
	}{
		{name: "previous_secret_ciphertext", ddl: `ALTER TABLE tenant_notification_endpoint_secrets ADD COLUMN previous_secret_ciphertext TEXT NOT NULL DEFAULT ''`},
		{name: "previous_secret_expires_at", ddl: `ALTER TABLE tenant_notification_endpoint_secrets ADD COLUMN previous_secret_expires_at DATETIME`},
	}
	for _, column := range columns {
		hasColumn, err := s.tableHasColumn(ctx, "tenant_notification_endpoint_secrets", column.name)
		if err != nil {
			return fmt.Errorf("inspect tenant_notification_endpoint_secrets %s column: %w", column.name, err)
		}
		if hasColumn {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.ddl); err != nil {
			return fmt.Errorf("add tenant_notification_endpoint_secrets %s column: %w", column.name, err)
		}
	}
	return nil
}

func (s *ControlPlaneStore) SaveTenantNotificationEndpointSecret(ctx context.Context, tenantID, endpointID int64, kind, secret string) error {
	kind = strings.ToLower(strings.TrimSpace(kind))
	secret = strings.TrimSpace(secret)
	if tenantID <= 0 || endpointID <= 0 {
		return fmt.Errorf("tenant id and endpoint id are required")
	}
	if kind == "" {
		return fmt.Errorf("notification kind is required")
	}
	if secret == "" {
		return s.DeleteTenantNotificationEndpointSecret(ctx, tenantID, endpointID, kind)
	}
	if len(s.secretKey) == 0 {
		return fmt.Errorf("secret key is not configured")
	}

	sealed, err := encryptProviderSecret(s.secretKey, secret)
	if err != nil {
		return fmt.Errorf("encrypt endpoint secret: %w", err)
	}

	now := time.Now().UTC()
	var (
		existingCiphertext         string
		existingPreviousCiphertext string
		existingPreviousExpires    sql.NullTime
	)
	err = s.db.QueryRowContext(ctx, `
SELECT secret_ciphertext, previous_secret_ciphertext, previous_secret_expires_at
FROM tenant_notification_endpoint_secrets
WHERE tenant_id = ? AND endpoint_id = ? AND kind = ?
LIMIT 1
`, tenantID, endpointID, kind).Scan(&existingCiphertext, &existingPreviousCiphertext, &existingPreviousExpires)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load existing tenant notification endpoint secret: %w", err)
	}

	previousCiphertext := ""
	var previousExpires any
	if err == nil && strings.TrimSpace(existingCiphertext) != "" {
		existingPlain, decryptErr := s.decryptSecret(existingCiphertext)
		if decryptErr != nil {
			return fmt.Errorf("decrypt existing tenant notification endpoint secret: %w", decryptErr)
		}
		if existingPlain != secret {
			// Rotate: keep the previous current secret valid for dual-secret grace.
			previousCiphertext = existingCiphertext
			previousExpires = now.Add(tenantNotificationEndpointPreviousSecretGrace)
		} else {
			// Same secret rewritten: preserve any remaining previous grace window.
			previousCiphertext = strings.TrimSpace(existingPreviousCiphertext)
			if existingPreviousExpires.Valid {
				previousExpires = existingPreviousExpires.Time.UTC()
			}
		}
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO tenant_notification_endpoint_secrets (
	tenant_id, endpoint_id, kind, secret_ciphertext, previous_secret_ciphertext, previous_secret_expires_at, created_at, updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, endpoint_id, kind) DO UPDATE SET
	secret_ciphertext = excluded.secret_ciphertext,
	previous_secret_ciphertext = excluded.previous_secret_ciphertext,
	previous_secret_expires_at = excluded.previous_secret_expires_at,
	updated_at = excluded.updated_at
`, tenantID, endpointID, kind, sealed, previousCiphertext, previousExpires, now, now)
	if err != nil {
		return fmt.Errorf("upsert tenant notification endpoint secret: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) GetTenantNotificationEndpointSecret(ctx context.Context, tenantID, endpointID int64, kind string) (string, error) {
	secrets, err := s.GetTenantNotificationEndpointSigningSecrets(ctx, tenantID, endpointID, kind)
	if err != nil {
		return "", err
	}
	return secrets.Current, nil
}

func (s *ControlPlaneStore) GetTenantNotificationEndpointSigningSecrets(ctx context.Context, tenantID, endpointID int64, kind string) (TenantNotificationEndpointSigningSecrets, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if tenantID <= 0 || endpointID <= 0 {
		return TenantNotificationEndpointSigningSecrets{}, fmt.Errorf("tenant id and endpoint id are required")
	}
	if kind == "" {
		return TenantNotificationEndpointSigningSecrets{}, fmt.Errorf("notification kind is required")
	}
	if len(s.secretKey) == 0 {
		return TenantNotificationEndpointSigningSecrets{}, fmt.Errorf("secret key is not configured")
	}

	var (
		ciphertext         string
		previousCiphertext string
		previousExpires    sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
SELECT secret_ciphertext, previous_secret_ciphertext, previous_secret_expires_at
FROM tenant_notification_endpoint_secrets
WHERE tenant_id = ? AND endpoint_id = ? AND kind = ?
LIMIT 1
`, tenantID, endpointID, kind).Scan(&ciphertext, &previousCiphertext, &previousExpires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TenantNotificationEndpointSigningSecrets{}, sql.ErrNoRows
		}
		return TenantNotificationEndpointSigningSecrets{}, fmt.Errorf("load tenant notification endpoint secret: %w", err)
	}

	plaintext, err := s.decryptSecret(ciphertext)
	if err != nil {
		return TenantNotificationEndpointSigningSecrets{}, fmt.Errorf("decrypt tenant notification endpoint secret: %w", err)
	}
	out := TenantNotificationEndpointSigningSecrets{Current: plaintext}
	now := time.Now().UTC()
	if strings.TrimSpace(previousCiphertext) != "" && previousExpires.Valid && !previousExpires.Time.UTC().Before(now) {
		previousPlain, prevErr := s.decryptSecret(previousCiphertext)
		if prevErr != nil {
			return TenantNotificationEndpointSigningSecrets{}, fmt.Errorf("decrypt previous tenant notification endpoint secret: %w", prevErr)
		}
		expires := previousExpires.Time.UTC()
		out.Previous = previousPlain
		out.PreviousExpiresAt = &expires
		out.PreviousGraceActive = true
	}
	return out, nil
}

func (s *ControlPlaneStore) ListTenantNotificationEndpointSecretIDs(ctx context.Context, tenantID int64, kind string) ([]int64, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if tenantID <= 0 {
		return nil, fmt.Errorf("tenant id is required")
	}
	if kind == "" {
		return nil, fmt.Errorf("notification kind is required")
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT endpoint_id
FROM tenant_notification_endpoint_secrets
WHERE tenant_id = ? AND kind = ?
ORDER BY endpoint_id ASC
`, tenantID, kind)
	if err != nil {
		return nil, fmt.Errorf("list tenant notification endpoint secret ids: %w", err)
	}
	defer rows.Close()

	ids := make([]int64, 0)
	for rows.Next() {
		var endpointID int64
		if err := rows.Scan(&endpointID); err != nil {
			return nil, fmt.Errorf("scan tenant notification endpoint secret id: %w", err)
		}
		ids = append(ids, endpointID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant notification endpoint secret ids: %w", err)
	}
	return ids, nil
}

func (s *ControlPlaneStore) DeleteTenantNotificationEndpointSecret(ctx context.Context, tenantID, endpointID int64, kind string) error {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if tenantID <= 0 || endpointID <= 0 {
		return fmt.Errorf("tenant id and endpoint id are required")
	}
	if kind == "" {
		return fmt.Errorf("notification kind is required")
	}
	_, err := s.db.ExecContext(ctx, `
DELETE FROM tenant_notification_endpoint_secrets
WHERE tenant_id = ? AND endpoint_id = ? AND kind = ?
`, tenantID, endpointID, kind)
	if err != nil {
		return fmt.Errorf("delete tenant notification endpoint secret: %w", err)
	}
	return nil
}
