package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type TenantNotificationEndpointSecret struct {
	TenantID   int64
	EndpointID int64
	Kind       string
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
	_, err = s.db.ExecContext(ctx, `
INSERT INTO tenant_notification_endpoint_secrets (tenant_id, endpoint_id, kind, secret_ciphertext, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, endpoint_id, kind) DO UPDATE SET
	secret_ciphertext = excluded.secret_ciphertext,
	updated_at = excluded.updated_at
`, tenantID, endpointID, kind, sealed, now, now)
	if err != nil {
		return fmt.Errorf("upsert tenant notification endpoint secret: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) GetTenantNotificationEndpointSecret(ctx context.Context, tenantID, endpointID int64, kind string) (string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if tenantID <= 0 || endpointID <= 0 {
		return "", fmt.Errorf("tenant id and endpoint id are required")
	}
	if kind == "" {
		return "", fmt.Errorf("notification kind is required")
	}
	if len(s.secretKey) == 0 {
		return "", fmt.Errorf("secret key is not configured")
	}

	var ciphertext string
	err := s.db.QueryRowContext(ctx, `
SELECT secret_ciphertext
FROM tenant_notification_endpoint_secrets
WHERE tenant_id = ? AND endpoint_id = ? AND kind = ?
LIMIT 1
`, tenantID, endpointID, kind).Scan(&ciphertext)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", sql.ErrNoRows
		}
		return "", fmt.Errorf("load tenant notification endpoint secret: %w", err)
	}

	plaintext, err := s.decryptSecret(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt tenant notification endpoint secret: %w", err)
	}
	return plaintext, nil
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
