package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

type RemoteNode struct {
	ID                      int64
	TenantID                int64
	NodeID                  string
	Name                    string
	Enabled                 bool
	HeartbeatTimeoutSeconds int
	LastSeenAt              *time.Time
	AccessTokenExpiresAt    *time.Time
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

const (
	remoteNodeIDRandomBytes           = 24
	remoteNodeBootstrapKeyRandomBytes = 48
	remoteNodeAccessTokenRandomBytes  = 48
	remoteNodeEventRetentionDays      = 30
)

func (n RemoteNode) IsOnline(now time.Time) bool {
	if !n.Enabled || n.LastSeenAt == nil {
		return false
	}
	timeout := n.HeartbeatTimeoutSeconds
	if timeout <= 0 {
		timeout = 120
	}
	return now.UTC().Sub(n.LastSeenAt.UTC()) <= time.Duration(timeout)*time.Second
}

func (s *ControlPlaneStore) CreateRemoteNode(ctx context.Context, tenantID int64, name string, heartbeatTimeoutSeconds int) (RemoteNode, string, error) {
	if tenantID <= 0 {
		return RemoteNode{}, "", errors.New("tenant id is required")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return RemoteNode{}, "", errors.New("node name is required")
	}
	if heartbeatTimeoutSeconds < 30 {
		heartbeatTimeoutSeconds = 120
	}

	nodeID, err := generateTokenValue(remoteNodeIDRandomBytes)
	if err != nil {
		return RemoteNode{}, "", fmt.Errorf("generate node id: %w", err)
	}
	nodeID = "rn_" + nodeID
	bootstrapKey, err := generateTokenValue(remoteNodeBootstrapKeyRandomBytes)
	if err != nil {
		return RemoteNode{}, "", fmt.Errorf("generate bootstrap key: %w", err)
	}
	if len(s.secretKey) == 0 {
		return RemoteNode{}, "", errors.New("control-plane secret key is not configured")
	}
	sealedBootstrap, err := encryptProviderSecret(s.secretKey, bootstrapKey)
	if err != nil {
		return RemoteNode{}, "", fmt.Errorf("encrypt bootstrap key: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO remote_nodes (
	tenant_id,
	node_id,
	name,
	bootstrap_key_ciphertext,
	heartbeat_timeout_seconds,
	enabled,
	created_at,
	updated_at
) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
`, tenantID, nodeID, name, sealedBootstrap, heartbeatTimeoutSeconds, now, now)
	if err != nil {
		return RemoteNode{}, "", fmt.Errorf("create remote node: %w", err)
	}

	node, err := s.GetRemoteNodeByTenantAndNodeID(ctx, tenantID, nodeID)
	if err != nil {
		return RemoteNode{}, "", err
	}
	return node, bootstrapKey, nil
}

func (s *ControlPlaneStore) DeleteRemoteNodeByTenantAndNodeID(ctx context.Context, tenantID int64, nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if tenantID <= 0 || nodeID == "" {
		return errors.New("tenant id and node id are required")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM remote_nodes WHERE tenant_id = ? AND node_id = ?`, tenantID, nodeID)
	if err != nil {
		return fmt.Errorf("delete remote node: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete remote node rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *ControlPlaneStore) RotateRemoteNodeBootstrapKey(ctx context.Context, tenantID int64, nodeID string) (string, error) {
	nodeID = strings.TrimSpace(nodeID)
	if tenantID <= 0 || nodeID == "" {
		return "", errors.New("tenant id and node id are required")
	}
	if len(s.secretKey) == 0 {
		return "", errors.New("control-plane secret key is not configured")
	}

	bootstrapKey, err := generateTokenValue(remoteNodeBootstrapKeyRandomBytes)
	if err != nil {
		return "", fmt.Errorf("generate bootstrap key: %w", err)
	}
	sealedBootstrap, err := encryptProviderSecret(s.secretKey, bootstrapKey)
	if err != nil {
		return "", fmt.Errorf("encrypt bootstrap key: %w", err)
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE remote_nodes
SET bootstrap_key_ciphertext = ?, updated_at = ?
WHERE tenant_id = ? AND node_id = ? AND enabled = 1
`, sealedBootstrap, time.Now().UTC(), tenantID, nodeID)
	if err != nil {
		return "", fmt.Errorf("rotate remote node bootstrap key: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("rotate remote node bootstrap key rows affected: %w", err)
	}
	if affected == 0 {
		return "", sql.ErrNoRows
	}

	return bootstrapKey, nil
}

func (s *ControlPlaneStore) ListRemoteNodesByTenant(ctx context.Context, tenantID int64) ([]RemoteNode, error) {
	if tenantID <= 0 {
		return []RemoteNode{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, node_id, name, enabled, heartbeat_timeout_seconds, last_seen_at, access_token_expires_at, created_at, updated_at
FROM remote_nodes
WHERE tenant_id = ? AND enabled = 1
ORDER BY name COLLATE NOCASE ASC, id ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list remote nodes: %w", err)
	}
	defer rows.Close()

	items := make([]RemoteNode, 0)
	for rows.Next() {
		item, err := scanRemoteNode(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remote nodes: %w", err)
	}
	return items, nil
}

func (s *ControlPlaneStore) ListAllEnabledRemoteNodes(ctx context.Context) ([]RemoteNode, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, node_id, name, enabled, heartbeat_timeout_seconds, last_seen_at, access_token_expires_at, created_at, updated_at
FROM remote_nodes
WHERE enabled = 1
ORDER BY tenant_id ASC, name COLLATE NOCASE ASC, id ASC
`)
	if err != nil {
		return nil, fmt.Errorf("list all remote nodes: %w", err)
	}
	defer rows.Close()

	items := make([]RemoteNode, 0)
	for rows.Next() {
		item, err := scanRemoteNode(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate all remote nodes: %w", err)
	}
	return items, nil
}

func (s *ControlPlaneStore) GetRemoteNodeByTenantAndNodeID(ctx context.Context, tenantID int64, nodeID string) (RemoteNode, error) {
	nodeID = strings.TrimSpace(nodeID)
	if tenantID <= 0 || nodeID == "" {
		return RemoteNode{}, errors.New("tenant id and node id are required")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, node_id, name, enabled, heartbeat_timeout_seconds, last_seen_at, access_token_expires_at, created_at, updated_at
FROM remote_nodes
WHERE tenant_id = ? AND node_id = ? AND enabled = 1
`, tenantID, nodeID)
	item, err := scanRemoteNodeRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return RemoteNode{}, sql.ErrNoRows
		}
		return RemoteNode{}, fmt.Errorf("get remote node: %w", err)
	}
	return item, nil
}

func scanRemoteNode(scanner interface{ Scan(dest ...any) error }) (RemoteNode, error) {
	var (
		item                 RemoteNode
		enabledRaw           int
		lastSeenAt           sql.NullTime
		accessTokenExpiresAt sql.NullTime
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.NodeID,
		&item.Name,
		&enabledRaw,
		&item.HeartbeatTimeoutSeconds,
		&lastSeenAt,
		&accessTokenExpiresAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return RemoteNode{}, fmt.Errorf("scan remote node: %w", err)
	}
	item.Enabled = enabledRaw == 1
	if lastSeenAt.Valid {
		value := lastSeenAt.Time.UTC()
		item.LastSeenAt = &value
	}
	if accessTokenExpiresAt.Valid {
		value := accessTokenExpiresAt.Time.UTC()
		item.AccessTokenExpiresAt = &value
	}
	return item, nil
}

func scanRemoteNodeRow(row *sql.Row) (RemoteNode, error) {
	var (
		item                 RemoteNode
		enabledRaw           int
		lastSeenAt           sql.NullTime
		accessTokenExpiresAt sql.NullTime
	)
	if err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.NodeID,
		&item.Name,
		&enabledRaw,
		&item.HeartbeatTimeoutSeconds,
		&lastSeenAt,
		&accessTokenExpiresAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return RemoteNode{}, err
	}
	item.Enabled = enabledRaw == 1
	if lastSeenAt.Valid {
		value := lastSeenAt.Time.UTC()
		item.LastSeenAt = &value
	}
	if accessTokenExpiresAt.Valid {
		value := accessTokenExpiresAt.Time.UTC()
		item.AccessTokenExpiresAt = &value
	}
	return item, nil
}

func generateTokenValue(randomBytes int) (string, error) {
	if randomBytes < 16 {
		randomBytes = 16
	}
	buf := make([]byte, randomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
