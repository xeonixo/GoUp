package sqlite

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *ControlPlaneStore) AuthenticateRemoteNodeBootstrap(ctx context.Context, nodeID, bootstrapKey string) (RemoteNode, error) {
	nodeID = strings.TrimSpace(nodeID)
	bootstrapKey = strings.TrimSpace(bootstrapKey)
	if nodeID == "" || bootstrapKey == "" {
		return RemoteNode{}, errors.New("node id and bootstrap key are required")
	}

	var (
		item                   RemoteNode
		enabledRaw             int
		lastSeenAt             sql.NullTime
		accessTokenExpiresAt   sql.NullTime
		agentVersionSeenAt     sql.NullTime
		bootstrapKeyCiphertext string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, node_id, name, enabled, heartbeat_timeout_seconds, last_seen_at, access_token_expires_at, created_at, updated_at, agent_version, agent_version_seen_at, bootstrap_key_ciphertext
FROM remote_nodes
WHERE node_id = ?
`, nodeID).Scan(
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
		&item.AgentVersion,
		&agentVersionSeenAt,
		&bootstrapKeyCiphertext,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return RemoteNode{}, sql.ErrNoRows
		}
		return RemoteNode{}, fmt.Errorf("load remote node for bootstrap: %w", err)
	}
	item.Enabled = enabledRaw == 1
	if !item.Enabled {
		return RemoteNode{}, sql.ErrNoRows
	}
	if lastSeenAt.Valid {
		value := lastSeenAt.Time.UTC()
		item.LastSeenAt = &value
	}
	if agentVersionSeenAt.Valid {
		value := agentVersionSeenAt.Time.UTC()
		item.AgentVersionSeenAt = &value
	}
	if accessTokenExpiresAt.Valid {
		value := accessTokenExpiresAt.Time.UTC()
		item.AccessTokenExpiresAt = &value
	}
	plainBootstrap, err := s.decryptSecret(bootstrapKeyCiphertext)
	if err != nil {
		return RemoteNode{}, fmt.Errorf("decrypt bootstrap key: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(bootstrapKey), []byte(plainBootstrap)) != 1 {
		return RemoteNode{}, sql.ErrNoRows
	}
	return item, nil
}

func (s *ControlPlaneStore) IssueRemoteNodeAccessToken(ctx context.Context, nodeInternalID int64, ttl time.Duration) (string, time.Time, error) {
	if nodeInternalID <= 0 {
		return "", time.Time{}, errors.New("node id is required")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if len(s.secretKey) == 0 {
		return "", time.Time{}, errors.New("control-plane secret key is not configured")
	}
	token, err := generateTokenValue(remoteNodeAccessTokenRandomBytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generate access token: %w", err)
	}
	sealed, err := encryptProviderSecret(s.secretKey, token)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encrypt access token: %w", err)
	}
	fingerprint := remoteNodeTokenFingerprint(token)
	expiresAt := time.Now().UTC().Add(ttl)
	_, err = s.db.ExecContext(ctx, `
UPDATE remote_nodes
SET access_token_ciphertext = ?, access_token_fingerprint = ?, access_token_expires_at = ?, updated_at = ?
WHERE id = ?
`, sealed, fingerprint, expiresAt, time.Now().UTC(), nodeInternalID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("store access token: %w", err)
	}
	return token, expiresAt, nil
}

func (s *ControlPlaneStore) AuthenticateRemoteNodeAccessToken(ctx context.Context, token string) (RemoteNode, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return RemoteNode{}, sql.ErrNoRows
	}
	now := time.Now().UTC()
	fingerprint := remoteNodeTokenFingerprint(token)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, node_id, name, enabled, heartbeat_timeout_seconds, last_seen_at, access_token_expires_at, created_at, updated_at, agent_version, agent_version_seen_at, access_token_ciphertext
FROM remote_nodes
WHERE access_token_fingerprint = ?
	AND enabled = 1
	AND TRIM(access_token_ciphertext) <> ''
	AND access_token_expires_at IS NOT NULL
	AND access_token_expires_at >= ?
`, fingerprint, now)
	if err != nil {
		return RemoteNode{}, fmt.Errorf("query remote node access candidates: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			item                 RemoteNode
			enabledRaw           int
			lastSeenAt           sql.NullTime
			accessTokenExpiresAt sql.NullTime
			agentVersionSeenAt   sql.NullTime
			ciphertext           string
		)
		if err := rows.Scan(
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
			&item.AgentVersion,
			&agentVersionSeenAt,
			&item.AgentVersion,
			&agentVersionSeenAt,
			&ciphertext,
		); err != nil {
			return RemoteNode{}, fmt.Errorf("scan remote node access candidate: %w", err)
		}
		item.Enabled = enabledRaw == 1
		if lastSeenAt.Valid {
			value := lastSeenAt.Time.UTC()
			item.LastSeenAt = &value
		}
		if agentVersionSeenAt.Valid {
			value := agentVersionSeenAt.Time.UTC()
			item.AgentVersionSeenAt = &value
		}
		if accessTokenExpiresAt.Valid {
			value := accessTokenExpiresAt.Time.UTC()
			item.AccessTokenExpiresAt = &value
		}
		plainToken, err := s.decryptSecret(ciphertext)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(plainToken)) == 1 {
			return item, nil
		}
	}
	if err := rows.Err(); err != nil {
		return RemoteNode{}, fmt.Errorf("iterate remote node access candidates: %w", err)
	}

	return RemoteNode{}, sql.ErrNoRows
}

func remoteNodeTokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func (s *ControlPlaneStore) TouchRemoteNodeLastSeen(ctx context.Context, nodeInternalID int64, seenAt time.Time) error {
	if nodeInternalID <= 0 {
		return errors.New("node id is required")
	}
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE remote_nodes
SET last_seen_at = ?, updated_at = ?
WHERE id = ?
`, seenAt.UTC(), time.Now().UTC(), nodeInternalID)
	if err != nil {
		return fmt.Errorf("update remote node last_seen_at: %w", err)
	}
	return nil
}
