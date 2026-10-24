package sqlite

import (
	"context"
	"fmt"
)

func (s *ControlPlaneStore) ensureRemoteNodesTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS remote_nodes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id INTEGER NOT NULL,
	node_id TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	bootstrap_key_ciphertext TEXT NOT NULL,
	access_token_ciphertext TEXT NOT NULL DEFAULT '',
	access_token_fingerprint TEXT NOT NULL DEFAULT '',
	access_token_expires_at DATETIME,
	last_seen_at DATETIME,
	heartbeat_timeout_seconds INTEGER NOT NULL DEFAULT 120,
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
)
`); err != nil {
		return fmt.Errorf("create remote_nodes table: %w", err)
	}
	if err := s.ensureRemoteNodeAccessTokenFingerprintColumn(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS remote_node_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id INTEGER NOT NULL,
	node_id TEXT NOT NULL,
	event_type TEXT NOT NULL,
	remote_ip TEXT NOT NULL,
	user_agent TEXT,
	details TEXT,
	created_at DATETIME NOT NULL,
	FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
)
`); err != nil {
		return fmt.Errorf("create remote_node_events table: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_remote_nodes_tenant ON remote_nodes(tenant_id, enabled, node_id)`); err != nil {
		return fmt.Errorf("create remote_nodes tenant index: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_remote_nodes_last_seen ON remote_nodes(last_seen_at)`); err != nil {
		return fmt.Errorf("create remote_nodes last_seen index: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_remote_nodes_access_token_fingerprint ON remote_nodes(access_token_fingerprint, enabled, access_token_expires_at)`); err != nil {
		return fmt.Errorf("create remote_nodes access token fingerprint index: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_remote_node_events_tenant_node_created ON remote_node_events(tenant_id, node_id, created_at DESC)`); err != nil {
		return fmt.Errorf("create remote_node_events tenant-node-created index: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_remote_node_events_tenant_created ON remote_node_events(tenant_id, created_at DESC, id DESC)`); err != nil {
		return fmt.Errorf("create remote_node_events tenant-created index: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_remote_node_events_created ON remote_node_events(created_at DESC)`); err != nil {
		return fmt.Errorf("create remote_node_events created index: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ensureRemoteNodeAccessTokenFingerprintColumn(ctx context.Context) error {
	hasColumn, err := s.tableHasColumn(ctx, "remote_nodes", "access_token_fingerprint")
	if err != nil {
		return fmt.Errorf("inspect remote_nodes access_token_fingerprint column: %w", err)
	}
	if !hasColumn {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE remote_nodes ADD COLUMN access_token_fingerprint TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add remote_nodes access_token_fingerprint column: %w", err)
		}
	}
	if err := s.backfillRemoteNodeAccessTokenFingerprints(ctx); err != nil {
		return err
	}
	return nil
}

func (s *ControlPlaneStore) backfillRemoteNodeAccessTokenFingerprints(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, access_token_ciphertext
FROM remote_nodes
WHERE TRIM(access_token_ciphertext) <> '' AND TRIM(access_token_fingerprint) = ''
`)
	if err != nil {
		return fmt.Errorf("query remote node token fingerprint backfill candidates: %w", err)
	}
	defer rows.Close()

	type candidate struct {
		id         int64
		ciphertext string
	}
	candidates := make([]candidate, 0)
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.ciphertext); err != nil {
			return fmt.Errorf("scan remote node token fingerprint backfill candidate: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate remote node token fingerprint backfill candidates: %w", err)
	}
	for _, item := range candidates {
		plainToken, err := s.decryptSecret(item.ciphertext)
		if err != nil {
			continue
		}
		fingerprint := remoteNodeTokenFingerprint(plainToken)
		if _, err := s.db.ExecContext(ctx, `UPDATE remote_nodes SET access_token_fingerprint = ? WHERE id = ?`, fingerprint, item.id); err != nil {
			return fmt.Errorf("backfill remote node access token fingerprint: %w", err)
		}
	}
	return nil
}
