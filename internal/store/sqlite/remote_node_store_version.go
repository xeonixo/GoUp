package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const remoteNodeAgentVersionMaxLen = 64

func (s *ControlPlaneStore) ensureRemoteNodeAgentVersionColumns(ctx context.Context) error {
	columns := []struct{ name, ddl string }{
		{"agent_version", `ALTER TABLE remote_nodes ADD COLUMN agent_version TEXT NOT NULL DEFAULT ''`},
		{"agent_version_seen_at", `ALTER TABLE remote_nodes ADD COLUMN agent_version_seen_at DATETIME`},
	}
	for _, column := range columns {
		hasColumn, err := s.tableHasColumn(ctx, "remote_nodes", column.name)
		if err != nil {
			return fmt.Errorf("inspect remote_nodes %s column: %w", column.name, err)
		}
		if hasColumn {
			continue
		}
		if _, err := s.db.ExecContext(ctx, column.ddl); err != nil {
			return fmt.Errorf("add remote_nodes %s column: %w", column.name, err)
		}
	}
	return nil
}

// NormalizeRemoteNodeAgentVersion trims the reported agent version and returns
// "" when it is too long or contains non-printable characters.
func NormalizeRemoteNodeAgentVersion(raw string) string {
	value := strings.TrimSpace(raw)
	if len(value) > remoteNodeAgentVersionMaxLen {
		return ""
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return ""
		}
	}
	return value
}

// UpdateRemoteNodeAgentVersion stores the agent version the node reported.
// Callers should only invoke it when the value changed to avoid a write per poll.
func (s *ControlPlaneStore) UpdateRemoteNodeAgentVersion(ctx context.Context, nodeInternalID int64, agentVersion string, seenAt time.Time) error {
	if nodeInternalID <= 0 {
		return errors.New("node id is required")
	}
	agentVersion = NormalizeRemoteNodeAgentVersion(agentVersion)
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	if _, err := s.db.ExecContext(ctx, `
UPDATE remote_nodes
SET agent_version = ?, agent_version_seen_at = ?
WHERE id = ?
`, agentVersion, seenAt.UTC(), nodeInternalID); err != nil {
		return fmt.Errorf("update remote node agent version: %w", err)
	}
	return nil
}
