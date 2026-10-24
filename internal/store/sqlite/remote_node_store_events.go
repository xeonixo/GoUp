package sqlite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type RemoteNodeEvent struct {
	ID        int64
	TenantID  int64
	NodeID    string
	EventType string
	RemoteIP  string
	UserAgent string
	Details   string
	CreatedAt time.Time
}

type ControlPlaneMaintenanceResult struct {
	DeletedRemoteNodeEvents int64
	Vacuumed                bool
	CompactionSkipped       string
}

// RunMaintenance prunes remote node events and compacts the control-plane database.
func (s *ControlPlaneStore) RunMaintenance(ctx context.Context, now time.Time) (ControlPlaneMaintenanceResult, error) {
	result := ControlPlaneMaintenanceResult{}

	deleted, err := s.pruneRemoteNodeEvents(ctx, now.UTC().AddDate(0, 0, -remoteNodeEventRetentionDays))
	if err != nil {
		return result, err
	}
	result.DeletedRemoteNodeEvents = deleted

	vacuumed, err := compactDatabase(ctx, s.db)
	if err != nil {
		if !errors.Is(err, ErrInsufficientDiskSpace) {
			return result, err
		}
		result.CompactionSkipped = err.Error()
	}
	result.Vacuumed = vacuumed
	return result, nil
}

func (s *ControlPlaneStore) pruneRemoteNodeEvents(ctx context.Context, cutoff time.Time) (int64, error) {
	// Older versions logged every poll and every fully accepted report. These rows
	// are no longer written, so removing them is idempotent and cheap after the first run.
	res, err := s.db.ExecContext(ctx, `
DELETE FROM remote_node_events
WHERE created_at < ?
   OR event_type = 'poll'
   OR (event_type = 'report'
       AND details LIKE 'accepted=% received=%'
       AND substr(details, 10, instr(details, ' ') - 10) = substr(details, instr(details, 'received=') + 9))
`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune remote node events: %w", err)
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read pruned remote node event rows: %w", err)
	}
	return deleted, nil
}

func (s *ControlPlaneStore) InsertRemoteNodeEvent(ctx context.Context, tenantID int64, nodeID, eventType, remoteIP, userAgent, details string, createdAt time.Time) error {
	nodeID = strings.TrimSpace(nodeID)
	eventType = strings.TrimSpace(eventType)
	if tenantID <= 0 || nodeID == "" || eventType == "" {
		return errors.New("tenant id, node id and event type are required")
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	remoteIP = strings.TrimSpace(remoteIP)
	if remoteIP == "" {
		remoteIP = "unknown"
	}
	if len(remoteIP) > 128 {
		remoteIP = remoteIP[:128]
	}
	userAgent = strings.TrimSpace(userAgent)
	if len(userAgent) > 255 {
		userAgent = userAgent[:255]
	}
	details = strings.TrimSpace(details)
	if len(details) > 400 {
		details = details[:400]
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO remote_node_events (
	tenant_id,
	node_id,
	event_type,
	remote_ip,
	user_agent,
	details,
	created_at
) VALUES (?, ?, ?, ?, ?, ?, ?)
`, tenantID, nodeID, eventType, remoteIP, userAgent, details, createdAt.UTC())
	if err != nil {
		return fmt.Errorf("insert remote node event: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ListRecentRemoteNodeEventsByTenant(ctx context.Context, tenantID int64, limit int) ([]RemoteNodeEvent, error) {
	if tenantID <= 0 {
		return []RemoteNodeEvent{}, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, node_id, event_type, remote_ip, user_agent, details, created_at
FROM remote_node_events
WHERE tenant_id = ?
ORDER BY created_at DESC, id DESC
LIMIT ?
`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list remote node events: %w", err)
	}
	defer rows.Close()

	items := make([]RemoteNodeEvent, 0)
	for rows.Next() {
		var item RemoteNodeEvent
		if err := rows.Scan(
			&item.ID,
			&item.TenantID,
			&item.NodeID,
			&item.EventType,
			&item.RemoteIP,
			&item.UserAgent,
			&item.Details,
			&item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan remote node event: %w", err)
		}
		item.NodeID = strings.TrimSpace(item.NodeID)
		item.EventType = strings.TrimSpace(item.EventType)
		item.RemoteIP = strings.TrimSpace(item.RemoteIP)
		item.UserAgent = strings.TrimSpace(item.UserAgent)
		item.Details = strings.TrimSpace(item.Details)
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate remote node events: %w", err)
	}
	return items, nil
}
