package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type AuditEvent struct {
	ID         int64
	Actor      string
	Action     string
	TargetType string
	TargetID   int64
	Details    string
	CreatedAt  time.Time
}

func (s *ControlPlaneStore) InsertAuditEvent(ctx context.Context, actor, action, targetType string, targetID int64, details string) error {
	if strings.TrimSpace(action) == "" {
		return fmt.Errorf("audit action is required")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_events (actor, action, target_type, target_id, details, created_at)
VALUES (?, ?, ?, ?, ?, ?)
`, strings.TrimSpace(actor), strings.TrimSpace(action), strings.TrimSpace(targetType), targetID, strings.TrimSpace(details), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) ListRecentAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT id, actor, action, target_type, target_id, details, created_at
FROM audit_events
ORDER BY id DESC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	items := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(&event.ID, &event.Actor, &event.Action, &event.TargetType, &event.TargetID, &event.Details, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		items = append(items, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}

	return items, nil
}

func (s *ControlPlaneStore) ListAuditEventsFiltered(ctx context.Context, limit int, action, actor, targetType string) ([]AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	action = strings.TrimSpace(action)
	actor = strings.TrimSpace(actor)
	targetType = strings.TrimSpace(targetType)

	query := `
SELECT id, actor, action, target_type, target_id, details, created_at
FROM audit_events
WHERE 1=1
`
	args := make([]any, 0, 4)

	if action != "" {
		query += " AND lower(action) = lower(?)"
		args = append(args, action)
	}
	if actor != "" {
		query += " AND lower(actor) LIKE lower(?)"
		args = append(args, "%"+actor+"%")
	}
	if targetType != "" {
		query += " AND lower(target_type) = lower(?)"
		args = append(args, targetType)
	}

	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query filtered audit events: %w", err)
	}
	defer rows.Close()

	items := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(&event.ID, &event.Actor, &event.Action, &event.TargetType, &event.TargetID, &event.Details, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan filtered audit event: %w", err)
		}
		items = append(items, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate filtered audit events: %w", err)
	}

	return items, nil
}

func (s *ControlPlaneStore) ListAuditActionKeys(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT action
FROM audit_events
WHERE trim(action) <> ''
GROUP BY action
ORDER BY action ASC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit action keys: %w", err)
	}
	defer rows.Close()

	items := make([]string, 0, limit)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan audit action key: %w", err)
		}
		value = strings.TrimSpace(value)
		if value != "" {
			items = append(items, value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit action keys: %w", err)
	}
	return items, nil
}

func (s *ControlPlaneStore) ListAuditTargetTypes(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT target_type
FROM audit_events
WHERE trim(target_type) <> ''
GROUP BY target_type
ORDER BY target_type ASC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit target types: %w", err)
	}
	defer rows.Close()

	items := make([]string, 0, limit)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan audit target type: %w", err)
		}
		value = strings.TrimSpace(value)
		if value != "" {
			items = append(items, value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit target types: %w", err)
	}
	return items, nil
}
