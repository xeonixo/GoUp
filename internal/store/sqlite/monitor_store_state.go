package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"goup/internal/monitor"
	"strings"
	"time"
)

func (s *Store) RecordMonitorState(ctx context.Context, monitorID int64, status monitor.Status, message string, checkedAt time.Time) error {
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}

	if err := s.recordMonitorStateTransition(ctx, monitorID, status, message, checkedAt); err != nil {
		return err
	}

	if status == monitor.StatusUp {
		result, err := s.db.ExecContext(ctx, `
UPDATE incidents
SET resolved_at = ?, last_state = 'up'
WHERE monitor_id = ? AND resolved_at IS NULL
`, checkedAt.UTC(), monitorID)
		if err != nil {
			return fmt.Errorf("resolve incident: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("resolve incident rows affected: %w", err)
		}
		if affected > 0 {
			return nil
		}

		var fallbackID int64
		var fallbackResolvedAt sql.NullTime
		err = s.db.QueryRowContext(ctx, `
SELECT id, resolved_at
FROM incidents
WHERE monitor_id = ?
ORDER BY started_at DESC
LIMIT 1
`, monitorID).Scan(&fallbackID, &fallbackResolvedAt)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil
			}
			return fmt.Errorf("fallback lookup incident: %w", err)
		}
		if fallbackResolvedAt.Valid {
			return nil
		}

		_, err = s.db.ExecContext(ctx, `
UPDATE incidents
SET resolved_at = ?, last_state = 'up'
WHERE id = ?
`, checkedAt.UTC(), fallbackID)
		if err != nil {
			return fmt.Errorf("fallback resolve incident: %w", err)
		}
		return nil
	}

	var incidentID int64
	err := s.db.QueryRowContext(ctx, `
SELECT id
FROM incidents
WHERE monitor_id = ? AND resolved_at IS NULL
ORDER BY started_at DESC
LIMIT 1
`, monitorID).Scan(&incidentID)
	if err != nil {
		if err == sql.ErrNoRows {
			_, insertErr := s.db.ExecContext(ctx, `
INSERT INTO incidents (monitor_id, started_at, resolved_at, cause, last_state)
VALUES (?, ?, NULL, ?, ?)
`, monitorID, checkedAt.UTC(), strings.TrimSpace(message), string(status))
			if insertErr != nil {
				return fmt.Errorf("create incident: %w", insertErr)
			}
			return nil
		}
		return fmt.Errorf("lookup open incident: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
UPDATE incidents
SET cause = ?, last_state = ?
WHERE id = ?
`, strings.TrimSpace(message), string(status), incidentID)
	if err != nil {
		return fmt.Errorf("update incident: %w", err)
	}

	return nil
}

func (s *Store) recordMonitorStateTransition(ctx context.Context, monitorID int64, status monitor.Status, message string, checkedAt time.Time) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT status
FROM monitor_results
WHERE monitor_id = ?
ORDER BY checked_at DESC, id DESC
LIMIT 2
`, monitorID)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("load previous monitor states: %w", err)
	}
	defer rows.Close()

	states := make([]monitor.Status, 0, 2)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			if isMalformedSQLiteError(err) {
				return nil
			}
			return fmt.Errorf("scan previous monitor state: %w", err)
		}
		states = append(states, monitor.Status(strings.TrimSpace(raw)))
	}
	if err := rows.Err(); err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("iterate previous monitor states: %w", err)
	}

	if len(states) < 2 {
		return nil
	}

	previous := states[1]
	if previous == status {
		return nil
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO monitor_state_events (monitor_id, checked_at, from_status, to_status, message)
VALUES (?, ?, ?, ?, ?)
`, monitorID, checkedAt.UTC(), string(previous), string(status), strings.TrimSpace(message))
	if err != nil {
		if isMalformedSQLiteError(err) {
			return nil
		}
		return fmt.Errorf("insert monitor state transition: %w", err)
	}

	return nil
}
