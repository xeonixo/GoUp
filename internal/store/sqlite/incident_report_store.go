package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// IncidentReportRow is a tenant incident used for SLA reports (no cause text in aggregates).
type IncidentReportRow struct {
	ID         int64
	MonitorID  int64
	StartedAt  time.Time
	ResolvedAt *time.Time
}

// ListIncidentsStartedSince returns incidents whose start falls on or after since, oldest first.
func (s *Store) ListIncidentsStartedSince(ctx context.Context, since time.Time) ([]IncidentReportRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, monitor_id, started_at, resolved_at
FROM incidents
WHERE started_at >= ?
ORDER BY started_at ASC, id ASC
`, since.UTC())
	if err != nil {
		if isMalformedSQLiteError(err) {
			return []IncidentReportRow{}, nil
		}
		return nil, fmt.Errorf("list incidents started since: %w", err)
	}
	defer rows.Close()

	items := make([]IncidentReportRow, 0)
	for rows.Next() {
		var item IncidentReportRow
		var resolvedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.MonitorID, &item.StartedAt, &resolvedAt); err != nil {
			if isMalformedSQLiteError(err) {
				return []IncidentReportRow{}, nil
			}
			return nil, fmt.Errorf("scan incident report row: %w", err)
		}
		item.ResolvedAt = nullableTime(resolvedAt)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		if isMalformedSQLiteError(err) {
			return []IncidentReportRow{}, nil
		}
		return nil, fmt.Errorf("iterate incident report rows: %w", err)
	}
	return items, nil
}
