package sqlite

import (
	"context"
	"fmt"
	"goup/internal/monitor"
	"sort"
	"strings"
	"time"
)

// MaintenanceSet returns the windows from a cache that is refreshed every 30 seconds and
// dropped whenever a window is created, changed or deleted through this store.
func (s *Store) MaintenanceSet(ctx context.Context) monitor.MaintenanceSet {
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	if !s.maintenanceLoaded.IsZero() && time.Since(s.maintenanceLoaded) < maintenanceCacheTTL {
		return s.maintenanceCache
	}
	items, err := s.ListMaintenanceWindows(ctx)
	if err != nil {
		// Keep serving the previous snapshot; retry on the next call.
		return s.maintenanceCache
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	s.maintenanceCache = monitor.MaintenanceSet{Windows: items}
	s.maintenanceLoaded = time.Now()
	return s.maintenanceCache
}

// ActiveMaintenance implements monitor.MaintenanceChecker.
func (s *Store) ActiveMaintenance(ctx context.Context, monitorID int64, group string, now time.Time) bool {
	_, ok := s.MaintenanceSet(ctx).Active(monitorID, group, now)
	return ok
}

// SetMonitorMuteStartStatus stores the catch-up marker.
func (s *Store) SetMonitorMuteStartStatus(ctx context.Context, monitorID int64, status monitor.Status) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE monitors SET mute_start_status = ? WHERE id = ?`, string(status), monitorID); err != nil {
		return fmt.Errorf("set monitor mute_start_status: %w", err)
	}
	return nil
}

// SetMonitorLastAlert records when the current outage was last announced; nil clears it.
func (s *Store) SetMonitorLastAlert(ctx context.Context, monitorID int64, at *time.Time) error {
	var value any
	if at != nil {
		value = at.UTC()
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE monitors SET last_alert_at = ? WHERE id = ?`, value, monitorID); err != nil {
		return fmt.Errorf("set monitor last_alert_at: %w", err)
	}
	return nil
}

// CurrentOutageStart returns the time of the first result of the ongoing run of down results.
func (s *Store) CurrentOutageStart(ctx context.Context, monitorID int64) (time.Time, bool, error) {
	var raw any
	err := s.db.QueryRowContext(ctx, `
SELECT MIN(checked_at) FROM monitor_results
WHERE monitor_id = ? AND status = 'down'
  AND checked_at > COALESCE((SELECT MAX(checked_at) FROM monitor_results WHERE monitor_id = ? AND status != 'down'), '')
`, monitorID, monitorID).Scan(&raw)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, fmt.Errorf("load outage start: %w", err)
	}
	switch v := raw.(type) {
	case time.Time:
		return v.UTC(), true, nil
	case string:
		// The driver stores times in Go's default format ("... +0000 UTC", optionally with a
		// monotonic clock suffix).
		if i := strings.Index(v, " m="); i >= 0 {
			v = v[:i]
		}
		for _, layout := range []string{"2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05.999999999-07:00", time.RFC3339Nano} {
			if t, err := time.Parse(layout, v); err == nil {
				return t.UTC(), true, nil
			}
		}
	}
	return time.Time{}, false, nil
}

var _ monitor.MaintenanceChecker = (*Store)(nil)
