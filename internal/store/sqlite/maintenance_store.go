package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	defaultRawResultRetentionDays = 30
	// The latency detail chart reads raw results for up to 7 days (history_handlers.go).
	minRawResultRetentionDays       = 7
	maxRawResultRetentionDays       = 90
	hourlyRollupRetentionDays       = 400 // 12 full calendar months for the 12M trend view
	defaultStoreEventRetentionDays  = 365
	maintenanceInterval             = 6 * time.Hour
	retentionRunInterval            = 24 * time.Hour
	hourlyRollupBackfillSettingKey  = "hourly_rollup_backfill_v2_completed_at"
	hourlyRollupMinRepairSettingKey = "hourly_rollup_min_repair_v1_completed_at"
	lastRetentionRunSettingKey      = "last_raw_retention_run_at"
	lastRollupRetentionRunSetting   = "last_hourly_rollup_retention_run_at"
	lastEventRetentionRunSetting    = "last_event_retention_run_at"
	lastOptimizeMonthSettingKey     = "last_sqlite_optimize_month"
)

type MaintenanceResult struct {
	BackfilledHourlyRollups   bool
	DeletedRawResults         int64
	DeletedHourlyRollups      int64
	DeletedStateEvents        int64
	DeletedNotificationEvents int64
	Optimized                 bool
	// Vacuumed reports the one-time full VACUUM that enables incremental auto-vacuum.
	Vacuumed bool
	// CompactionSkipped holds the reason when compaction could not run, e.g. low disk space.
	CompactionSkipped string
}

type MaintenanceOptions struct {
	StateEventRetentionDays        int
	NotificationEventRetentionDays int
	RawResultRetentionDays         int
}

type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func MaintenanceInterval() time.Duration {
	return maintenanceInterval
}

func (s *Store) RunMaintenance(ctx context.Context, now time.Time, options ...MaintenanceOptions) (MaintenanceResult, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	opts := normalizeMaintenanceOptions(options...)

	result := MaintenanceResult{}

	backfilled, err := s.ensureHourlyRollupBackfill(ctx, now)
	if err != nil {
		return result, err
	}
	result.BackfilledHourlyRollups = backfilled

	if err := s.ensureHourlyRollupMinRepair(ctx, now); err != nil {
		return result, err
	}

	deleted, err := s.pruneRawResultsIfDue(ctx, now, opts.RawResultRetentionDays)
	if err != nil {
		return result, err
	}
	result.DeletedRawResults = deleted

	deletedRollups, err := s.pruneHourlyRollupsIfDue(ctx, now)
	if err != nil {
		return result, err
	}
	result.DeletedHourlyRollups = deletedRollups

	deletedStateEvents, deletedNotificationEvents, err := s.pruneEventsIfDue(ctx, now, opts)
	if err != nil {
		return result, err
	}
	result.DeletedStateEvents = deletedStateEvents
	result.DeletedNotificationEvents = deletedNotificationEvents

	optimized, err := s.optimizeIfDue(ctx, now)
	if err != nil {
		return result, err
	}
	result.Optimized = optimized

	if err := s.pruneOldNotificationRetries(ctx, now); err != nil {
		return result, err
	}

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

func normalizeMaintenanceOptions(options ...MaintenanceOptions) MaintenanceOptions {
	opts := MaintenanceOptions{
		StateEventRetentionDays:        defaultStoreEventRetentionDays,
		NotificationEventRetentionDays: defaultStoreEventRetentionDays,
		RawResultRetentionDays:         defaultRawResultRetentionDays,
	}
	if len(options) > 0 {
		opts = options[0]
	}
	opts.StateEventRetentionDays = normalizeRetentionDays(opts.StateEventRetentionDays)
	opts.NotificationEventRetentionDays = normalizeRetentionDays(opts.NotificationEventRetentionDays)
	opts.RawResultRetentionDays = NormalizeRawResultRetentionDays(opts.RawResultRetentionDays)
	return opts
}

// NormalizeRawResultRetentionDays clamps the raw check result retention. Older
// data stays available as hourly rollups, so long raw retention mostly costs disk.
func NormalizeRawResultRetentionDays(days int) int {
	if days <= 0 {
		return defaultRawResultRetentionDays
	}
	if days < minRawResultRetentionDays {
		return minRawResultRetentionDays
	}
	if days > maxRawResultRetentionDays {
		return maxRawResultRetentionDays
	}
	return days
}

func normalizeRetentionDays(days int) int {
	if days <= 0 {
		return defaultStoreEventRetentionDays
	}
	return days
}
