package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"goup/internal/monitor"
	"strings"
	"time"
)

type CreateMonitorParams struct {
	Name               string
	Group              string
	ExecutorKind       string
	ExecutorRef        string
	Kind               monitor.Kind
	Target             string
	Interval           time.Duration
	Timeout            time.Duration
	Enabled            bool
	TLSMode            monitor.TLSMode
	ExpectedStatusCode *int
	ExpectedText       string
	NotifyOnRecovery   bool
	RetryCount         int
	RetryInterval      time.Duration
	CertWarningDays    int
	// ConfirmAfter is the number of consecutive failed checks required before a down/degraded
	// transition is announced (flapping protection). 1 announces immediately.
	ConfirmAfter int
	// RemindEveryMinutes repeats the down alert while the outage lasts (0 = off).
	RemindEveryMinutes int
}

type UpdateMonitorParams struct {
	ID int64
	CreateMonitorParams
}

func (s *Store) CreateMonitor(ctx context.Context, params CreateMonitorParams) (int64, error) {
	if err := validateCreateMonitorParams(params); err != nil {
		return 0, err
	}
	executorKind, executorRef := normalizeMonitorExecutor(params.ExecutorKind, params.ExecutorRef)

	now := time.Now().UTC()
	if err := s.ensureMonitorGroupExists(ctx, strings.TrimSpace(params.Group)); err != nil {
		return 0, err
	}
	nextSortOrder, err := s.nextMonitorSortOrder(ctx)
	if err != nil {
		return 0, err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO monitors (
	name, group_name, sort_order, executor_kind, executor_ref, kind, target, interval_seconds, timeout_seconds, enabled,
    tls_mode, expected_status_code, expected_text, notify_on_recovery,
    retry_count, retry_interval_seconds, cert_warning_days, confirm_after, remind_every_minutes,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, params.Name, strings.TrimSpace(params.Group), nextSortOrder, executorKind, executorRef, string(params.Kind), params.Target, int(params.Interval.Seconds()), int(params.Timeout.Seconds()), boolToInt(params.Enabled), string(params.TLSMode), params.ExpectedStatusCode, strings.TrimSpace(params.ExpectedText), boolToInt(params.NotifyOnRecovery), params.RetryCount, int(params.RetryInterval.Seconds()), normalizeCertWarningDays(params.CertWarningDays), normalizeConfirmAfter(params.ConfirmAfter), params.RemindEveryMinutes, now, now)
	if err != nil {
		return 0, fmt.Errorf("create monitor: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read monitor id: %w", err)
	}

	return id, nil
}

func (s *Store) UpdateMonitor(ctx context.Context, params UpdateMonitorParams) error {
	if params.ID <= 0 {
		return errors.New("monitor id is required")
	}

	if err := validateCreateMonitorParams(params.CreateMonitorParams); err != nil {
		return err
	}
	executorKind, executorRef := normalizeMonitorExecutor(params.ExecutorKind, params.ExecutorRef)

	now := time.Now().UTC()
	if err := s.ensureMonitorGroupExists(ctx, strings.TrimSpace(params.Group)); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE monitors
SET
    name = ?,
	group_name = ?,
	executor_kind = ?,
	executor_ref = ?,
    kind = ?,
    target = ?,
    interval_seconds = ?,
    timeout_seconds = ?,
    enabled = ?,
    tls_mode = ?,
    expected_status_code = ?,
    expected_text = ?,
    notify_on_recovery = ?,
    retry_count = ?,
    retry_interval_seconds = ?,
    cert_warning_days = ?,
    confirm_after = ?,
    remind_every_minutes = ?,
    updated_at = ?
WHERE id = ?
`,
		params.Name,
		strings.TrimSpace(params.Group),
		executorKind,
		executorRef,
		string(params.Kind),
		params.Target,
		int(params.Interval.Seconds()),
		int(params.Timeout.Seconds()),
		boolToInt(params.Enabled),
		string(params.TLSMode),
		params.ExpectedStatusCode,
		strings.TrimSpace(params.ExpectedText),
		boolToInt(params.NotifyOnRecovery),
		params.RetryCount,
		int(params.RetryInterval.Seconds()),
		normalizeCertWarningDays(params.CertWarningDays),
		normalizeConfirmAfter(params.ConfirmAfter),
		params.RemindEveryMinutes,
		now,
		params.ID,
	)
	if err != nil {
		return fmt.Errorf("update monitor: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update monitor rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (s *Store) DeleteMonitor(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM monitors WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete monitor: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete monitor rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (s *Store) SetMonitorEnabled(ctx context.Context, id int64, enabled bool) error {
	if id <= 0 {
		return errors.New("monitor id is required")
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE monitors
SET enabled = ?, updated_at = ?
WHERE id = ?
`, boolToInt(enabled), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("set monitor enabled: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("set monitor enabled rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// SetMonitorsMutedUntil suppresses notifications for the given monitors until the given time;
// a nil time unmutes them. It returns how many monitors were updated.
func (s *Store) SetMonitorsMutedUntil(ctx context.Context, ids []int64, until *time.Time) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var value any
	if until != nil {
		value = until.UTC()
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := []any{value, time.Now().UTC()}
	for _, id := range ids {
		args = append(args, id)
	}
	// mute_start_status remembers the status when the mute began so a catch-up notification can
	// be sent afterwards. Extending a running mute keeps the original value; unmuting keeps it
	// as a pending catch-up marker until the runner has processed it.
	now := time.Now().UTC()
	args = append([]any{value, now, value, now}, args[2:]...)
	result, err := s.db.ExecContext(ctx, `
UPDATE monitors
SET mute_start_status = CASE
        WHEN ? IS NULL THEN mute_start_status
        WHEN muted_until IS NOT NULL AND muted_until > ? THEN mute_start_status
        ELSE COALESCE((
            SELECT r.status FROM monitor_results r
            WHERE r.monitor_id = monitors.id
            ORDER BY r.checked_at DESC, r.id DESC LIMIT 1
        ), '')
    END,
    muted_until = ?, updated_at = ?
WHERE id IN (`+placeholders+`)
`, args...)
	if err != nil {
		return 0, fmt.Errorf("set monitor muted_until: %w", err)
	}
	return result.RowsAffected()
}

// MaxConfirmAfter bounds the flapping-protection setting.
const MaxConfirmAfter = 10

func normalizeConfirmAfter(value int) int {
	if value < 1 {
		return 1
	}
	if value > MaxConfirmAfter {
		return MaxConfirmAfter
	}
	return value
}

func normalizeCertWarningDays(days int) int {
	if days <= 0 {
		return monitor.DefaultCertWarningDays
	}
	return days
}

func nullableTime(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time
	return &t
}

func (s *Store) UpdateMonitorTarget(ctx context.Context, id int64, target string) error {
	var kindRaw string
	var tlsModeRaw string
	err := s.db.QueryRowContext(ctx, `
SELECT kind, tls_mode
FROM monitors
WHERE id = ?
`, id).Scan(&kindRaw, &tlsModeRaw)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.ErrNoRows
		}
		return fmt.Errorf("load monitor for target update: %w", err)
	}

	kind := monitor.Kind(kindRaw)
	tlsMode := monitor.TLSMode(tlsModeRaw)
	if err := validateMonitorKindSettings(kind, strings.TrimSpace(target), tlsMode, nil); err != nil {
		return err
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE monitors
SET target = ?, updated_at = ?
WHERE id = ?
`, strings.TrimSpace(target), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update monitor target: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update monitor target rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (s *Store) ReassignRemoteNodeMonitorsToLocal(ctx context.Context, nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("node id is required")
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE monitors
SET executor_kind = 'local', executor_ref = '', updated_at = ?
WHERE executor_kind = 'remote' AND executor_ref = ?
`, time.Now().UTC(), nodeID)
	if err != nil {
		return fmt.Errorf("reassign remote node monitors: %w", err)
	}
	return nil
}

// ClearMonitorMuteStartStatus drops the pending mute catch-up marker once it was handled.
func (s *Store) ClearMonitorMuteStartStatus(ctx context.Context, monitorID int64) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE monitors SET mute_start_status = '' WHERE id = ?`, monitorID); err != nil {
		return fmt.Errorf("clear monitor mute_start_status: %w", err)
	}
	return nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableBoolInt(value *bool) any {
	if value == nil {
		return nil
	}
	if *value {
		return 1
	}
	return 0
}
