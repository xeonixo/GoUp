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

func (s *Store) ListMonitorSnapshots(ctx context.Context) ([]monitor.Snapshot, error) {
	snapshots, err := s.listMonitorSnapshotsWithResults(ctx)
	if err == nil {
		return snapshots, nil
	}
	if !isMalformedSQLiteError(err) {
		return nil, err
	}

	return s.listMonitorSnapshotsWithoutResults(ctx)
}

const monitorSnapshotSelect = `
SELECT
    m.id,
    m.name,
	m.group_name,
	m.sort_order,
	m.executor_kind,
	m.executor_ref,
    m.kind,
    m.target,
    m.interval_seconds,
    m.timeout_seconds,
    m.enabled,
    m.tls_mode,
    m.expected_status_code,
    m.expected_text,
    m.notify_on_recovery,
    m.retry_count,
    m.retry_interval_seconds,
    m.muted_until,
    m.cert_warning_days,
    m.confirm_after,
    m.mute_start_status,
    m.remind_every_minutes,
    m.last_alert_at,
    m.created_at,
    m.updated_at,
    r.id,
    r.checked_at,
    r.status,
    r.latency_ms,
    r.message,
    r.http_status_code,
    r.tls_valid,
    r.tls_not_after,
    r.tls_days_remaining,
    m.heartbeat_token,
    m.last_heartbeat_at,
    m.last_heartbeat_ok
FROM monitors m
LEFT JOIN monitor_results r ON r.id = (
    SELECT mr.id
    FROM monitor_results mr
    WHERE mr.monitor_id = m.id
    ORDER BY mr.checked_at DESC, mr.id DESC
    LIMIT 1
)
`

func (s *Store) listMonitorSnapshotsWithResults(ctx context.Context) ([]monitor.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, monitorSnapshotSelect+"ORDER BY m.sort_order ASC, m.id ASC")
	if err != nil {
		return nil, fmt.Errorf("list monitors: %w", err)
	}
	defer rows.Close()

	var snapshots []monitor.Snapshot
	for rows.Next() {
		snapshot, err := scanMonitorSnapshot(rows)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate monitors: %w", err)
	}

	return snapshots, nil
}

func (s *Store) listMonitorSnapshotsWithoutResults(ctx context.Context) ([]monitor.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
    id,
    name,
    group_name,
    sort_order,
	executor_kind,
	executor_ref,
    kind,
    target,
    interval_seconds,
    timeout_seconds,
    enabled,
    tls_mode,
    expected_status_code,
    expected_text,
    notify_on_recovery,
    retry_count,
    retry_interval_seconds,
    muted_until,
    cert_warning_days,
    confirm_after,
    mute_start_status,
    remind_every_minutes,
    last_alert_at,
    created_at,
    updated_at,
    heartbeat_token,
    last_heartbeat_at,
    last_heartbeat_ok
FROM monitors
ORDER BY sort_order ASC, id ASC
`)
	if err != nil {
		return nil, fmt.Errorf("list monitors fallback: %w", err)
	}
	defer rows.Close()

	snapshots := make([]monitor.Snapshot, 0)
	for rows.Next() {
		var (
			item                 monitor.Snapshot
			kindRaw              string
			tlsModeRaw           string
			intervalSeconds      int
			timeoutSeconds       int
			enabledRaw           int
			notifyOnRecovery     int
			retryCount           int
			retryIntervalSeconds int
			expectedStatusCode   sql.NullInt64
			mutedUntil           sql.NullTime
			muteStartStatus      string
			lastAlertAt          sql.NullTime
			heartbeatAt          sql.NullTime
			heartbeatOK          int
		)

		if err := rows.Scan(
			&item.Monitor.ID,
			&item.Monitor.Name,
			&item.Monitor.Group,
			&item.Monitor.SortOrder,
			&item.Monitor.ExecutorKind,
			&item.Monitor.ExecutorRef,
			&kindRaw,
			&item.Monitor.Target,
			&intervalSeconds,
			&timeoutSeconds,
			&enabledRaw,
			&tlsModeRaw,
			&expectedStatusCode,
			&item.Monitor.ExpectedText,
			&notifyOnRecovery,
			&retryCount,
			&retryIntervalSeconds,
			&mutedUntil,
			&item.Monitor.CertWarningDays,
			&item.Monitor.ConfirmAfter,
			&muteStartStatus,
			&item.Monitor.RemindEveryMinutes,
			&lastAlertAt,
			&item.Monitor.CreatedAt,
			&item.Monitor.UpdatedAt,
			&item.Monitor.HeartbeatToken,
			&heartbeatAt,
			&heartbeatOK,
		); err != nil {
			return nil, fmt.Errorf("scan monitor fallback: %w", err)
		}
		item.Monitor.MutedUntil = nullableTime(mutedUntil)
		item.Monitor.MuteStartStatus = monitor.Status(strings.TrimSpace(muteStartStatus))
		item.Monitor.ConfirmAfter = normalizeConfirmAfter(item.Monitor.ConfirmAfter)
		item.Monitor.LastAlertAt = nullableTime(lastAlertAt)
		item.Monitor.LastHeartbeatAt = nullableTime(heartbeatAt)
		item.Monitor.LastHeartbeatFailed = heartbeatOK == 0

		item.Monitor.Kind = monitor.Kind(kindRaw)
		if strings.TrimSpace(item.Monitor.ExecutorKind) == "" {
			item.Monitor.ExecutorKind = "local"
		}
		item.Monitor.TLSMode = monitor.TLSMode(tlsModeRaw)
		item.Monitor.Interval = time.Duration(intervalSeconds) * time.Second
		item.Monitor.Timeout = time.Duration(timeoutSeconds) * time.Second
		item.Monitor.Enabled = enabledRaw == 1
		item.Monitor.NotifyOnRecovery = notifyOnRecovery == 1
		item.Monitor.RetryCount = retryCount
		item.Monitor.RetryInterval = time.Duration(retryIntervalSeconds) * time.Second
		if expectedStatusCode.Valid {
			value := int(expectedStatusCode.Int64)
			item.Monitor.ExpectedStatusCode = &value
		}

		snapshots = append(snapshots, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate monitors fallback: %w", err)
	}

	return snapshots, nil
}

// GetMonitorSnapshot loads one monitor with its latest result; it returns sql.ErrNoRows when
// the monitor no longer exists.
func (s *Store) GetMonitorSnapshot(ctx context.Context, monitorID int64) (monitor.Snapshot, error) {
	row := s.db.QueryRowContext(ctx, monitorSnapshotSelect+"WHERE m.id = ?", monitorID)
	snapshot, err := scanMonitorSnapshot(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return monitor.Snapshot{}, sql.ErrNoRows
		}
		return monitor.Snapshot{}, err
	}
	return snapshot, nil
}
