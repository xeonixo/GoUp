package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"goup/internal/monitor"
	"strings"
	"time"
)

func (s *Store) ListMonitorsByExecutor(ctx context.Context, executorKind, executorRef string) ([]monitor.Monitor, error) {
	executorKind = strings.ToLower(strings.TrimSpace(executorKind))
	if executorKind == "" {
		executorKind = "local"
	}
	executorRef = strings.TrimSpace(executorRef)

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
	muted_until,
	cert_warning_days,
	confirm_after,
	mute_start_status,
	created_at,
	updated_at
FROM monitors
WHERE executor_kind = ?
	AND executor_ref = ?
	AND enabled = 1
ORDER BY sort_order ASC, id ASC
`, executorKind, executorRef)
	if err != nil {
		return nil, fmt.Errorf("list monitors by executor: %w", err)
	}
	defer rows.Close()

	items := make([]monitor.Monitor, 0)
	for rows.Next() {
		var item monitor.Monitor
		var intervalSeconds int
		var timeoutSeconds int
		var enabledRaw int
		var notifyOnRecovery int
		var kindRaw string
		var tlsModeRaw string
		var expectedStatusCode sql.NullInt64
		var mutedUntil sql.NullTime
		var muteStartStatus string
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.Group,
			&item.SortOrder,
			&item.ExecutorKind,
			&item.ExecutorRef,
			&kindRaw,
			&item.Target,
			&intervalSeconds,
			&timeoutSeconds,
			&enabledRaw,
			&tlsModeRaw,
			&expectedStatusCode,
			&item.ExpectedText,
			&notifyOnRecovery,
			&mutedUntil,
			&item.CertWarningDays,
			&item.ConfirmAfter,
			&muteStartStatus,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan monitor by executor: %w", err)
		}
		item.MutedUntil = nullableTime(mutedUntil)
		item.MuteStartStatus = monitor.Status(strings.TrimSpace(muteStartStatus))
		item.ConfirmAfter = normalizeConfirmAfter(item.ConfirmAfter)
		item.Kind = monitor.Kind(strings.TrimSpace(kindRaw))
		item.TLSMode = monitor.TLSMode(strings.TrimSpace(tlsModeRaw))
		item.Interval = time.Duration(intervalSeconds) * time.Second
		item.Timeout = time.Duration(timeoutSeconds) * time.Second
		item.Enabled = enabledRaw == 1
		item.NotifyOnRecovery = notifyOnRecovery == 1
		if item.ExecutorKind == "" {
			item.ExecutorKind = "local"
		}
		if expectedStatusCode.Valid {
			value := int(expectedStatusCode.Int64)
			item.ExpectedStatusCode = &value
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate monitors by executor: %w", err)
	}

	return items, nil
}

func scanMonitorSnapshot(scanner interface{ Scan(dest ...any) error }) (monitor.Snapshot, error) {
	var item monitor.Snapshot
	var intervalSeconds int
	var timeoutSeconds int
	var enabled int
	var notifyOnRecovery int
	var retryCount int
	var retryIntervalSeconds int
	var sortOrder int
	var executorKind string
	var executorRef string
	var kind string
	var tlsMode string
	var expectedStatusCode sql.NullInt64
	var expectedText string
	var mutedUntil sql.NullTime
	var muteStartStatus string
	var lastAlertAt sql.NullTime
	var resultID sql.NullInt64
	var checkedAt sql.NullTime
	var status sql.NullString
	var latencyMS sql.NullInt64
	var message sql.NullString
	var httpStatusCode sql.NullInt64
	var tlsValid sql.NullInt64
	var tlsNotAfter sql.NullTime
	var tlsDaysRemaining sql.NullInt64

	if err := scanner.Scan(
		&item.Monitor.ID,
		&item.Monitor.Name,
		&item.Monitor.Group,
		&sortOrder,
		&executorKind,
		&executorRef,
		&kind,
		&item.Monitor.Target,
		&intervalSeconds,
		&timeoutSeconds,
		&enabled,
		&tlsMode,
		&expectedStatusCode,
		&expectedText,
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
		&resultID,
		&checkedAt,
		&status,
		&latencyMS,
		&message,
		&httpStatusCode,
		&tlsValid,
		&tlsNotAfter,
		&tlsDaysRemaining,
	); err != nil {
		return monitor.Snapshot{}, fmt.Errorf("scan monitor snapshot: %w", err)
	}

	item.Monitor.Kind = monitor.Kind(kind)
	item.Monitor.SortOrder = sortOrder
	item.Monitor.ExecutorKind = strings.TrimSpace(executorKind)
	if item.Monitor.ExecutorKind == "" {
		item.Monitor.ExecutorKind = "local"
	}
	item.Monitor.ExecutorRef = strings.TrimSpace(executorRef)
	item.Monitor.Interval = time.Duration(intervalSeconds) * time.Second
	item.Monitor.Timeout = time.Duration(timeoutSeconds) * time.Second
	item.Monitor.Enabled = enabled == 1
	item.Monitor.TLSMode = monitor.TLSMode(tlsMode)
	item.Monitor.ExpectedText = expectedText
	item.Monitor.NotifyOnRecovery = notifyOnRecovery == 1
	item.Monitor.RetryCount = retryCount
	item.Monitor.RetryInterval = time.Duration(retryIntervalSeconds) * time.Second
	item.Monitor.MutedUntil = nullableTime(mutedUntil)
	item.Monitor.MuteStartStatus = monitor.Status(strings.TrimSpace(muteStartStatus))
	item.Monitor.ConfirmAfter = normalizeConfirmAfter(item.Monitor.ConfirmAfter)
	item.Monitor.LastAlertAt = nullableTime(lastAlertAt)
	if expectedStatusCode.Valid {
		value := int(expectedStatusCode.Int64)
		item.Monitor.ExpectedStatusCode = &value
	}

	if resultID.Valid {
		result := &monitor.Result{
			ID:        resultID.Int64,
			MonitorID: item.Monitor.ID,
			CheckedAt: checkedAt.Time,
			Status:    monitor.Status(status.String),
			Latency:   time.Duration(latencyMS.Int64) * time.Millisecond,
			Message:   message.String,
		}
		if httpStatusCode.Valid {
			value := int(httpStatusCode.Int64)
			result.HTTPStatusCode = &value
		}
		if tlsValid.Valid {
			value := tlsValid.Int64 == 1
			result.TLSValid = &value
		}
		if tlsNotAfter.Valid {
			value := tlsNotAfter.Time
			result.TLSNotAfter = &value
		}
		if tlsDaysRemaining.Valid {
			value := int(tlsDaysRemaining.Int64)
			result.TLSDaysRemaining = &value
		}
		item.LastResult = result
	}

	return item, nil
}
