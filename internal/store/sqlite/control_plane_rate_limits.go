package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Rate-limit attempt kinds persisted for auth lockouts.
const (
	RateLimitKindLocalLogin  = "local_login"
	RateLimitKindAdminAccess = "admin_access"
	RateLimitKindBootstrap   = "bootstrap"
)

// RateLimitAttempt is one auth rate-limit / lockout counter keyed by client identity.
type RateLimitAttempt struct {
	Key         string
	Kind        string
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
}

func (s *ControlPlaneStore) ensureRateLimitAttemptsTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS rate_limit_attempts (
	key TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	failures INTEGER NOT NULL DEFAULT 0,
	window_start DATETIME,
	locked_until DATETIME
)
`); err != nil {
		return fmt.Errorf("create rate_limit_attempts table: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS idx_rate_limit_attempts_kind ON rate_limit_attempts(kind)
`); err != nil {
		return fmt.Errorf("create rate_limit_attempts kind index: %w", err)
	}
	return nil
}

// UpsertRateLimitAttempt writes or replaces one attempt row (best-effort persistence).
func (s *ControlPlaneStore) UpsertRateLimitAttempt(ctx context.Context, attempt RateLimitAttempt) error {
	key := strings.TrimSpace(attempt.Key)
	kind := strings.TrimSpace(attempt.Kind)
	if key == "" {
		return fmt.Errorf("rate limit attempt key is required")
	}
	if kind == "" {
		return fmt.Errorf("rate limit attempt kind is required")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO rate_limit_attempts (key, kind, failures, window_start, locked_until)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
	kind = excluded.kind,
	failures = excluded.failures,
	window_start = excluded.window_start,
	locked_until = excluded.locked_until
`, key, kind, attempt.Failures, nullableTimeArg(attempt.WindowStart), nullableTimeArg(attempt.LockedUntil))
	if err != nil {
		return fmt.Errorf("upsert rate limit attempt: %w", err)
	}
	return nil
}

// DeleteRateLimitAttempt removes one attempt row by key.
func (s *ControlPlaneStore) DeleteRateLimitAttempt(ctx context.Context, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_attempts WHERE key = ?`, key)
	if err != nil {
		return fmt.Errorf("delete rate limit attempt: %w", err)
	}
	return nil
}

// DeleteRateLimitAttempts removes many attempt rows by key.
func (s *ControlPlaneStore) DeleteRateLimitAttempts(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete rate limit attempts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `DELETE FROM rate_limit_attempts WHERE key = ?`)
	if err != nil {
		return fmt.Errorf("prepare delete rate limit attempts: %w", err)
	}
	defer stmt.Close()

	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, err := stmt.ExecContext(ctx, key); err != nil {
			return fmt.Errorf("delete rate limit attempt %q: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete rate limit attempts: %w", err)
	}
	return nil
}

// ListRateLimitAttempts returns all persisted attempt rows.
func (s *ControlPlaneStore) ListRateLimitAttempts(ctx context.Context) ([]RateLimitAttempt, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT key, kind, failures, window_start, locked_until
FROM rate_limit_attempts
`)
	if err != nil {
		return nil, fmt.Errorf("list rate limit attempts: %w", err)
	}
	defer rows.Close()

	items := make([]RateLimitAttempt, 0)
	for rows.Next() {
		var (
			item        RateLimitAttempt
			windowStart sql.NullTime
			lockedUntil sql.NullTime
		)
		if err := rows.Scan(&item.Key, &item.Kind, &item.Failures, &windowStart, &lockedUntil); err != nil {
			return nil, fmt.Errorf("scan rate limit attempt: %w", err)
		}
		if windowStart.Valid {
			item.WindowStart = windowStart.Time.UTC()
		}
		if lockedUntil.Valid {
			item.LockedUntil = lockedUntil.Time.UTC()
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rate limit attempts: %w", err)
	}
	return items, nil
}

// PruneRateLimitAttempts deletes expired rows per kind window.
// A row is kept while LockedUntil is in the future, or WindowStart is within the kind window.
func (s *ControlPlaneStore) PruneRateLimitAttempts(ctx context.Context, now time.Time, kindWindows map[string]time.Duration) (int64, error) {
	if len(kindWindows) == 0 {
		return 0, nil
	}
	now = now.UTC()
	var total int64
	for kind, window := range kindWindows {
		kind = strings.TrimSpace(kind)
		if kind == "" {
			continue
		}
		cutoff := now.Add(-window)
		res, err := s.db.ExecContext(ctx, `
DELETE FROM rate_limit_attempts
WHERE kind = ?
  AND (locked_until IS NULL OR locked_until <= ?)
  AND (window_start IS NULL OR window_start <= ?)
`, kind, now, cutoff)
		if err != nil {
			return total, fmt.Errorf("prune rate limit attempts kind %q: %w", kind, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("read pruned rate limit rows kind %q: %w", kind, err)
		}
		total += n
	}
	return total, nil
}

func nullableTimeArg(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
