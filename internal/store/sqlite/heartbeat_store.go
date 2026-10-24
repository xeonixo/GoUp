package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"goup/internal/monitor"
	"strings"
	"time"
)

// HeartbeatTarget is the display value stored as target of heartbeat monitors.
const HeartbeatTarget = "heartbeat"

// MinHeartbeatPeriod is the shortest expected ping period.
const MinHeartbeatPeriod = 60 * time.Second

// ensureHeartbeatColumns adds the push-monitor columns: the secret ping token (unique when set),
// the time of the latest ping and whether that ping reported success.
func (s *Store) ensureHeartbeatColumns(ctx context.Context) error {
	if _, err := s.ensureColumn(ctx, "monitors", "heartbeat_token", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := s.ensureColumn(ctx, "monitors", "last_heartbeat_at", "DATETIME"); err != nil {
		return err
	}
	if _, err := s.ensureColumn(ctx, "monitors", "last_heartbeat_ok", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE UNIQUE INDEX IF NOT EXISTS idx_monitors_heartbeat_token
ON monitors(heartbeat_token) WHERE heartbeat_token <> ''`); err != nil {
		return fmt.Errorf("create heartbeat token index: %w", err)
	}
	return nil
}

// newHeartbeatToken returns 32 random bytes, base64url encoded (43 characters).
func newHeartbeatToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate heartbeat token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// normalizeHeartbeatParams forces the fixed fields of a heartbeat monitor: it has no target,
// no TLS/expectation settings and always runs locally.
func normalizeHeartbeatParams(params CreateMonitorParams) CreateMonitorParams {
	if params.Kind != monitor.KindHeartbeat {
		return params
	}
	params.Target = HeartbeatTarget
	params.TLSMode = monitor.TLSModeNone
	params.ExpectedStatusCode = nil
	params.ExpectedText = ""
	params.ExecutorKind, params.ExecutorRef = "local", ""
	return params
}

// GetMonitorSnapshotByHeartbeatToken resolves a ping token to its monitor (sql.ErrNoRows when
// the token is unknown or empty).
func (s *Store) GetMonitorSnapshotByHeartbeatToken(ctx context.Context, token string) (monitor.Snapshot, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return monitor.Snapshot{}, sql.ErrNoRows
	}
	row := s.db.QueryRowContext(ctx, monitorSnapshotSelect+"WHERE m.heartbeat_token = ? AND m.kind = 'heartbeat'", token)
	snapshot, err := scanMonitorSnapshot(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return monitor.Snapshot{}, sql.ErrNoRows
		}
		return monitor.Snapshot{}, err
	}
	return snapshot, nil
}

// RecordHeartbeat stores the time of a ping and whether the job reported success.
func (s *Store) RecordHeartbeat(ctx context.Context, monitorID int64, at time.Time, ok bool) error {
	if _, err := s.db.ExecContext(ctx, `
UPDATE monitors SET last_heartbeat_at = ?, last_heartbeat_ok = ? WHERE id = ?`,
		at.UTC(), boolToInt(ok), monitorID); err != nil {
		return fmt.Errorf("record heartbeat: %w", err)
	}
	return nil
}

// RegenerateHeartbeatToken replaces the ping token of a heartbeat monitor and returns the new
// one; the old URL stops working immediately. sql.ErrNoRows when no heartbeat monitor matches.
func (s *Store) RegenerateHeartbeatToken(ctx context.Context, monitorID int64) (string, error) {
	token, err := newHeartbeatToken()
	if err != nil {
		return "", err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE monitors SET heartbeat_token = ?, updated_at = ?
WHERE id = ? AND kind = 'heartbeat'`, token, time.Now().UTC(), monitorID)
	if err != nil {
		return "", fmt.Errorf("regenerate heartbeat token: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("regenerate heartbeat token rows affected: %w", err)
	}
	if affected == 0 {
		return "", sql.ErrNoRows
	}
	return token, nil
}
