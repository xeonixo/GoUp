package sqlite

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxPushSubscriptionsPerUser caps the number of devices a user can register in one tenant.
const MaxPushSubscriptionsPerUser = 10

// ErrPushSubscriptionLimit is returned when a user already owns the maximum number of devices.
var ErrPushSubscriptionLimit = errors.New("push subscription limit reached")

const (
	vapidPublicSettingKey  = "vapid_public_key"
	vapidPrivateSettingKey = "vapid_private_key_ciphertext"
)

// PushSubscription is one registered Web Push endpoint (one browser/device of a user).
// P256dh and Auth are stored encrypted and returned decrypted.
type PushSubscription struct {
	ID            int64
	TenantID      int64
	UserID        int64
	Endpoint      string
	P256dh        string
	Auth          string
	UserAgent     string
	DeviceLabel   string
	CreatedAt     time.Time
	LastSuccessAt *time.Time
	LastError     string
	LastErrorAt   *time.Time
	// ReplacesEndpoint (upsert input only) names one of the user's own earlier endpoints that
	// this subscription supersedes; it is removed in the same transaction.
	ReplacesEndpoint string

	NotifyDown     bool
	NotifyRecovery bool
	NotifyDegraded bool
	NotifyReminder bool
}

// PushTarget is a subscription together with the owner's preferred language.
type PushTarget struct {
	PushSubscription
	PreferredLanguage string
}

// PushPrefs selects which event categories a device receives.
type PushPrefs struct {
	Down     bool
	Recovery bool
	Degraded bool
	Reminder bool
}

// DefaultPushPrefs enables every category.
func DefaultPushPrefs() PushPrefs {
	return PushPrefs{Down: true, Recovery: true, Degraded: true, Reminder: true}
}

func (s *ControlPlaneStore) ensurePushTables(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS push_subscriptions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	endpoint TEXT NOT NULL UNIQUE,
	p256dh_ciphertext TEXT NOT NULL,
	auth_ciphertext TEXT NOT NULL,
	user_agent TEXT NOT NULL DEFAULT '',
	device_label TEXT NOT NULL DEFAULT '',
	notify_down INTEGER NOT NULL DEFAULT 1,
	notify_recovery INTEGER NOT NULL DEFAULT 1,
	notify_degraded INTEGER NOT NULL DEFAULT 1,
	notify_reminder INTEGER NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL,
	last_success_at DATETIME,
	last_error TEXT NOT NULL DEFAULT '',
	last_error_at DATETIME,
	FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(tenant_id, user_id);
`); err != nil {
		return fmt.Errorf("create push subscriptions table: %w", err)
	}
	return nil
}

// GetOrCreateVAPIDKeys returns the VAPID key pair (base64url, raw), generating and storing it
// on first use. The private key is stored encrypted with the control-plane secret key.
func (s *ControlPlaneStore) GetOrCreateVAPIDKeys(ctx context.Context) (privateKey, publicKey string, err error) {
	if len(s.secretKey) == 0 {
		return "", "", errors.New("secret key is not configured")
	}
	load := func() (string, string, bool, error) {
		var pub, privCipher string
		rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM system_settings WHERE key IN (?, ?)`, vapidPublicSettingKey, vapidPrivateSettingKey)
		if err != nil {
			return "", "", false, err
		}
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				return "", "", false, err
			}
			switch k {
			case vapidPublicSettingKey:
				pub = strings.TrimSpace(v)
			case vapidPrivateSettingKey:
				privCipher = strings.TrimSpace(v)
			}
		}
		if err := rows.Err(); err != nil {
			return "", "", false, err
		}
		if pub == "" || privCipher == "" {
			return "", "", false, nil
		}
		priv, err := s.decryptSecret(privCipher)
		if err != nil {
			return "", "", false, fmt.Errorf("decrypt vapid private key: %w", err)
		}
		return priv, pub, true, nil
	}

	priv, pub, ok, err := load()
	if err != nil {
		return "", "", fmt.Errorf("load vapid keys: %w", err)
	}
	if ok {
		return priv, pub, nil
	}

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate vapid key: %w", err)
	}
	priv = base64.RawURLEncoding.EncodeToString(key.Bytes())
	pub = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	sealed, err := encryptProviderSecret(s.secretKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("encrypt vapid key: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("store vapid keys: %w", err)
	}
	defer tx.Rollback()
	// DO NOTHING keeps the first writer's pair if two goroutines race; re-read below.
	for k, v := range map[string]string{vapidPublicSettingKey: pub, vapidPrivateSettingKey: sealed} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`, k, v); err != nil {
			return "", "", fmt.Errorf("store vapid keys: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", "", fmt.Errorf("store vapid keys: %w", err)
	}
	priv, pub, ok, err = load()
	if err != nil || !ok {
		return "", "", fmt.Errorf("reload vapid keys: %v", err)
	}
	return priv, pub, nil
}

// UpsertPushSubscription registers a device. The endpoint is unique: if it already exists
// (even for another user or tenant) the row is reassigned to the caller and its keys refreshed.
func (s *ControlPlaneStore) UpsertPushSubscription(ctx context.Context, sub PushSubscription) (PushSubscription, error) {
	sub.Endpoint = strings.TrimSpace(sub.Endpoint)
	if sub.TenantID <= 0 || sub.UserID <= 0 || sub.Endpoint == "" || sub.P256dh == "" || sub.Auth == "" {
		return PushSubscription{}, errors.New("tenant, user, endpoint and keys are required")
	}
	if len(s.secretKey) == 0 {
		return PushSubscription{}, errors.New("secret key is not configured")
	}
	p256dh, err := encryptProviderSecret(s.secretKey, sub.P256dh)
	if err != nil {
		return PushSubscription{}, fmt.Errorf("encrypt p256dh: %w", err)
	}
	auth, err := encryptProviderSecret(s.secretKey, sub.Auth)
	if err != nil {
		return PushSubscription{}, fmt.Errorf("encrypt auth: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PushSubscription{}, fmt.Errorf("begin push subscription upsert: %w", err)
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM push_subscriptions WHERE tenant_id = ? AND user_id = ? AND endpoint <> ? AND endpoint <> ?
`, sub.TenantID, sub.UserID, sub.Endpoint, sub.ReplacesEndpoint).Scan(&count); err != nil {
		return PushSubscription{}, fmt.Errorf("count push subscriptions: %w", err)
	}
	if count >= MaxPushSubscriptionsPerUser {
		return PushSubscription{}, ErrPushSubscriptionLimit
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO push_subscriptions (tenant_id, user_id, endpoint, p256dh_ciphertext, auth_ciphertext, user_agent, device_label,
	notify_down, notify_recovery, notify_degraded, notify_reminder, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(endpoint) DO UPDATE SET
	tenant_id = excluded.tenant_id,
	user_id = excluded.user_id,
	p256dh_ciphertext = excluded.p256dh_ciphertext,
	auth_ciphertext = excluded.auth_ciphertext,
	user_agent = excluded.user_agent,
	device_label = excluded.device_label,
	notify_down = excluded.notify_down,
	notify_recovery = excluded.notify_recovery,
	notify_degraded = excluded.notify_degraded,
	notify_reminder = excluded.notify_reminder,
	last_error = '',
	last_error_at = NULL
`, sub.TenantID, sub.UserID, sub.Endpoint, p256dh, auth, sub.UserAgent, sub.DeviceLabel,
		boolToInt(sub.NotifyDown), boolToInt(sub.NotifyRecovery), boolToInt(sub.NotifyDegraded), boolToInt(sub.NotifyReminder), now); err != nil {
		return PushSubscription{}, fmt.Errorf("upsert push subscription: %w", err)
	}
	if old := strings.TrimSpace(sub.ReplacesEndpoint); old != "" && old != sub.Endpoint {
		if _, err := tx.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE tenant_id = ? AND user_id = ? AND endpoint = ?`, sub.TenantID, sub.UserID, old); err != nil {
			return PushSubscription{}, fmt.Errorf("remove replaced push subscription: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return PushSubscription{}, fmt.Errorf("commit push subscription: %w", err)
	}

	items, err := s.queryPushSubscriptions(ctx, `WHERE ps.endpoint = ?`, sub.Endpoint)
	if err != nil || len(items) == 0 {
		return PushSubscription{}, fmt.Errorf("reload push subscription: %v", err)
	}
	return items[0].PushSubscription, nil
}

// ListUserPushSubscriptions returns the caller's devices, newest first.
func (s *ControlPlaneStore) ListUserPushSubscriptions(ctx context.Context, tenantID, userID int64) ([]PushSubscription, error) {
	items, err := s.queryPushSubscriptions(ctx, `WHERE ps.tenant_id = ? AND ps.user_id = ?`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	out := make([]PushSubscription, len(items))
	for i := range items {
		out[i] = items[i].PushSubscription
	}
	return out, nil
}

// ListTenantPushTargets returns the devices of all active, non-blocked members of a tenant
// (only admins when adminOnly), with the owner's preferred language.
func (s *ControlPlaneStore) ListTenantPushTargets(ctx context.Context, tenantID int64, adminOnly bool) ([]PushTarget, error) {
	if tenantID <= 0 {
		return nil, errors.New("tenant id is required")
	}
	where := `
JOIN tenant_memberships tm ON tm.tenant_id = ps.tenant_id AND tm.user_id = ps.user_id
JOIN tenants t ON t.id = tm.tenant_id
WHERE ps.tenant_id = ? AND t.active = 1 AND tm.blocked = 0`
	if adminOnly {
		where += ` AND lower(trim(tm.role)) = 'admin'`
	}
	return s.queryPushSubscriptions(ctx, where, tenantID)
}

// queryPushSubscriptions runs the shared SELECT; clause starts with JOIN/WHERE.
func (s *ControlPlaneStore) queryPushSubscriptions(ctx context.Context, clause string, args ...any) ([]PushTarget, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ps.id, ps.tenant_id, ps.user_id, ps.endpoint, ps.p256dh_ciphertext, ps.auth_ciphertext, ps.user_agent, ps.device_label,
	ps.notify_down, ps.notify_recovery, ps.notify_degraded, ps.notify_reminder,
	ps.created_at, ps.last_success_at, ps.last_error, ps.last_error_at,
	COALESCE((SELECT NULLIF(trim(u.preferred_language), '') FROM users u WHERE u.id = ps.user_id), 'en')
FROM push_subscriptions ps
`+clause+`
ORDER BY ps.created_at DESC, ps.id DESC
`, args...)
	if err != nil {
		return nil, fmt.Errorf("query push subscriptions: %w", err)
	}
	defer rows.Close()

	var items []PushTarget
	for rows.Next() {
		var (
			t                                  PushTarget
			p256Cipher, authCipher             string
			down, recovery, degraded, reminder int
			lastSuccess, lastErrorAt           sql.NullTime
		)
		if err := rows.Scan(&t.ID, &t.TenantID, &t.UserID, &t.Endpoint, &p256Cipher, &authCipher, &t.UserAgent, &t.DeviceLabel,
			&down, &recovery, &degraded, &reminder,
			&t.CreatedAt, &lastSuccess, &t.LastError, &lastErrorAt, &t.PreferredLanguage); err != nil {
			return nil, fmt.Errorf("scan push subscription: %w", err)
		}
		p256, err1 := s.decryptSecret(p256Cipher)
		auth, err2 := s.decryptSecret(authCipher)
		if err1 != nil || err2 != nil {
			continue // undecryptable (key rotated): skip rather than fail every notification
		}
		t.P256dh, t.Auth = p256, auth
		t.NotifyDown, t.NotifyRecovery, t.NotifyDegraded, t.NotifyReminder = down == 1, recovery == 1, degraded == 1, reminder == 1
		t.LastSuccessAt = nullableTime(lastSuccess)
		t.LastErrorAt = nullableTime(lastErrorAt)
		items = append(items, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate push subscriptions: %w", err)
	}
	return items, nil
}

// DeleteUserPushSubscriptionByEndpoint removes the caller's own subscription; it reports
// whether a row was deleted (false for unknown endpoints and for other users' endpoints).
func (s *ControlPlaneStore) DeleteUserPushSubscriptionByEndpoint(ctx context.Context, tenantID, userID int64, endpoint string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE tenant_id = ? AND user_id = ? AND endpoint = ?`, tenantID, userID, strings.TrimSpace(endpoint))
	if err != nil {
		return false, fmt.Errorf("delete push subscription: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteUserPushSubscription removes the caller's own subscription by id.
func (s *ControlPlaneStore) DeleteUserPushSubscription(ctx context.Context, tenantID, userID, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE tenant_id = ? AND user_id = ? AND id = ?`, tenantID, userID, id)
	if err != nil {
		return false, fmt.Errorf("delete push subscription: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeletePushSubscriptionByID removes a subscription the push service reported as gone.
func (s *ControlPlaneStore) DeletePushSubscriptionByID(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete push subscription: %w", err)
	}
	return nil
}

// UpdatePushSubscriptionPrefs sets the event categories of one of the caller's devices.
func (s *ControlPlaneStore) UpdatePushSubscriptionPrefs(ctx context.Context, tenantID, userID, id int64, prefs PushPrefs) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE push_subscriptions SET notify_down = ?, notify_recovery = ?, notify_degraded = ?, notify_reminder = ?
WHERE tenant_id = ? AND user_id = ? AND id = ?
`, boolToInt(prefs.Down), boolToInt(prefs.Recovery), boolToInt(prefs.Degraded), boolToInt(prefs.Reminder), tenantID, userID, id)
	if err != nil {
		return false, fmt.Errorf("update push subscription prefs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecordPushResult stores the outcome of the latest delivery attempt.
func (s *ControlPlaneStore) RecordPushResult(ctx context.Context, id int64, success bool, errMsg string) error {
	now := time.Now().UTC()
	var err error
	if success {
		_, err = s.db.ExecContext(ctx, `UPDATE push_subscriptions SET last_success_at = ?, last_error = '', last_error_at = NULL WHERE id = ?`, now, id)
	} else {
		if len(errMsg) > 300 {
			errMsg = errMsg[:300]
		}
		_, err = s.db.ExecContext(ctx, `UPDATE push_subscriptions SET last_error = ?, last_error_at = ? WHERE id = ?`, errMsg, now, id)
	}
	if err != nil {
		return fmt.Errorf("record push result: %w", err)
	}
	return nil
}
