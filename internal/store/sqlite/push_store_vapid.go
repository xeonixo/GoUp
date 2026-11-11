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

// GetOrCreateVAPIDKeys returns the VAPID key pair (base64url, raw), generating and storing it
// on first use. The private key is stored encrypted with the control-plane secret key.
func (s *ControlPlaneStore) GetOrCreateVAPIDKeys(ctx context.Context) (privateKey, publicKey string, err error) {
	if len(s.secretKey) == 0 {
		return "", "", errors.New("secret key is not configured")
	}
	priv, pub, ok, err := s.loadVAPIDKeys(ctx)
	if err != nil {
		return "", "", fmt.Errorf("load vapid keys: %w", err)
	}
	if ok {
		return priv, pub, nil
	}

	priv, pub, sealed, err := generateVAPIDKeyPair(s.secretKey)
	if err != nil {
		return "", "", err
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
	priv, pub, ok, err = s.loadVAPIDKeys(ctx)
	if err != nil || !ok {
		return "", "", fmt.Errorf("reload vapid keys: %v", err)
	}
	return priv, pub, nil
}

// RotateVAPIDKeys generates a new VAPID key pair, encrypts and stores it (replacing any
// existing pair), deletes all push subscriptions so clients must re-subscribe, and records
// the rotation time for the profile resubscribe notice.
func (s *ControlPlaneStore) RotateVAPIDKeys(ctx context.Context) (publicKey string, cleared int64, err error) {
	if len(s.secretKey) == 0 {
		return "", 0, errors.New("secret key is not configured")
	}
	_, pub, sealed, err := generateVAPIDKeyPair(s.secretKey)
	if err != nil {
		return "", 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, fmt.Errorf("rotate vapid keys: %w", err)
	}
	defer tx.Rollback()

	for k, v := range map[string]string{
		vapidPublicSettingKey:    pub,
		vapidPrivateSettingKey:   sealed,
		vapidRotatedAtSettingKey: now,
	} {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO system_settings (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value
`, k, v); err != nil {
			return "", 0, fmt.Errorf("store rotated vapid keys: %w", err)
		}
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM push_subscriptions`)
	if err != nil {
		// Table may be missing on a brand-new install that never opened the push UI.
		if !strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return "", 0, fmt.Errorf("clear push subscriptions: %w", err)
		}
	} else {
		cleared, _ = res.RowsAffected()
	}

	if err := tx.Commit(); err != nil {
		return "", 0, fmt.Errorf("commit vapid rotation: %w", err)
	}
	return pub, cleared, nil
}

// VAPIDNeedsResubscribeNotice reports whether the profile UI should show guidance that
// users must reopen the app and re-enable push after a recent VAPID key rotation.
func (s *ControlPlaneStore) VAPIDNeedsResubscribeNotice(ctx context.Context) (bool, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = ?`, vapidRotatedAtSettingKey).Scan(&raw)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load vapid rotation time: %w", err)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, nil
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false, nil
	}
	return time.Since(at) <= VAPIDResubscribeNoticeTTL, nil
}

func (s *ControlPlaneStore) loadVAPIDKeys(ctx context.Context) (privateKey, publicKey string, ok bool, err error) {
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

func generateVAPIDKeyPair(secretKey []byte) (privateKey, publicKey, sealedPrivate string, err error) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate vapid key: %w", err)
	}
	privateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
	publicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	sealedPrivate, err = encryptProviderSecret(secretKey, privateKey)
	if err != nil {
		return "", "", "", fmt.Errorf("encrypt vapid key: %w", err)
	}
	return privateKey, publicKey, sealedPrivate, nil
}
