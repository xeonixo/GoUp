package sqlite

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

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
