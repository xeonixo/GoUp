package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ControlPlaneAdmin holds the single control-plane administrator account.
type ControlPlaneAdmin struct {
	Username       string
	PasswordHash   string
	TOTPEnabled    bool
	SessionVersion int64
	// TOTPUnreadable is set when TOTP is enabled but the stored secret cannot
	// be decrypted (e.g. wrong GOUP_SSO_SECRET_KEY). Login must fail closed.
	TOTPUnreadable bool
	// TOTPSecret is the decrypted TOTP secret; only populated when needed.
	TOTPSecret string
}

// IsSetupRequired returns true when no control-plane admin account exists yet.
func (s *ControlPlaneStore) IsSetupRequired(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM control_plane_admins`).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check control plane admin count: %w", err)
	}
	return count == 0, nil
}

// CreateControlPlaneAdmin creates the single admin account (id=1).
func (s *ControlPlaneStore) CreateControlPlaneAdmin(ctx context.Context, username, passwordHash string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
	INSERT INTO control_plane_admins (id, username, password_hash, totp_secret_ciphertext, totp_enabled, session_version, created_at, updated_at)
	VALUES (1, ?, ?, '', 0, 1, ?, ?)
	`, username, passwordHash, now, now)
	if err != nil {
		return fmt.Errorf("create control plane admin: %w", err)
	}
	return nil
}

// GetControlPlaneAdmin returns the admin account, decrypting the TOTP secret if present.
func (s *ControlPlaneStore) GetControlPlaneAdmin(ctx context.Context) (ControlPlaneAdmin, error) {
	var a ControlPlaneAdmin
	var totpCiphertext string
	var totpEnabled int
	err := s.db.QueryRowContext(ctx, `
	SELECT username, password_hash, totp_secret_ciphertext, totp_enabled, session_version
	FROM control_plane_admins WHERE id = 1
	`).Scan(&a.Username, &a.PasswordHash, &totpCiphertext, &totpEnabled, &a.SessionVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlPlaneAdmin{}, fmt.Errorf("no control plane admin configured")
	}
	if err != nil {
		return ControlPlaneAdmin{}, fmt.Errorf("get control plane admin: %w", err)
	}
	a.TOTPEnabled = totpEnabled == 1
	if totpCiphertext != "" {
		decrypted, err := s.decryptSecret(totpCiphertext)
		if err != nil {
			// Fail closed: TOTP stays enabled with an empty secret, which can
			// never validate. Restore the correct GOUP_SSO_SECRET_KEY (or the
			// GOUP_SESSION_KEY fallback) to regain access.
			a.TOTPEnabled = true
			a.TOTPUnreadable = true
			a.TOTPSecret = ""
			return a, nil
		}
		a.TOTPSecret = decrypted
	}
	return a, nil
}

// UpdateControlPlaneAdminPassword updates the bcrypt password hash.
func (s *ControlPlaneStore) UpdateControlPlaneAdminPassword(ctx context.Context, passwordHash string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
	UPDATE control_plane_admins SET password_hash = ?, session_version = session_version + 1, updated_at = ? WHERE id = 1
	`, passwordHash, now)
	if err != nil {
		return fmt.Errorf("update control plane admin password: %w", err)
	}
	return nil
}

// SetControlPlaneAdminTOTP stores (encrypts) the TOTP secret and sets the enabled flag.
// Pass secret="" to clear the secret. Pass enabled=false to disable without clearing.
func (s *ControlPlaneStore) SetControlPlaneAdminTOTP(ctx context.Context, secret string, enabled bool) error {
	now := time.Now().UTC()
	ciphertext := ""
	if secret != "" {
		encrypted, err := encryptProviderSecret(s.secretKey, secret)
		if err != nil {
			return fmt.Errorf("encrypt totp secret: %w", err)
		}
		ciphertext = encrypted
	}
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := s.db.ExecContext(ctx, `
	UPDATE control_plane_admins
	SET totp_secret_ciphertext = ?, totp_enabled = ?, session_version = session_version + 1, updated_at = ?
	WHERE id = 1
	`, ciphertext, enabledInt, now)
	if err != nil {
		return fmt.Errorf("set control plane admin totp: %w", err)
	}
	return nil
}

// GetOrCreateSessionKey returns the persistent session key from system_settings,
// generating and storing a new random 32-byte key on first call.
func (s *ControlPlaneStore) GetOrCreateSessionKey(ctx context.Context) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM system_settings WHERE key = 'session_key'`).Scan(&value)
	if err == nil && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value), nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("get session key: %w", err)
	}
	// Generate a new random key.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session key: %w", err)
	}
	keyHex := hex.EncodeToString(raw)
	_, err = s.db.ExecContext(ctx, `
	INSERT INTO system_settings (key, value) VALUES ('session_key', ?)
	ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, keyHex)
	if err != nil {
		return "", fmt.Errorf("store session key: %w", err)
	}
	return keyHex, nil
}
