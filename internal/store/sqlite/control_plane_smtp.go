package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type GlobalSMTPSettings struct {
	Host               string
	Port               int
	Username           string
	FromEmail          string
	FromName           string
	TLSMode            string // none, starttls, tls
	PasswordConfigured bool
}

type GlobalSMTPDeliveryConfig struct {
	Settings GlobalSMTPSettings
	Password string
}

func (s *ControlPlaneStore) GetGlobalSMTPSettings(ctx context.Context) (GlobalSMTPSettings, error) {
	var settings GlobalSMTPSettings
	var passwordCiphertext string
	err := s.db.QueryRowContext(ctx, `
SELECT host, port, username, password_ciphertext, from_email, from_name, tls_mode
FROM global_smtp_settings
WHERE id = 1
`).Scan(&settings.Host, &settings.Port, &settings.Username, &passwordCiphertext, &settings.FromEmail, &settings.FromName, &settings.TLSMode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			settings.Port = 587
			settings.TLSMode = "starttls"
			return settings, nil
		}
		return GlobalSMTPSettings{}, fmt.Errorf("get global smtp settings: %w", err)
	}
	settings.PasswordConfigured = strings.TrimSpace(passwordCiphertext) != ""
	if settings.Port <= 0 {
		settings.Port = 587
	}
	settings.TLSMode = normalizeSMTPMode(settings.TLSMode)
	return settings, nil
}

func (s *ControlPlaneStore) UpsertGlobalSMTPSettings(ctx context.Context, settings GlobalSMTPSettings, password string) error {
	settings.Host = strings.TrimSpace(settings.Host)
	settings.Username = strings.TrimSpace(settings.Username)
	settings.FromEmail = strings.TrimSpace(settings.FromEmail)
	settings.FromName = strings.TrimSpace(settings.FromName)
	settings.TLSMode = normalizeSMTPMode(settings.TLSMode)
	if settings.Port <= 0 {
		settings.Port = 587
	}

	password = strings.TrimSpace(password)
	if password != "" && len(s.secretKey) == 0 {
		return fmt.Errorf("secret key is not configured")
	}

	var existingCiphertext string
	err := s.db.QueryRowContext(ctx, `
SELECT password_ciphertext
FROM global_smtp_settings
WHERE id = 1
`).Scan(&existingCiphertext)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load existing smtp password: %w", err)
	}

	passwordCiphertext := existingCiphertext
	if password != "" {
		sealed, encErr := encryptProviderSecret(s.secretKey, password)
		if encErr != nil {
			return fmt.Errorf("encrypt smtp password: %w", encErr)
		}
		passwordCiphertext = sealed
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO global_smtp_settings (id, host, port, username, password_ciphertext, from_email, from_name, tls_mode, updated_at)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	host = excluded.host,
	port = excluded.port,
	username = excluded.username,
	password_ciphertext = excluded.password_ciphertext,
	from_email = excluded.from_email,
	from_name = excluded.from_name,
	tls_mode = excluded.tls_mode,
	updated_at = excluded.updated_at
`, settings.Host, settings.Port, settings.Username, passwordCiphertext, settings.FromEmail, settings.FromName, settings.TLSMode, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("upsert global smtp settings: %w", err)
	}

	return nil
}

func (s *ControlPlaneStore) GetGlobalSMTPDeliveryConfig(ctx context.Context) (GlobalSMTPDeliveryConfig, error) {
	settings, err := s.GetGlobalSMTPSettings(ctx)
	if err != nil {
		return GlobalSMTPDeliveryConfig{}, err
	}

	var passwordCiphertext string
	err = s.db.QueryRowContext(ctx, `
SELECT password_ciphertext
FROM global_smtp_settings
WHERE id = 1
`).Scan(&passwordCiphertext)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GlobalSMTPDeliveryConfig{Settings: settings}, nil
		}
		return GlobalSMTPDeliveryConfig{}, fmt.Errorf("load smtp password: %w", err)
	}

	cfg := GlobalSMTPDeliveryConfig{Settings: settings}
	if strings.TrimSpace(passwordCiphertext) == "" {
		return cfg, nil
	}
	if len(s.secretKey) == 0 {
		return GlobalSMTPDeliveryConfig{}, fmt.Errorf("secret key is not configured")
	}

	password, err := s.decryptSecret(passwordCiphertext)
	if err != nil {
		return GlobalSMTPDeliveryConfig{}, fmt.Errorf("decrypt smtp password: %w", err)
	}
	cfg.Password = password
	return cfg, nil
}

func normalizeSMTPMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "none", "tls":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "starttls"
	}
}
