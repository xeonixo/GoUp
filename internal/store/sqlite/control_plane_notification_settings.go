package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type UserNotificationSettings struct {
	EmailEnabled        bool
	MatrixEnabled       bool
	MatrixHomeserver    string
	MatrixRoomID        string
	MatrixAccessToken   string
	HasLocalCredentials bool
}

func (s *ControlPlaneStore) GetUserNotificationSettings(ctx context.Context, tenantID, userID int64) (UserNotificationSettings, error) {
	if tenantID <= 0 || userID <= 0 {
		return UserNotificationSettings{}, fmt.Errorf("tenant id and user id are required")
	}

	var settings UserNotificationSettings
	var emailEnabled int
	var hasLocal int
	err := s.db.QueryRowContext(ctx, `
SELECT tm.notifications_email_enabled,
	CASE WHEN lc.user_id IS NULL THEN 0 ELSE 1 END AS has_local_credentials
FROM tenant_memberships tm
LEFT JOIN local_credentials lc ON lc.user_id = tm.user_id
WHERE tm.tenant_id = ? AND tm.user_id = ?
LIMIT 1
`, tenantID, userID).Scan(&emailEnabled, &hasLocal)
	if err != nil {
		if err == sql.ErrNoRows {
			return UserNotificationSettings{}, sql.ErrNoRows
		}
		return UserNotificationSettings{}, fmt.Errorf("load email notification setting: %w", err)
	}
	settings.EmailEnabled = emailEnabled == 1
	settings.HasLocalCredentials = hasLocal == 1

	var (
		enabled          int
		configJSON       string
		secretCiphertext string
	)
	err = s.db.QueryRowContext(ctx, `
SELECT enabled, config_json, secret_ciphertext
FROM user_notification_channels
WHERE tenant_id = ? AND user_id = ? AND kind = 'matrix'
LIMIT 1
`, tenantID, userID).Scan(&enabled, &configJSON, &secretCiphertext)
	if err != nil {
		if err != sql.ErrNoRows {
			return UserNotificationSettings{}, fmt.Errorf("load matrix notification setting: %w", err)
		}
		return settings, nil
	}

	var parsed struct {
		HomeserverURL string `json:"homeserver_url"`
		RoomID        string `json:"room_id"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(configJSON)), &parsed); err == nil {
		settings.MatrixHomeserver = strings.TrimSpace(parsed.HomeserverURL)
		settings.MatrixRoomID = strings.TrimSpace(parsed.RoomID)
	}
	if strings.TrimSpace(secretCiphertext) != "" && len(s.secretKey) > 0 {
		if token, err := s.decryptSecret(secretCiphertext); err == nil {
			settings.MatrixAccessToken = token
		}
	}
	settings.MatrixEnabled = enabled == 1

	return settings, nil
}

func (s *ControlPlaneStore) SaveUserNotificationSettings(ctx context.Context, tenantID, userID int64, emailEnabled bool, matrixEnabled bool, homeserverURL, roomID, accessToken string) error {
	if tenantID <= 0 || userID <= 0 {
		return fmt.Errorf("tenant id and user id are required")
	}

	homeserverURL = strings.TrimSpace(strings.TrimRight(homeserverURL, "/"))
	roomID = strings.TrimSpace(roomID)
	accessToken = strings.TrimSpace(accessToken)
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin save user notification settings transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
UPDATE tenant_memberships
SET notifications_email_enabled = ?, updated_at = ?
WHERE tenant_id = ? AND user_id = ?
`, boolToInt(emailEnabled), now, tenantID, userID)
	if err != nil {
		return fmt.Errorf("update email notification opt-in: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update email notification rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	configJSONBytes, err := json.Marshal(map[string]string{
		"homeserver_url": homeserverURL,
		"room_id":        roomID,
	})
	if err != nil {
		return fmt.Errorf("marshal matrix config: %w", err)
	}

	var secretCiphertext string
	if accessToken != "" {
		if len(s.secretKey) == 0 {
			return fmt.Errorf("secret key is not configured")
		}
		sealed, err := encryptProviderSecret(s.secretKey, accessToken)
		if err != nil {
			return fmt.Errorf("encrypt matrix access token: %w", err)
		}
		secretCiphertext = sealed
	} else {
		err = tx.QueryRowContext(ctx, `
SELECT secret_ciphertext
FROM user_notification_channels
WHERE tenant_id = ? AND user_id = ? AND kind = 'matrix'
LIMIT 1
`, tenantID, userID).Scan(&secretCiphertext)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("load existing matrix access token: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO user_notification_channels (tenant_id, user_id, kind, enabled, config_json, secret_ciphertext, created_at, updated_at)
VALUES (?, ?, 'matrix', ?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, user_id, kind) DO UPDATE SET
	enabled = excluded.enabled,
	config_json = excluded.config_json,
	secret_ciphertext = excluded.secret_ciphertext,
	updated_at = excluded.updated_at
`, tenantID, userID, boolToInt(matrixEnabled), string(configJSONBytes), secretCiphertext, now, now); err != nil {
		return fmt.Errorf("upsert matrix notification channel: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit save user notification settings: %w", err)
	}
	return nil
}

func (s *ControlPlaneStore) DeleteUserNotificationChannel(ctx context.Context, tenantID, userID int64, kind string) error {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if tenantID <= 0 || userID <= 0 {
		return fmt.Errorf("tenant id and user id are required")
	}
	if kind == "" {
		return fmt.Errorf("notification kind is required")
	}

	result, err := s.db.ExecContext(ctx, `
DELETE FROM user_notification_channels
WHERE tenant_id = ? AND user_id = ? AND kind = ?
`, tenantID, userID, kind)
	if err != nil {
		return fmt.Errorf("delete user notification channel: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete user notification channel rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
