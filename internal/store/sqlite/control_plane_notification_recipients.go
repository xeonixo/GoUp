package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type MatrixNotificationTarget struct {
	UserID            int64
	HomeserverURL     string
	RoomID            string
	AccessToken       string
	PreferredLanguage string
}

type NotificationRecipient struct {
	Email             string
	PreferredLanguage string
}

func (s *ControlPlaneStore) ListTenantNotificationEmails(ctx context.Context, tenantID int64) ([]string, error) {
	if tenantID <= 0 {
		return nil, fmt.Errorf("tenant id is required")
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT trim(u.email)
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
JOIN tenants t ON t.id = tm.tenant_id
WHERE tm.blocked = 0 AND tm.tenant_id = ?
	AND t.active = 1
	AND tm.notifications_email_enabled = 1
	AND trim(u.email) <> ''
ORDER BY lower(trim(u.email)) ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query tenant notification emails: %w", err)
	}
	defer rows.Close()

	items := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan tenant notification email: %w", err)
		}
		value = strings.TrimSpace(value)
		if value != "" {
			items = append(items, value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant notification emails: %w", err)
	}

	return items, nil
}

func (s *ControlPlaneStore) ListTenantNotificationRecipients(ctx context.Context, tenantID int64) ([]NotificationRecipient, error) {
	if tenantID <= 0 {
		return nil, fmt.Errorf("tenant id is required")
	}

	return s.listTenantNotificationRecipients(ctx, tenantID, false)
}

func (s *ControlPlaneStore) ListTenantAdminNotificationRecipients(ctx context.Context, tenantID int64) ([]NotificationRecipient, error) {
	if tenantID <= 0 {
		return nil, fmt.Errorf("tenant id is required")
	}

	return s.listTenantNotificationRecipients(ctx, tenantID, true)
}

func (s *ControlPlaneStore) listTenantNotificationRecipients(ctx context.Context, tenantID int64, adminOnly bool) ([]NotificationRecipient, error) {
	roleFilter := ""
	if adminOnly {
		roleFilter = " AND lower(trim(tm.role)) = 'admin'"
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT trim(u.email), COALESCE(NULLIF(trim(u.preferred_language), ''), 'en')
FROM tenant_memberships tm
JOIN users u ON u.id = tm.user_id
JOIN tenants t ON t.id = tm.tenant_id
WHERE tm.blocked = 0 AND tm.tenant_id = ?
	AND t.active = 1
	AND tm.notifications_email_enabled = 1
	AND trim(u.email) <> ''
`+roleFilter+`
ORDER BY lower(trim(u.email)) ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query tenant notification recipients: %w", err)
	}
	defer rows.Close()

	items := make([]NotificationRecipient, 0)
	for rows.Next() {
		var item NotificationRecipient
		if err := rows.Scan(&item.Email, &item.PreferredLanguage); err != nil {
			return nil, fmt.Errorf("scan tenant notification recipient: %w", err)
		}
		item.Email = strings.TrimSpace(item.Email)
		if item.Email == "" {
			continue
		}
		item.PreferredLanguage = normalizePreferredLanguage(item.PreferredLanguage)
		if item.PreferredLanguage == "" {
			item.PreferredLanguage = "en"
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant notification recipients: %w", err)
	}

	return items, nil
}

func (s *ControlPlaneStore) ListTenantMatrixNotificationTargets(ctx context.Context, tenantID int64) ([]MatrixNotificationTarget, error) {
	if tenantID <= 0 {
		return nil, fmt.Errorf("tenant id is required")
	}

	return s.listTenantMatrixNotificationTargets(ctx, tenantID, false)
}

func (s *ControlPlaneStore) ListTenantAdminMatrixNotificationTargets(ctx context.Context, tenantID int64) ([]MatrixNotificationTarget, error) {
	if tenantID <= 0 {
		return nil, fmt.Errorf("tenant id is required")
	}

	return s.listTenantMatrixNotificationTargets(ctx, tenantID, true)
}

func (s *ControlPlaneStore) listTenantMatrixNotificationTargets(ctx context.Context, tenantID int64, adminOnly bool) ([]MatrixNotificationTarget, error) {
	roleFilter := ""
	if adminOnly {
		roleFilter = " AND lower(trim(tm.role)) = 'admin'"
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT unc.user_id, unc.config_json, unc.secret_ciphertext, COALESCE(NULLIF(trim(u.preferred_language), ''), 'en')
FROM user_notification_channels unc
JOIN tenant_memberships tm ON tm.tenant_id = unc.tenant_id AND tm.user_id = unc.user_id
JOIN tenants t ON t.id = tm.tenant_id
JOIN users u ON u.id = unc.user_id
WHERE unc.tenant_id = ?
	AND unc.kind = 'matrix'
	AND unc.enabled = 1
	AND t.active = 1
	AND tm.blocked = 0
`+roleFilter+`
ORDER BY unc.user_id ASC
`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query tenant matrix notification targets: %w", err)
	}
	defer rows.Close()

	items := make([]MatrixNotificationTarget, 0)
	for rows.Next() {
		var (
			userID            int64
			configJSON        string
			secretCiphertext  string
			preferredLanguage string
		)
		if err := rows.Scan(&userID, &configJSON, &secretCiphertext, &preferredLanguage); err != nil {
			return nil, fmt.Errorf("scan matrix notification target: %w", err)
		}
		if strings.TrimSpace(secretCiphertext) == "" || len(s.secretKey) == 0 {
			continue
		}
		token, err := s.decryptSecret(secretCiphertext)
		if err != nil {
			continue
		}
		var cfg struct {
			HomeserverURL string `json:"homeserver_url"`
			RoomID        string `json:"room_id"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(configJSON)), &cfg); err != nil {
			continue
		}
		homeserverURL := strings.TrimSpace(cfg.HomeserverURL)
		roomID := strings.TrimSpace(cfg.RoomID)
		if homeserverURL == "" || roomID == "" || strings.TrimSpace(token) == "" {
			continue
		}
		items = append(items, MatrixNotificationTarget{
			UserID:            userID,
			HomeserverURL:     homeserverURL,
			RoomID:            roomID,
			AccessToken:       token,
			PreferredLanguage: preferredLanguage,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate matrix notification targets: %w", err)
	}

	return items, nil
}
