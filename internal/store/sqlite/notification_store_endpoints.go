package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type WebhookEndpoint struct {
	ID               int64
	Name             string
	Enabled          bool
	URL              string
	TimeoutSeconds   int
	SecretConfigured bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type webhookEndpointConfig struct {
	URL            string `json:"url"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

func (s *Store) EnsureSystemNotificationEndpoint(ctx context.Context, kind, name, configJSON string, enabled bool) (int64, error) {
	kind = strings.TrimSpace(kind)
	name = strings.TrimSpace(name)
	if kind == "" || name == "" {
		return 0, fmt.Errorf("notification endpoint kind and name are required")
	}
	if configJSON == "" {
		configJSON = "{}"
	}

	now := time.Now().UTC()

	var (
		id            int64
		currentEnable int
		currentConfig string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, enabled, config_json
FROM notification_endpoints
WHERE kind = ? AND name = ?
LIMIT 1
`, kind, name).Scan(&id, &currentEnable, &currentConfig)
	if err != nil {
		if err != sql.ErrNoRows {
			return 0, fmt.Errorf("lookup notification endpoint: %w", err)
		}

		result, insertErr := s.db.ExecContext(ctx, `
INSERT INTO notification_endpoints (kind, name, enabled, config_json, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
`, kind, name, boolToInt(enabled), configJSON, now, now)
		if insertErr != nil {
			return 0, fmt.Errorf("create notification endpoint: %w", insertErr)
		}
		id, insertErr = result.LastInsertId()
		if insertErr != nil {
			return 0, fmt.Errorf("read notification endpoint id: %w", insertErr)
		}
		return id, nil
	}

	// Callers ensure these endpoints on every notifier build (e.g. each remote
	// node report); skip the write when nothing changed.
	if currentEnable == boolToInt(enabled) && currentConfig == configJSON {
		return id, nil
	}

	_, err = s.db.ExecContext(ctx, `
UPDATE notification_endpoints
SET enabled = ?, config_json = ?, updated_at = ?
WHERE id = ?
`, boolToInt(enabled), configJSON, now, id)
	if err != nil {
		return 0, fmt.Errorf("update notification endpoint: %w", err)
	}

	return id, nil
}

func (s *Store) ListWebhookEndpoints(ctx context.Context) ([]WebhookEndpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, enabled, config_json, created_at, updated_at
FROM notification_endpoints
WHERE kind = 'webhook'
ORDER BY name COLLATE NOCASE ASC, id ASC
`)
	if err != nil {
		if isMalformedSQLiteError(err) {
			return []WebhookEndpoint{}, nil
		}
		return nil, fmt.Errorf("list webhook endpoints: %w", err)
	}
	defer rows.Close()

	items := make([]WebhookEndpoint, 0)
	for rows.Next() {
		var (
			item       WebhookEndpoint
			enabled    int
			configJSON string
			cfg        webhookEndpointConfig
		)
		if err := rows.Scan(&item.ID, &item.Name, &enabled, &configJSON, &item.CreatedAt, &item.UpdatedAt); err != nil {
			if isMalformedSQLiteError(err) {
				return []WebhookEndpoint{}, nil
			}
			return nil, fmt.Errorf("scan webhook endpoint: %w", err)
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(configJSON)), &cfg); err != nil {
			cfg = webhookEndpointConfig{}
		}
		item.Enabled = enabled == 1
		item.URL = strings.TrimSpace(cfg.URL)
		item.TimeoutSeconds = cfg.TimeoutSeconds
		if item.TimeoutSeconds <= 0 {
			item.TimeoutSeconds = 10
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		if isMalformedSQLiteError(err) {
			return []WebhookEndpoint{}, nil
		}
		return nil, fmt.Errorf("iterate webhook endpoints: %w", err)
	}
	return items, nil
}

func (s *Store) UpsertWebhookEndpoint(ctx context.Context, endpoint WebhookEndpoint) (int64, error) {
	endpoint.Name = strings.TrimSpace(endpoint.Name)
	endpoint.URL = strings.TrimSpace(endpoint.URL)
	if endpoint.Name == "" {
		return 0, fmt.Errorf("webhook endpoint name is required")
	}
	if endpoint.URL == "" {
		return 0, fmt.Errorf("webhook endpoint url is required")
	}
	if endpoint.TimeoutSeconds <= 0 {
		endpoint.TimeoutSeconds = 10
	}
	configJSONBytes, err := json.Marshal(webhookEndpointConfig{
		URL:            endpoint.URL,
		TimeoutSeconds: endpoint.TimeoutSeconds,
	})
	if err != nil {
		return 0, fmt.Errorf("marshal webhook endpoint config: %w", err)
	}

	now := time.Now().UTC()
	if endpoint.ID > 0 {
		result, err := s.db.ExecContext(ctx, `
UPDATE notification_endpoints
SET name = ?, enabled = ?, config_json = ?, updated_at = ?
WHERE id = ? AND kind = 'webhook'
`, endpoint.Name, boolToInt(endpoint.Enabled), string(configJSONBytes), now, endpoint.ID)
		if err != nil {
			return 0, fmt.Errorf("update webhook endpoint: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("update webhook endpoint rows affected: %w", err)
		}
		if affected == 0 {
			return 0, sql.ErrNoRows
		}
		return endpoint.ID, nil
	}

	result, err := s.db.ExecContext(ctx, `
INSERT INTO notification_endpoints (kind, name, enabled, config_json, created_at, updated_at)
VALUES ('webhook', ?, ?, ?, ?, ?)
`, endpoint.Name, boolToInt(endpoint.Enabled), string(configJSONBytes), now, now)
	if err != nil {
		return 0, fmt.Errorf("create webhook endpoint: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read webhook endpoint id: %w", err)
	}
	return id, nil
}

func (s *Store) DeleteWebhookEndpoint(ctx context.Context, endpointID int64) error {
	if endpointID <= 0 {
		return fmt.Errorf("endpoint id is required")
	}
	result, err := s.db.ExecContext(ctx, `
DELETE FROM notification_endpoints
WHERE id = ? AND kind = 'webhook'
`, endpointID)
	if err != nil {
		return fmt.Errorf("delete webhook endpoint: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete webhook endpoint rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
