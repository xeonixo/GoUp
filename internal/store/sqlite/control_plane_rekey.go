package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ReencryptAllSecrets decrypts every stored ciphertext with the current key
// set (primary + fallbacks) and re-encrypts it with the primary key. Empty
// ciphertext columns are skipped. Returns the number of rows/columns updated.
func (s *ControlPlaneStore) ReencryptAllSecrets(ctx context.Context) (int, error) {
	return s.reencryptAllSecrets(ctx, false)
}

// CountDecryptableSecrets counts non-empty ciphertext values that decrypt with
// the current key set without writing updates (CLI --dry-run).
func (s *ControlPlaneStore) CountDecryptableSecrets(ctx context.Context) (int, error) {
	return s.reencryptAllSecrets(ctx, true)
}

func (s *ControlPlaneStore) reencryptAllSecrets(ctx context.Context, dryRun bool) (int, error) {
	if len(s.secretKey) == 0 {
		return 0, fmt.Errorf("secret key is not configured")
	}

	updated := 0
	now := time.Now().UTC()

	type job struct {
		label string
		run   func() (int, error)
	}
	jobs := []job{
		{"auth_provider_secrets", func() (int, error) {
			return s.reencryptKeyedCiphertexts(ctx, dryRun, `
SELECT tenant_id, provider_key, secret_ciphertext
FROM auth_provider_secrets
WHERE TRIM(secret_ciphertext) <> ''
`, 2, func(keys []any, sealed string) (string, []any) {
				return `UPDATE auth_provider_secrets SET secret_ciphertext = ?, updated_at = ? WHERE tenant_id = ? AND provider_key = ?`,
					[]any{sealed, now, keys[0], keys[1]}
			})
		}},
		{"global_smtp_settings", func() (int, error) {
			return s.reencryptIDCiphertexts(ctx, dryRun, `
SELECT id, password_ciphertext FROM global_smtp_settings WHERE TRIM(password_ciphertext) <> ''
`, `UPDATE global_smtp_settings SET password_ciphertext = ?, updated_at = ? WHERE id = ?`, now)
		}},
		{"control_plane_admins", func() (int, error) {
			return s.reencryptIDCiphertexts(ctx, dryRun, `
SELECT id, totp_secret_ciphertext FROM control_plane_admins WHERE TRIM(totp_secret_ciphertext) <> ''
`, `UPDATE control_plane_admins SET totp_secret_ciphertext = ?, updated_at = ? WHERE id = ?`, now)
		}},
		{"tenant_notification_endpoint_secrets", func() (int, error) {
			n, err := s.reencryptKeyedCiphertexts(ctx, dryRun, `
SELECT tenant_id, endpoint_id, kind, secret_ciphertext
FROM tenant_notification_endpoint_secrets
WHERE TRIM(secret_ciphertext) <> ''
`, 3, func(keys []any, sealed string) (string, []any) {
				return `UPDATE tenant_notification_endpoint_secrets SET secret_ciphertext = ?, updated_at = ? WHERE tenant_id = ? AND endpoint_id = ? AND kind = ?`,
					[]any{sealed, now, keys[0], keys[1], keys[2]}
			})
			if err != nil {
				return n, err
			}
			prev, prevErr := s.reencryptKeyedCiphertexts(ctx, dryRun, `
SELECT tenant_id, endpoint_id, kind, previous_secret_ciphertext
FROM tenant_notification_endpoint_secrets
WHERE TRIM(previous_secret_ciphertext) <> ''
`, 3, func(keys []any, sealed string) (string, []any) {
				return `UPDATE tenant_notification_endpoint_secrets SET previous_secret_ciphertext = ?, updated_at = ? WHERE tenant_id = ? AND endpoint_id = ? AND kind = ?`,
					[]any{sealed, now, keys[0], keys[1], keys[2]}
			})
			return n + prev, prevErr
		}},
		{"user_notification_channels", func() (int, error) {
			return s.reencryptKeyedCiphertexts(ctx, dryRun, `
SELECT tenant_id, user_id, kind, secret_ciphertext
FROM user_notification_channels
WHERE TRIM(secret_ciphertext) <> ''
`, 3, func(keys []any, sealed string) (string, []any) {
				return `UPDATE user_notification_channels SET secret_ciphertext = ?, updated_at = ? WHERE tenant_id = ? AND user_id = ? AND kind = ?`,
					[]any{sealed, now, keys[0], keys[1], keys[2]}
			})
		}},
		{"remote_nodes", func() (int, error) {
			return s.reencryptRemoteNodeSecrets(ctx, dryRun, now)
		}},
		{"vapid_private", func() (int, error) {
			return s.reencryptVAPIDPrivate(ctx, dryRun)
		}},
		{"push_subscriptions", func() (int, error) {
			return s.reencryptPushSubscriptionSecrets(ctx, dryRun)
		}},
	}

	for _, j := range jobs {
		n, err := j.run()
		if err != nil {
			return updated, fmt.Errorf("%s: %w", j.label, err)
		}
		updated += n
	}
	return updated, nil
}

type secretRow struct {
	keys       []any
	ciphertext string
}

func (s *ControlPlaneStore) reencryptKeyedCiphertexts(
	ctx context.Context,
	dryRun bool,
	selectSQL string,
	keyCount int,
	update func(keys []any, sealed string) (string, []any),
) (int, error) {
	rows, err := s.db.QueryContext(ctx, selectSQL)
	if err != nil {
		return 0, fmt.Errorf("query: %w", err)
	}
	var pending []secretRow
	for rows.Next() {
		raw := make([]any, keyCount+1)
		ptrs := make([]any, len(raw))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan: %w", err)
		}
		ciphertext := strings.TrimSpace(fmt.Sprint(raw[keyCount]))
		if ciphertext == "" || ciphertext == "<nil>" {
			continue
		}
		keys := make([]any, keyCount)
		copy(keys, raw[:keyCount])
		pending = append(pending, secretRow{keys: keys, ciphertext: ciphertext})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}

	updated := 0
	for _, row := range pending {
		plaintext, err := s.decryptSecret(row.ciphertext)
		if err != nil {
			if dryRun {
				continue
			}
			return updated, fmt.Errorf("decrypt: %w", err)
		}
		if dryRun {
			updated++
			continue
		}
		sealed, err := encryptProviderSecret(s.secretKey, plaintext)
		if err != nil {
			return updated, fmt.Errorf("encrypt: %w", err)
		}
		query, args := update(row.keys, sealed)
		if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
			return updated, fmt.Errorf("update: %w", err)
		}
		updated++
	}
	return updated, nil
}

func (s *ControlPlaneStore) reencryptIDCiphertexts(ctx context.Context, dryRun bool, selectSQL, updateSQL string, now time.Time) (int, error) {
	rows, err := s.db.QueryContext(ctx, selectSQL)
	if err != nil {
		return 0, fmt.Errorf("query: %w", err)
	}
	type item struct {
		id         int64
		ciphertext string
	}
	var pending []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.ciphertext); err != nil {
			rows.Close()
			return 0, err
		}
		it.ciphertext = strings.TrimSpace(it.ciphertext)
		if it.ciphertext == "" {
			continue
		}
		pending = append(pending, it)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}

	updated := 0
	for _, it := range pending {
		plaintext, err := s.decryptSecret(it.ciphertext)
		if err != nil {
			if dryRun {
				continue
			}
			return updated, fmt.Errorf("decrypt id=%d: %w", it.id, err)
		}
		if dryRun {
			updated++
			continue
		}
		sealed, err := encryptProviderSecret(s.secretKey, plaintext)
		if err != nil {
			return updated, err
		}
		if _, err := s.db.ExecContext(ctx, updateSQL, sealed, now, it.id); err != nil {
			return updated, fmt.Errorf("update id=%d: %w", it.id, err)
		}
		updated++
	}
	return updated, nil
}

func (s *ControlPlaneStore) reencryptRemoteNodeSecrets(ctx context.Context, dryRun bool, now time.Time) (int, error) {
	// New remote-node tokens/bootstrap keys are fingerprint-only; ciphertext columns are
	// empty. Rekey still re-encrypts any legacy non-empty ciphertext rows during transition.
	rows, err := s.db.QueryContext(ctx, `
SELECT id, bootstrap_key_ciphertext, access_token_ciphertext, previous_access_token_ciphertext
FROM remote_nodes
`)
	if err != nil {
		return 0, fmt.Errorf("query: %w", err)
	}
	type colUpdate struct {
		id     int64
		column string
		value  string
	}
	var pending []colUpdate
	for rows.Next() {
		var id int64
		var bootstrap, access, previous string
		if err := rows.Scan(&id, &bootstrap, &access, &previous); err != nil {
			rows.Close()
			return 0, err
		}
		for _, c := range []struct {
			column string
			value  string
		}{
			{"bootstrap_key_ciphertext", strings.TrimSpace(bootstrap)},
			{"access_token_ciphertext", strings.TrimSpace(access)},
			{"previous_access_token_ciphertext", strings.TrimSpace(previous)},
		} {
			if c.value == "" {
				continue
			}
			pending = append(pending, colUpdate{id: id, column: c.column, value: c.value})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}

	updated := 0
	for _, it := range pending {
		plaintext, err := s.decryptSecret(it.value)
		if err != nil {
			if dryRun {
				continue
			}
			return updated, fmt.Errorf("decrypt remote node %d %s: %w", it.id, it.column, err)
		}
		if dryRun {
			updated++
			continue
		}
		sealed, err := encryptProviderSecret(s.secretKey, plaintext)
		if err != nil {
			return updated, err
		}
		query := fmt.Sprintf(`UPDATE remote_nodes SET %s = ?, updated_at = ? WHERE id = ?`, it.column)
		if _, err := s.db.ExecContext(ctx, query, sealed, now, it.id); err != nil {
			return updated, fmt.Errorf("update remote node %d %s: %w", it.id, it.column, err)
		}
		updated++
	}
	return updated, nil
}

func (s *ControlPlaneStore) reencryptVAPIDPrivate(ctx context.Context, dryRun bool) (int, error) {
	var ciphertext string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = ?`, vapidPrivateSettingKey).Scan(&ciphertext)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("load: %w", err)
	}
	ciphertext = strings.TrimSpace(ciphertext)
	if ciphertext == "" {
		return 0, nil
	}
	plaintext, err := s.decryptSecret(ciphertext)
	if err != nil {
		if dryRun {
			return 0, nil
		}
		return 0, fmt.Errorf("decrypt: %w", err)
	}
	if dryRun {
		return 1, nil
	}
	sealed, err := encryptProviderSecret(s.secretKey, plaintext)
	if err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE system_settings SET value = ? WHERE key = ?`, sealed, vapidPrivateSettingKey); err != nil {
		return 0, fmt.Errorf("update: %w", err)
	}
	return 1, nil
}

func (s *ControlPlaneStore) reencryptPushSubscriptionSecrets(ctx context.Context, dryRun bool) (int, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, p256dh_ciphertext, auth_ciphertext
FROM push_subscriptions
`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return 0, nil
		}
		return 0, fmt.Errorf("query: %w", err)
	}
	type colUpdate struct {
		id     int64
		column string
		value  string
	}
	var pending []colUpdate
	for rows.Next() {
		var id int64
		var p256dh, auth string
		if err := rows.Scan(&id, &p256dh, &auth); err != nil {
			rows.Close()
			return 0, err
		}
		for _, c := range []struct {
			column string
			value  string
		}{
			{"p256dh_ciphertext", strings.TrimSpace(p256dh)},
			{"auth_ciphertext", strings.TrimSpace(auth)},
		} {
			if c.value == "" {
				continue
			}
			pending = append(pending, colUpdate{id: id, column: c.column, value: c.value})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}

	updated := 0
	for _, it := range pending {
		plaintext, err := s.decryptSecret(it.value)
		if err != nil {
			if dryRun {
				continue
			}
			return updated, fmt.Errorf("decrypt push %d %s: %w", it.id, it.column, err)
		}
		if dryRun {
			updated++
			continue
		}
		sealed, err := encryptProviderSecret(s.secretKey, plaintext)
		if err != nil {
			return updated, err
		}
		query := fmt.Sprintf(`UPDATE push_subscriptions SET %s = ? WHERE id = ?`, it.column)
		if _, err := s.db.ExecContext(ctx, query, sealed, it.id); err != nil {
			return updated, fmt.Errorf("update push %d %s: %w", it.id, it.column, err)
		}
		updated++
	}
	return updated, nil
}
