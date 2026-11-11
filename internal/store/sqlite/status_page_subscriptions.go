package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	statusPageSubscriptionEmailMaxRunes = 254
	statusPageConfirmTokenTTL           = 48 * time.Hour
	statusPageSubscriptionTokenPrefix   = "goup_ss_"
)

// StatusPageSubscription is a visitor email subscription to public status-page incidents.
type StatusPageSubscription struct {
	ID                   int64
	Email                string
	Language             string
	ConfirmTokenHash     string
	UnsubscribeTokenHash string
	ConfirmedAt          *time.Time
	ConfirmSentAt        *time.Time
	CreatedAt            time.Time
	MonitorIDs           []int64
}

func (s *Store) ensureStatusPageSubscriptionTables(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS status_page_subscriptions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT NOT NULL,
	email_normalized TEXT NOT NULL UNIQUE,
	language TEXT NOT NULL DEFAULT 'en',
	confirm_token_hash TEXT NOT NULL DEFAULT '',
	unsubscribe_token_hash TEXT NOT NULL DEFAULT '',
	confirmed_at DATETIME,
	confirm_sent_at DATETIME,
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS status_page_subscription_monitors (
	subscription_id INTEGER NOT NULL,
	monitor_id INTEGER NOT NULL,
	PRIMARY KEY (subscription_id, monitor_id),
	FOREIGN KEY(subscription_id) REFERENCES status_page_subscriptions(id) ON DELETE CASCADE,
	FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_status_page_subs_confirm
	ON status_page_subscriptions(confirm_token_hash) WHERE confirm_token_hash <> '';
CREATE INDEX IF NOT EXISTS idx_status_page_subs_unsub
	ON status_page_subscriptions(unsubscribe_token_hash) WHERE unsubscribe_token_hash <> '';
`); err != nil {
		return fmt.Errorf("create status page subscription tables: %w", err)
	}
	return nil
}

// GenerateStatusPageSubscriptionToken returns a fresh plain token and its SHA-256 hex hash.
func GenerateStatusPageSubscriptionToken() (plain, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate status page subscription token: %w", err)
	}
	plain = statusPageSubscriptionTokenPrefix + hex.EncodeToString(raw)
	return plain, hashStatusPageSubscriptionToken(plain), nil
}

func hashStatusPageSubscriptionToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// StatusPageSubscriptionTokenMatches reports whether the plain token matches the stored hash.
func StatusPageSubscriptionTokenMatches(plain, hash string) bool {
	plain = strings.TrimSpace(plain)
	hash = strings.TrimSpace(hash)
	if plain == "" || hash == "" {
		return false
	}
	got := hashStatusPageSubscriptionToken(plain)
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1
}

func normalizeStatusPageSubscriptionEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validStatusPageSubscriptionEmail(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" || len([]rune(email)) > statusPageSubscriptionEmailMaxRunes {
		return false
	}
	if strings.ContainsAny(email, " \t\r\n\x00") {
		return false
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at >= len(email)-1 {
		return false
	}
	if strings.Contains(email[at+1:], "@") {
		return false
	}
	return strings.Contains(email[at+1:], ".")
}

func normalizeStatusPageSubscriptionLanguage(language string) string {
	language = strings.ToLower(strings.TrimSpace(language))
	if strings.HasPrefix(language, "de") {
		return "de"
	}
	return "en"
}

// UpsertPendingStatusPageSubscription creates or refreshes an unconfirmed subscription and
// returns the plain confirm token that must be emailed. Monitor IDs that are not on the
// status page are ignored.
func (s *Store) UpsertPendingStatusPageSubscription(ctx context.Context, email, language string, monitorIDs []int64) (plainConfirm string, err error) {
	email = truncateRunes(strings.TrimSpace(email), statusPageSubscriptionEmailMaxRunes)
	if !validStatusPageSubscriptionEmail(email) {
		return "", fmt.Errorf("invalid email")
	}
	normalized := normalizeStatusPageSubscriptionEmail(email)
	language = normalizeStatusPageSubscriptionLanguage(language)
	plain, hash, err := GenerateStatusPageSubscriptionToken()
	if err != nil {
		return "", err
	}
	monitorIDs, err = s.filterStatusPageMonitorIDs(ctx, monitorIDs)
	if err != nil {
		return "", err
	}
	if len(monitorIDs) == 0 {
		return "", fmt.Errorf("no status page monitors selected")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin status page subscription upsert: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	var existingID int64
	var confirmedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
SELECT id, confirmed_at FROM status_page_subscriptions WHERE email_normalized = ?
`, normalized).Scan(&existingID, &confirmedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, execErr := tx.ExecContext(ctx, `
INSERT INTO status_page_subscriptions (
	email, email_normalized, language, confirm_token_hash, unsubscribe_token_hash,
	confirmed_at, confirm_sent_at, created_at
) VALUES (?, ?, ?, ?, '', NULL, ?, ?)
`, email, normalized, language, hash, now, now)
		if execErr != nil {
			return "", fmt.Errorf("insert status page subscription: %w", execErr)
		}
		existingID, err = res.LastInsertId()
		if err != nil {
			return "", fmt.Errorf("status page subscription id: %w", err)
		}
	case err != nil:
		return "", fmt.Errorf("lookup status page subscription: %w", err)
	default:
		if confirmedAt.Valid {
			// Already confirmed: rotate confirm token is unnecessary; update monitors + language.
			if _, err := tx.ExecContext(ctx, `
UPDATE status_page_subscriptions SET email = ?, language = ?, confirm_token_hash = '', confirm_sent_at = NULL
WHERE id = ?
`, email, language, existingID); err != nil {
				return "", fmt.Errorf("update confirmed status page subscription: %w", err)
			}
			if err := replaceStatusPageSubscriptionMonitorsTx(ctx, tx, existingID, monitorIDs); err != nil {
				return "", err
			}
			if err := tx.Commit(); err != nil {
				return "", err
			}
			return "", nil // empty confirm token signals already confirmed
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE status_page_subscriptions
SET email = ?, language = ?, confirm_token_hash = ?, confirm_sent_at = ?, confirmed_at = NULL
WHERE id = ?
`, email, language, hash, now, existingID); err != nil {
			return "", fmt.Errorf("refresh pending status page subscription: %w", err)
		}
	}
	if err := replaceStatusPageSubscriptionMonitorsTx(ctx, tx, existingID, monitorIDs); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return plain, nil
}

func replaceStatusPageSubscriptionMonitorsTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, monitorIDs []int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM status_page_subscription_monitors WHERE subscription_id = ?`, subscriptionID); err != nil {
		return fmt.Errorf("clear status page subscription monitors: %w", err)
	}
	for _, monitorID := range monitorIDs {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO status_page_subscription_monitors (subscription_id, monitor_id)
VALUES (?, ?)
`, subscriptionID, monitorID); err != nil {
			return fmt.Errorf("save status page subscription monitor: %w", err)
		}
	}
	return nil
}

func (s *Store) filterStatusPageMonitorIDs(ctx context.Context, monitorIDs []int64) ([]int64, error) {
	selected, err := s.ListStatusPageMonitors(ctx)
	if err != nil {
		return nil, err
	}
	allowed := make(map[int64]struct{}, len(selected))
	for _, item := range selected {
		allowed[item.MonitorID] = struct{}{}
	}
	if len(monitorIDs) == 0 {
		out := make([]int64, 0, len(selected))
		for _, item := range selected {
			out = append(out, item.MonitorID)
		}
		return out, nil
	}
	seen := make(map[int64]struct{}, len(monitorIDs))
	out := make([]int64, 0, len(monitorIDs))
	for _, id := range monitorIDs {
		if _, ok := allowed[id]; !ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// ConfirmStatusPageSubscription marks a pending subscription confirmed using the plain confirm token.
// It returns the plain unsubscribe token (newly generated) on success.
func (s *Store) ConfirmStatusPageSubscription(ctx context.Context, plainConfirm string) (plainUnsub string, err error) {
	plainConfirm = strings.TrimSpace(plainConfirm)
	if plainConfirm == "" {
		return "", fmt.Errorf("missing confirm token")
	}
	hash := hashStatusPageSubscriptionToken(plainConfirm)
	var (
		id          int64
		confirmHash string
		sentAt      sql.NullTime
		confirmedAt sql.NullTime
	)
	err = s.db.QueryRowContext(ctx, `
SELECT id, confirm_token_hash, confirm_sent_at, confirmed_at
FROM status_page_subscriptions WHERE confirm_token_hash = ?
`, hash).Scan(&id, &confirmHash, &sentAt, &confirmedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("invalid confirm token")
		}
		return "", fmt.Errorf("lookup confirm token: %w", err)
	}
	if !StatusPageSubscriptionTokenMatches(plainConfirm, confirmHash) {
		return "", fmt.Errorf("invalid confirm token")
	}
	if confirmedAt.Valid {
		return "", fmt.Errorf("already confirmed")
	}
	if !sentAt.Valid || time.Since(sentAt.Time) > statusPageConfirmTokenTTL {
		return "", fmt.Errorf("confirm token expired")
	}

	// Store the opaque unsubscribe token itself (high entropy) so incident emails can include it.
	plainUnsub, _, genErr := GenerateStatusPageSubscriptionToken()
	if genErr != nil {
		return "", genErr
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
UPDATE status_page_subscriptions
SET confirmed_at = ?, confirm_token_hash = '', confirm_sent_at = NULL, unsubscribe_token_hash = ?
WHERE id = ?
`, now, plainUnsub, id); err != nil {
		return "", fmt.Errorf("confirm status page subscription: %w", err)
	}
	return plainUnsub, nil
}

// UnsubscribeStatusPageSubscription deletes a confirmed (or pending) subscription by unsubscribe token.
func (s *Store) UnsubscribeStatusPageSubscription(ctx context.Context, plainUnsub string) error {
	plainUnsub = strings.TrimSpace(plainUnsub)
	if plainUnsub == "" {
		return fmt.Errorf("missing unsubscribe token")
	}
	var stored string
	var id int64
	err := s.db.QueryRowContext(ctx, `
SELECT id, unsubscribe_token_hash FROM status_page_subscriptions WHERE unsubscribe_token_hash = ?
`, plainUnsub).Scan(&id, &stored)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("invalid unsubscribe token")
		}
		return fmt.Errorf("lookup unsubscribe token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(plainUnsub), []byte(stored)) != 1 {
		return fmt.Errorf("invalid unsubscribe token")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM status_page_subscriptions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete status page subscription: %w", err)
	}
	return nil
}

// ListConfirmedStatusPageSubscribersForMonitor returns confirmed subscribers watching a status-page monitor.
func (s *Store) ListConfirmedStatusPageSubscribersForMonitor(ctx context.Context, monitorID int64) ([]StatusPageSubscription, error) {
	if monitorID <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT s.id, s.email, s.language, s.unsubscribe_token_hash, s.confirmed_at, s.created_at
FROM status_page_subscriptions s
JOIN status_page_subscription_monitors sm ON sm.subscription_id = s.id
JOIN status_page_monitors sp ON sp.monitor_id = sm.monitor_id
WHERE sm.monitor_id = ? AND s.confirmed_at IS NOT NULL
ORDER BY s.id ASC
`, monitorID)
	if err != nil {
		return nil, fmt.Errorf("list status page subscribers: %w", err)
	}
	defer rows.Close()
	items := make([]StatusPageSubscription, 0)
	for rows.Next() {
		var (
			item        StatusPageSubscription
			confirmedAt sql.NullTime
		)
		if err := rows.Scan(&item.ID, &item.Email, &item.Language, &item.UnsubscribeTokenHash, &confirmedAt, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan status page subscriber: %w", err)
		}
		item.ConfirmedAt = nullableTime(confirmedAt)
		item.Language = normalizeStatusPageSubscriptionLanguage(item.Language)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate status page subscribers: %w", err)
	}
	return items, nil
}

// StatusPageDisplayNameForMonitor returns the public display name for a status-page monitor.
func (s *Store) StatusPageDisplayNameForMonitor(ctx context.Context, monitorID int64) (string, bool, error) {
	var name string
	err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(NULLIF(TRIM(sp.display_name), ''), m.name)
FROM status_page_monitors sp
JOIN monitors m ON m.id = sp.monitor_id
WHERE sp.monitor_id = ?
`, monitorID).Scan(&name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("load status page display name: %w", err)
	}
	return strings.TrimSpace(name), true, nil
}
