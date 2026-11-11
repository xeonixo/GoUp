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
	statusPageTitleMaxRunes        = 120
	statusPageDescriptionMaxRunes  = 500
	statusPageDisplayNameMaxRunes  = 120
	statusPageBrandColorMaxRunes   = 32
	statusPageLogoRefMaxRunes      = 200
	statusPageAccessModePublic     = "public"
	statusPageAccessModeToken      = "token"
	statusPageAccessTokenPrefix    = "goup_"
	statusPageIncidentDefaultLimit = 20
	statusPageAnnounceHoursDefault = 24
	statusPageAnnounceHoursMax     = 720 // 30 days
)

// StatusPageSettings is the per-tenant configuration of the public status page.
type StatusPageSettings struct {
	Enabled         bool
	Title           string
	Description     string
	LogoRef         string
	BrandColor      string
	HideGoUpFooter  bool
	AccessMode      string
	AccessTokenHash string
	NoIndex         bool
	// AnnounceHours is how far ahead upcoming maintenance is shown on the public page.
	AnnounceHours int
	UpdatedAt     time.Time
}

// NormalizeAnnounceHours returns a sane announce lead time (default 24, max 720).
func NormalizeAnnounceHours(hours int) int {
	if hours <= 0 {
		return statusPageAnnounceHoursDefault
	}
	if hours > statusPageAnnounceHoursMax {
		return statusPageAnnounceHoursMax
	}
	return hours
}

// StatusPageMonitor selects one monitor for the public status page together with the
// name that is shown publicly (monitor names, targets and hosts are never exposed).
type StatusPageMonitor struct {
	MonitorID   int64
	DisplayName string
	SortOrder   int
}

// StatusPageIncident is a public incident row without cause or target details.
type StatusPageIncident struct {
	MonitorID   int64
	DisplayName string
	StartedAt   time.Time
	ResolvedAt  *time.Time
}

func (s *Store) ensureStatusPageTables(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS status_page_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	enabled INTEGER NOT NULL DEFAULT 0,
	title TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS status_page_monitors (
	monitor_id INTEGER PRIMARY KEY,
	display_name TEXT NOT NULL DEFAULT '',
	sort_order INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);
`); err != nil {
		return fmt.Errorf("create status page tables: %w", err)
	}
	for _, col := range []struct{ name, def string }{
		{"logo_ref", "TEXT NOT NULL DEFAULT ''"},
		{"brand_color", "TEXT NOT NULL DEFAULT ''"},
		{"hide_goup_footer", "INTEGER NOT NULL DEFAULT 0"},
		{"access_mode", "TEXT NOT NULL DEFAULT 'public'"},
		{"access_token_hash", "TEXT NOT NULL DEFAULT ''"},
		{"noindex", "INTEGER NOT NULL DEFAULT 0"},
		{"announce_hours", "INTEGER NOT NULL DEFAULT 24"},
	} {
		if _, err := s.ensureColumn(ctx, "status_page_settings", col.name, col.def); err != nil {
			return err
		}
	}
	return s.ensureStatusPageSubscriptionTables(ctx)
}

func normalizeStatusPageAccessMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), statusPageAccessModeToken) {
		return statusPageAccessModeToken
	}
	return statusPageAccessModePublic
}

func normalizeStatusPageBrandColor(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "#") {
		value = "#" + value
	}
	value = strings.ToLower(value)
	hexPart := value[1:]
	if len(hexPart) != 3 && len(hexPart) != 6 {
		return ""
	}
	for _, r := range hexPart {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return truncateRunes(value, statusPageBrandColorMaxRunes)
}

func hashStatusPageAccessToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// GenerateStatusPageAccessToken returns a fresh plain token and its SHA-256 hex hash.
func GenerateStatusPageAccessToken() (plain, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate status page access token: %w", err)
	}
	plain = statusPageAccessTokenPrefix + hex.EncodeToString(raw)
	return plain, hashStatusPageAccessToken(plain), nil
}

// StatusPageAccessTokenMatches reports whether the bearer token matches the stored hash.
func StatusPageAccessTokenMatches(plain, hash string) bool {
	plain = strings.TrimSpace(plain)
	hash = strings.TrimSpace(hash)
	if plain == "" || hash == "" {
		return false
	}
	got := hashStatusPageAccessToken(plain)
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1
}

// GetStatusPageSettings returns the status page settings; a tenant that never configured the
// page gets the disabled defaults.
func (s *Store) GetStatusPageSettings(ctx context.Context) (StatusPageSettings, error) {
	var (
		item           StatusPageSettings
		enabled        int
		hideFooter     int
		noindex        int
		updatedAt      sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
SELECT enabled, title, description, logo_ref, brand_color, hide_goup_footer, access_mode, access_token_hash, noindex, announce_hours, updated_at
FROM status_page_settings WHERE id = 1
`).Scan(&enabled, &item.Title, &item.Description, &item.LogoRef, &item.BrandColor, &hideFooter, &item.AccessMode, &item.AccessTokenHash, &noindex, &item.AnnounceHours, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return StatusPageSettings{AccessMode: statusPageAccessModePublic, AnnounceHours: statusPageAnnounceHoursDefault}, nil
		}
		return StatusPageSettings{}, fmt.Errorf("load status page settings: %w", err)
	}
	item.Enabled = enabled == 1
	item.HideGoUpFooter = hideFooter == 1
	item.NoIndex = noindex == 1
	item.AccessMode = normalizeStatusPageAccessMode(item.AccessMode)
	item.BrandColor = normalizeStatusPageBrandColor(item.BrandColor)
	item.AnnounceHours = NormalizeAnnounceHours(item.AnnounceHours)
	if updatedAt.Valid {
		item.UpdatedAt = updatedAt.Time
	}
	return item, nil
}

// SaveStatusPageSettings replaces the status page configuration, including the monitor selection.
// Monitors that no longer exist are ignored.
func (s *Store) SaveStatusPageSettings(ctx context.Context, settings StatusPageSettings, monitors []StatusPageMonitor) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin status page save: %w", err)
	}
	defer tx.Rollback()

	enabled := 0
	if settings.Enabled {
		enabled = 1
	}
	hideFooter := 0
	if settings.HideGoUpFooter {
		hideFooter = 1
	}
	noindex := 0
	if settings.NoIndex {
		noindex = 1
	}
	accessMode := normalizeStatusPageAccessMode(settings.AccessMode)
	announceHours := NormalizeAnnounceHours(settings.AnnounceHours)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO status_page_settings (
	id, enabled, title, description, logo_ref, brand_color, hide_goup_footer,
	access_mode, access_token_hash, noindex, announce_hours, updated_at
)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	enabled = excluded.enabled,
	title = excluded.title,
	description = excluded.description,
	logo_ref = excluded.logo_ref,
	brand_color = excluded.brand_color,
	hide_goup_footer = excluded.hide_goup_footer,
	access_mode = excluded.access_mode,
	access_token_hash = excluded.access_token_hash,
	noindex = excluded.noindex,
	announce_hours = excluded.announce_hours,
	updated_at = excluded.updated_at
`, enabled,
		truncateRunes(strings.TrimSpace(settings.Title), statusPageTitleMaxRunes),
		truncateRunes(strings.TrimSpace(settings.Description), statusPageDescriptionMaxRunes),
		truncateRunes(strings.TrimSpace(settings.LogoRef), statusPageLogoRefMaxRunes),
		normalizeStatusPageBrandColor(settings.BrandColor),
		hideFooter,
		accessMode,
		strings.TrimSpace(settings.AccessTokenHash),
		noindex,
		announceHours,
		time.Now().UTC()); err != nil {
		return fmt.Errorf("save status page settings: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM status_page_monitors`); err != nil {
		return fmt.Errorf("clear status page monitors: %w", err)
	}
	for idx, item := range monitors {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO status_page_monitors (monitor_id, display_name, sort_order)
SELECT id, ?, ? FROM monitors WHERE id = ?
ON CONFLICT(monitor_id) DO UPDATE SET display_name = excluded.display_name, sort_order = excluded.sort_order
`, truncateRunes(strings.TrimSpace(item.DisplayName), statusPageDisplayNameMaxRunes), idx, item.MonitorID); err != nil {
			return fmt.Errorf("save status page monitor: %w", err)
		}
	}
	return tx.Commit()
}

// ListStatusPageMonitors returns the selected monitors in display order.
func (s *Store) ListStatusPageMonitors(ctx context.Context) ([]StatusPageMonitor, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT sp.monitor_id, sp.display_name, sp.sort_order
FROM status_page_monitors sp
JOIN monitors m ON m.id = sp.monitor_id
ORDER BY sp.sort_order ASC, sp.monitor_id ASC
`)
	if err != nil {
		return nil, fmt.Errorf("list status page monitors: %w", err)
	}
	defer rows.Close()
	items := make([]StatusPageMonitor, 0)
	for rows.Next() {
		var item StatusPageMonitor
		if err := rows.Scan(&item.MonitorID, &item.DisplayName, &item.SortOrder); err != nil {
			return nil, fmt.Errorf("scan status page monitor: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate status page monitors: %w", err)
	}
	return items, nil
}

// ListStatusPageIncidents returns recent incidents for the selected status-page monitors.
// Cause and target fields are never included.
func (s *Store) ListStatusPageIncidents(ctx context.Context, monitorIDs []int64, limit int) ([]StatusPageIncident, error) {
	if limit <= 0 {
		limit = statusPageIncidentDefaultLimit
	}
	if len(monitorIDs) == 0 {
		return []StatusPageIncident{}, nil
	}
	placeholders := make([]string, len(monitorIDs))
	args := make([]any, 0, len(monitorIDs)+1)
	for i, id := range monitorIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `
SELECT i.monitor_id,
	COALESCE(NULLIF(TRIM(sp.display_name), ''), m.name) AS display_name,
	i.started_at,
	i.resolved_at
FROM incidents i
JOIN monitors m ON m.id = i.monitor_id
LEFT JOIN status_page_monitors sp ON sp.monitor_id = i.monitor_id
WHERE i.monitor_id IN (`+strings.Join(placeholders, ",")+`)
ORDER BY i.started_at DESC, i.id DESC
LIMIT ?
`, args...)
	if err != nil {
		return nil, fmt.Errorf("list status page incidents: %w", err)
	}
	defer rows.Close()
	items := make([]StatusPageIncident, 0)
	for rows.Next() {
		var (
			item       StatusPageIncident
			resolvedAt sql.NullTime
		)
		if err := rows.Scan(&item.MonitorID, &item.DisplayName, &item.StartedAt, &resolvedAt); err != nil {
			return nil, fmt.Errorf("scan status page incident: %w", err)
		}
		item.ResolvedAt = nullableTime(resolvedAt)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate status page incidents: %w", err)
	}
	return items, nil
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
