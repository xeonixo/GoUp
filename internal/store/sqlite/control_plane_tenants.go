package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var tenantSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// reservedTenantSlugs are top-level URL paths used by the application itself.
// A tenant with one of these slugs would shadow (or be shadowed by) a route.
var reservedTenantSlugs = map[string]struct{}{
	"node": {}, "admin": {}, "static": {}, "auth": {}, "healthz": {}, "assets": {},
	"api": {}, "metrics": {}, "status": {}, "sw.js": {}, "manifest": {}, "manifest.json": {},
	"offline": {}, "favicon": {}, "favicon.ico": {}, "robots.txt": {}, "login": {}, "logout": {},
	"icons": {}, "health": {}, "ready": {}, "readyz": {}, "livez": {}, "setup": {}, "settings": {},
}

// IsReservedTenantSlug reports whether slug collides with an application route.
func IsReservedTenantSlug(slug string) bool {
	_, ok := reservedTenantSlugs[strings.ToLower(strings.TrimSpace(slug))]
	return ok
}

type Tenant struct {
	ID                             int64
	Slug                           string
	Name                           string
	DBPath                         string
	Active                         bool
	StateEventRetentionDays        int
	NotificationEventRetentionDays int
	RawResultRetentionDays         int
}

func (s *ControlPlaneStore) GetTenantBySlug(ctx context.Context, slug string) (Tenant, error) {
	return s.getTenant(ctx, `
SELECT id, slug, name, db_path, active, state_event_retention_days, notification_event_retention_days, raw_result_retention_days
FROM tenants
WHERE slug = ?
`, slug)
}

func (s *ControlPlaneStore) GetTenantByID(ctx context.Context, tenantID int64) (Tenant, error) {
	return s.getTenant(ctx, `
SELECT id, slug, name, db_path, active, state_event_retention_days, notification_event_retention_days, raw_result_retention_days
FROM tenants
WHERE id = ?
`, tenantID)
}

func (s *ControlPlaneStore) getTenant(ctx context.Context, query string, args ...any) (Tenant, error) {
	var tenant Tenant
	var active int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&tenant.ID,
		&tenant.Slug,
		&tenant.Name,
		&tenant.DBPath,
		&active,
		&tenant.StateEventRetentionDays,
		&tenant.NotificationEventRetentionDays,
		&tenant.RawResultRetentionDays,
	)
	if err != nil {
		return Tenant{}, fmt.Errorf("get tenant: %w", err)
	}
	tenant.Active = active == 1
	tenant.StateEventRetentionDays = normalizeEventRetentionDays(tenant.StateEventRetentionDays)
	tenant.NotificationEventRetentionDays = normalizeEventRetentionDays(tenant.NotificationEventRetentionDays)
	tenant.RawResultRetentionDays = NormalizeRawResultRetentionDays(tenant.RawResultRetentionDays)
	return tenant, nil
}

// Admin Methods for Tenant Management

// GetAllTenants returns all tenants, optionally filtered by active status
func (s *ControlPlaneStore) GetAllTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, slug, name, db_path, active, state_event_retention_days, notification_event_retention_days, raw_result_retention_days
FROM tenants
ORDER BY created_at ASC
`)
	if err != nil {
		return nil, fmt.Errorf("query all tenants: %w", err)
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		var t Tenant
		var active int
		if err := rows.Scan(
			&t.ID,
			&t.Slug,
			&t.Name,
			&t.DBPath,
			&active,
			&t.StateEventRetentionDays,
			&t.NotificationEventRetentionDays,
			&t.RawResultRetentionDays,
		); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		t.Active = active == 1
		t.StateEventRetentionDays = normalizeEventRetentionDays(t.StateEventRetentionDays)
		t.NotificationEventRetentionDays = normalizeEventRetentionDays(t.NotificationEventRetentionDays)
		t.RawResultRetentionDays = NormalizeRawResultRetentionDays(t.RawResultRetentionDays)
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}
	return tenants, nil
}

// CreateTenant creates a new tenant and returns it
func (s *ControlPlaneStore) CreateTenant(ctx context.Context, slug, name, dbPath string) (Tenant, error) {
	return s.CreateTenantWithRetention(ctx, slug, name, dbPath, defaultEventRetentionDays, defaultEventRetentionDays)
}

func (s *ControlPlaneStore) CreateTenantWithRetention(ctx context.Context, slug, name, dbPath string, stateEventRetentionDays, notificationEventRetentionDays int) (Tenant, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if !tenantSlugPattern.MatchString(slug) {
		return Tenant{}, fmt.Errorf("invalid tenant slug %q (allowed: a-z, 0-9, -; length 2-63)", slug)
	}
	if IsReservedTenantSlug(slug) {
		return Tenant{}, fmt.Errorf("tenant slug %q is reserved", slug)
	}
	if strings.TrimSpace(name) == "" {
		return Tenant{}, fmt.Errorf("tenant name is required")
	}
	if strings.TrimSpace(dbPath) == "" {
		return Tenant{}, fmt.Errorf("tenant db_path is required")
	}
	stateEventRetentionDays = normalizeEventRetentionDays(stateEventRetentionDays)
	notificationEventRetentionDays = normalizeEventRetentionDays(notificationEventRetentionDays)

	// Validate slug is unique
	_, err := s.GetTenantBySlug(ctx, slug)
	if err == nil {
		return Tenant{}, fmt.Errorf("tenant slug already exists: %s", slug)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, fmt.Errorf("check slug uniqueness: %w", err)
	}

	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
INSERT INTO tenants (
	slug,
	name,
	db_path,
	active,
	state_event_retention_days,
	notification_event_retention_days,
	created_at,
	updated_at
) VALUES (?, ?, ?, 1, ?, ?, ?, ?)
`, slug, name, dbPath, stateEventRetentionDays, notificationEventRetentionDays, now, now)
	if err != nil {
		return Tenant{}, fmt.Errorf("insert tenant: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return Tenant{}, fmt.Errorf("get last tenant id: %w", err)
	}

	tenant, err := s.GetTenantByID(ctx, id)
	if err != nil {
		return Tenant{}, err
	}
	if err := ensureTenantDatabaseReady(ctx, tenant.DBPath); err != nil {
		return Tenant{}, err
	}

	return tenant, nil
}

// SetTenantRawResultRetentionDays sets how many days of raw check results the tenant keeps.
func (s *ControlPlaneStore) SetTenantRawResultRetentionDays(ctx context.Context, id int64, days int) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE tenants
SET raw_result_retention_days = ?, updated_at = ?
WHERE id = ?
`, NormalizeRawResultRetentionDays(days), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update tenant raw result retention: %w", err)
	}
	return nil
}

// UpdateTenant updates an existing tenant
func (s *ControlPlaneStore) UpdateTenant(ctx context.Context, id int64, name, dbPath string, active bool) (Tenant, error) {
	current, err := s.GetTenantByID(ctx, id)
	if err != nil {
		return Tenant{}, err
	}
	return s.UpdateTenantWithRetention(ctx, id, name, dbPath, active, current.StateEventRetentionDays, current.NotificationEventRetentionDays)
}

func (s *ControlPlaneStore) UpdateTenantWithRetention(ctx context.Context, id int64, name, dbPath string, active bool, stateEventRetentionDays, notificationEventRetentionDays int) (Tenant, error) {
	now := time.Now().UTC()
	activeInt := 0
	if active {
		activeInt = 1
	}
	stateEventRetentionDays = normalizeEventRetentionDays(stateEventRetentionDays)
	notificationEventRetentionDays = normalizeEventRetentionDays(notificationEventRetentionDays)

	_, err := s.db.ExecContext(ctx, `
UPDATE tenants
SET name = ?, db_path = ?, active = ?, state_event_retention_days = ?, notification_event_retention_days = ?, updated_at = ?
WHERE id = ?
`, name, dbPath, activeInt, stateEventRetentionDays, notificationEventRetentionDays, now, id)
	if err != nil {
		return Tenant{}, fmt.Errorf("update tenant: %w", err)
	}

	tenant, err := s.GetTenantByID(ctx, id)
	if err != nil {
		return Tenant{}, err
	}
	if err := ensureTenantDatabaseReady(ctx, tenant.DBPath); err != nil {
		return Tenant{}, err
	}

	return tenant, nil
}

const (
	defaultEventRetentionDays = 365
	minEventRetentionDays     = 1
	maxEventRetentionDays     = 3650
)

func NormalizeEventRetentionDays(days int) int {
	return normalizeEventRetentionDays(days)
}

func normalizeEventRetentionDays(days int) int {
	if days < minEventRetentionDays || days > maxEventRetentionDays {
		return defaultEventRetentionDays
	}
	return days
}

func ensureTenantDatabaseReady(ctx context.Context, dbPath string) error {
	trimmedPath := strings.TrimSpace(dbPath)
	if trimmedPath == "" {
		return fmt.Errorf("tenant db_path is required")
	}

	dir := filepath.Dir(trimmedPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create tenant db directory: %w", err)
		}
	}

	tenantStore, err := Open(ctx, trimmedPath)
	if err != nil {
		return fmt.Errorf("initialize tenant database %q: %w", trimmedPath, err)
	}
	if err := tenantStore.Close(); err != nil {
		return fmt.Errorf("close initialized tenant database %q: %w", trimmedPath, err)
	}

	return nil
}

// DeactivateTenant soft-deactivates a tenant without deleting
func (s *ControlPlaneStore) DeactivateTenant(ctx context.Context, id int64) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
UPDATE tenants
SET active = 0, updated_at = ?
WHERE id = ?
`, now, id)
	if err != nil {
		return fmt.Errorf("deactivate tenant: %w", err)
	}
	return nil
}

// PurgeTenant permanently deletes a tenant and all control-plane records, then removes the tenant DB file.
func (s *ControlPlaneStore) PurgeTenant(ctx context.Context, id int64) error {
	tenant, err := s.GetTenantByID(ctx, id)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tenant purge transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_provider_secrets WHERE tenant_id = ?`, id); err != nil {
		return fmt.Errorf("purge auth provider secrets: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_providers WHERE tenant_id = ?`, id); err != nil {
		return fmt.Errorf("purge auth providers: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM tenant_memberships WHERE tenant_id = ?`, id); err != nil {
		return fmt.Errorf("purge tenant memberships: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_identities WHERE tenant_id = ?`, id); err != nil {
		return fmt.Errorf("purge tenant user identities: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, id); err != nil {
		return fmt.Errorf("purge tenant record: %w", err)
	}

	// Cleanup users that are no longer referenced by any membership or external identity.
	if _, err := tx.ExecContext(ctx, `
DELETE FROM local_credentials
WHERE user_id IN (
	SELECT u.id
	FROM users u
	LEFT JOIN tenant_memberships tm ON tm.user_id = u.id
	LEFT JOIN user_identities ui ON ui.user_id = u.id
	WHERE tm.user_id IS NULL AND ui.user_id IS NULL
)
`); err != nil {
		return fmt.Errorf("purge orphan local credentials: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM users
WHERE id IN (
	SELECT u.id
	FROM users u
	LEFT JOIN tenant_memberships tm ON tm.user_id = u.id
	LEFT JOIN user_identities ui ON ui.user_id = u.id
	WHERE tm.user_id IS NULL AND ui.user_id IS NULL
)
`); err != nil {
		return fmt.Errorf("purge orphan users: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tenant purge transaction: %w", err)
	}

	dbPath := strings.TrimSpace(tenant.DBPath)
	if dbPath != "" {
		if err := os.Remove(dbPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove tenant db file: %w", err)
		}
		if err := os.Remove(dbPath + "-wal"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove tenant db wal file: %w", err)
		}
		if err := os.Remove(dbPath + "-shm"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove tenant db shm file: %w", err)
		}
	}

	return nil
}
