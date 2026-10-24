package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func openTestControlPlane(t *testing.T) (*ControlPlaneStore, string) {
	t.Helper()
	dir := t.TempDir()
	cp, err := OpenControlPlane(context.Background(), filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	t.Cleanup(func() { cp.Close() })
	return cp, dir
}

func TestOIDCNewMembersGetDefaultRoleNotAdmin(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	user, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-1", "a@example.com", "A", tenant.ID, "viewer")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if user.Role != "viewer" {
		t.Fatalf("new OIDC member role = %q, want viewer", user.Role)
	}

	// Unknown / invalid default roles fall back to viewer.
	user2, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-2", "b@example.com", "B", tenant.ID, "superuser")
	if err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if user2.Role != "viewer" {
		t.Fatalf("invalid default role must fall back to viewer, got %q", user2.Role)
	}

	// Configured admin default role is honored for new members only.
	user3, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-3", "c@example.com", "C", tenant.ID, "admin")
	if err != nil {
		t.Fatalf("upsert 3: %v", err)
	}
	if user3.Role != "admin" {
		t.Fatalf("role = %q, want admin", user3.Role)
	}
}

func TestOIDCReloginDoesNotChangeExistingRole(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	tenant, _ := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))

	user, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-1", "a@example.com", "A", tenant.ID, "viewer")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := cp.UpdateTenantUserRole(ctx, tenant.ID, user.UserID, "admin"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	again, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-1", "a@example.com", "A", tenant.ID, "viewer")
	if err != nil {
		t.Fatalf("relogin: %v", err)
	}
	if again.Role != "admin" {
		t.Fatalf("relogin with viewer default demoted/changed role: %q", again.Role)
	}
	demoted, _ := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-1", "a@example.com", "A", tenant.ID, "viewer")
	_ = demoted
	if err := cp.UpdateTenantUserRole(ctx, tenant.ID, user.UserID, "viewer"); err != nil {
		t.Fatalf("demote: %v", err)
	}
	third, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-1", "a@example.com", "A", tenant.ID, "admin")
	if err != nil {
		t.Fatalf("relogin 3: %v", err)
	}
	if third.Role != "viewer" {
		t.Fatalf("relogin with admin default must not escalate existing member, got %q", third.Role)
	}
}

func TestRemovedOIDCUserCannotSilentlyRejoin(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	tenant, _ := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))

	user, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-1", "a@example.com", "A", tenant.ID, "viewer")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	before, err := cp.GetTenantMembershipSessionVersion(ctx, tenant.ID, user.UserID)
	if err != nil {
		t.Fatalf("session version: %v", err)
	}
	if err := cp.RemoveUserFromTenant(ctx, tenant.ID, user.UserID); err != nil {
		t.Fatalf("remove: %v", err)
	}

	if _, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-1", "a@example.com", "A", tenant.ID, "viewer"); !errors.Is(err, ErrMembershipBlocked) {
		t.Fatalf("expected ErrMembershipBlocked, got %v", err)
	}
	if _, err := cp.GetTenantMembershipSessionVersion(ctx, tenant.ID, user.UserID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("blocked member must not validate sessions, got %v (before=%d)", err, before)
	}

	users, err := cp.ListTenantUsers(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("blocked user must not be listed as active, got %d", len(users))
	}
	blocked, err := cp.ListBlockedTenantUsers(ctx, tenant.ID)
	if err != nil || len(blocked) != 1 || !blocked[0].Blocked {
		t.Fatalf("expected one blocked user, got %v err=%v", blocked, err)
	}

	// Re-adding clears the block.
	if err := cp.UnblockTenantUser(ctx, tenant.ID, user.UserID, "viewer"); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if _, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-1", "a@example.com", "A", tenant.ID, "viewer"); err != nil {
		t.Fatalf("login after unblock: %v", err)
	}
}

func TestBlockedLocalUserCannotAuthenticate(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	tenant, _ := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))

	user, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "alice", "correct-horse-battery", "a@example.com", "Alice", "viewer")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := cp.AuthenticateLocalUser(ctx, tenant.ID, "alice", "correct-horse-battery"); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if _, err := cp.db.ExecContext(ctx, `UPDATE tenant_memberships SET blocked = 1 WHERE user_id = ?`, user.UserID); err != nil {
		t.Fatalf("block: %v", err)
	}
	if _, err := cp.AuthenticateLocalUser(ctx, tenant.ID, "alice", "correct-horse-battery"); err == nil {
		t.Fatalf("blocked local user must not authenticate")
	}
}

func TestIdentitiesAreTenantScoped(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	a, _ := cp.CreateTenant(ctx, "tenant-a", "A", filepath.Join(dir, "a.db"))
	b, _ := cp.CreateTenant(ctx, "tenant-b", "B", filepath.Join(dir, "b.db"))

	ua, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "same-sub", "x@a.example", "X", a.ID, "viewer")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	ub, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "same-sub", "x@b.example", "X", b.ID, "viewer")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if ua.UserID == ub.UserID {
		t.Fatalf("same provider key + subject in different tenants must map to different users")
	}
	if ub.TenantID != b.ID {
		t.Fatalf("tenant b login resolved to tenant %d", ub.TenantID)
	}
}

func TestUserIdentitiesMigrationBackfillsTenant(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "controlplane.db")

	legacy, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	legacySchema := []string{
		`CREATE TABLE tenants (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, db_path TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, state_event_retention_days INTEGER NOT NULL DEFAULT 365, notification_event_retention_days INTEGER NOT NULL DEFAULT 365, raw_result_retention_days INTEGER NOT NULL DEFAULT 30, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL DEFAULT '', preferred_language TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, last_login_at DATETIME)`,
		`CREATE TABLE user_identities (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, provider_key TEXT NOT NULL, provider_subject TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, UNIQUE(provider_key, provider_subject), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`,
		`CREATE TABLE tenant_memberships (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'viewer', session_version INTEGER NOT NULL DEFAULT 1, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, UNIQUE(tenant_id, user_id))`,
		`INSERT INTO tenants (id, slug, name, db_path, created_at, updated_at) VALUES (1, 'one', 'One', '/x/one.db', datetime('now'), datetime('now')), (2, 'two', 'Two', '/x/two.db', datetime('now'), datetime('now'))`,
		`INSERT INTO users (id, email, created_at, updated_at) VALUES (1, 'a@x', datetime('now'), datetime('now')), (2, 'orphan@x', datetime('now'), datetime('now'))`,
		`INSERT INTO user_identities (user_id, provider_key, provider_subject, email, created_at, updated_at) VALUES (1, 'oidc-primary', 'sub-a', 'a@x', datetime('now'), datetime('now')), (2, 'oidc-primary', 'sub-orphan', 'orphan@x', datetime('now'), datetime('now'))`,
		`INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at, updated_at) VALUES (1, 1, 'admin', datetime('now'), datetime('now')), (2, 1, 'viewer', datetime('now'), datetime('now'))`,
	}
	for _, stmt := range legacySchema {
		if _, err := legacy.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("legacy setup %q: %v", stmt, err)
		}
	}
	legacy.Close()

	cp, err := OpenControlPlane(ctx, path)
	if err != nil {
		t.Fatalf("open migrated control plane: %v", err)
	}
	defer cp.Close()

	rows, err := cp.db.QueryContext(ctx, `SELECT user_id, tenant_id FROM user_identities ORDER BY user_id, tenant_id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	type pair struct{ user, tenant int64 }
	var got []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.user, &p.tenant); err != nil {
			t.Fatal(err)
		}
		got = append(got, p)
	}
	want := []pair{{1, 1}, {1, 2}, {2, 0}}
	if len(got) != len(want) {
		t.Fatalf("identities = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("identities = %v, want %v", got, want)
		}
	}

	// Existing admin keeps their role through a relogin in tenant one.
	user, err := cp.UpsertOIDCUserIdentity(ctx, "oidc-primary", "sub-a", "a@x", "A", 1, "viewer")
	if err != nil {
		t.Fatalf("relogin after migration: %v", err)
	}
	if user.UserID != 1 || user.Role != "admin" {
		t.Fatalf("relogin resolved user=%d role=%s, want user 1 admin", user.UserID, user.Role)
	}

	// Re-opening is idempotent.
	cp.Close()
	cp2, err := OpenControlPlane(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	cp2.Close()
}

func TestReservedTenantSlugsRejected(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	for _, slug := range []string{"node", "admin", "static", "auth", "healthz", "assets", "api", "metrics", "status", "sw.js", "manifest", "offline", "favicon", "NODE"} {
		if _, err := cp.CreateTenant(ctx, slug, "x", filepath.Join(dir, "r.db")); err == nil {
			t.Errorf("slug %q must be rejected", slug)
		}
	}
	if _, err := cp.CreateTenant(ctx, "my-company", "x", filepath.Join(dir, "ok.db")); err != nil {
		t.Fatalf("regular slug rejected: %v", err)
	}
}

func TestShortLocalPasswordsRejected(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	tenant, _ := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))
	if _, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "bob", "short-pw", "", "", "viewer"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}
	if _, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "bob", "long-enough-password", "", "", "root"); err == nil {
		t.Fatalf("invalid role must be rejected")
	}
}

func TestProviderPolicy(t *testing.T) {
	yes, no := true, false
	p := AuthProvider{AllowedEmailDomains: "Example.com, @corp.test", AllowedGroups: "goup-users", RequireEmailVerified: true}
	cases := []struct {
		name   string
		claims OIDCClaims
		ok     bool
	}{
		{"allowed", OIDCClaims{Email: "a@example.com", EmailVerified: &yes, Groups: []string{"goup-users"}}, true},
		{"second domain", OIDCClaims{Email: "a@corp.test", EmailVerified: &yes, Groups: []string{"x", "goup-users"}}, true},
		{"wrong domain", OIDCClaims{Email: "a@evil.test", EmailVerified: &yes, Groups: []string{"goup-users"}}, false},
		{"unverified", OIDCClaims{Email: "a@example.com", EmailVerified: &no, Groups: []string{"goup-users"}}, false},
		{"claim missing with domain policy", OIDCClaims{Email: "a@example.com", Groups: []string{"goup-users"}}, false},
		{"missing group", OIDCClaims{Email: "a@example.com", EmailVerified: &yes}, false},
		{"suffix trick", OIDCClaims{Email: "a@notexample.com", EmailVerified: &yes, Groups: []string{"goup-users"}}, false},
	}
	for _, tc := range cases {
		if err := p.CheckOIDCAccess(tc.claims); (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}

	open := AuthProvider{}
	if err := open.CheckOIDCAccess(OIDCClaims{Email: "x@y.z"}); err != nil {
		t.Errorf("no policy and no claim must pass: %v", err)
	}
	// Authentik sends email_verified=false by default; that must not block
	// logins unless the provider requires verified emails.
	if err := open.CheckOIDCAccess(OIDCClaims{Email: "x@y.z", EmailVerified: &no}); err != nil {
		t.Errorf("email_verified=false without requirement must pass: %v", err)
	}
	domainOnly := AuthProvider{AllowedEmailDomains: "example.com"}
	if err := domainOnly.CheckOIDCAccess(OIDCClaims{Email: "a@example.com", EmailVerified: &no}); err != nil {
		t.Errorf("domain policy without verification requirement must pass: %v", err)
	}
	if err := domainOnly.CheckOIDCAccess(OIDCClaims{Email: "a@evil.test", EmailVerified: &yes}); err == nil {
		t.Errorf("wrong domain must be rejected")
	}
	strict := AuthProvider{RequireEmailVerified: true}
	if err := strict.CheckOIDCAccess(OIDCClaims{Email: "x@y.z"}); err == nil {
		t.Errorf("missing claim must be rejected when verification is required")
	}
}

func TestAdminTOTPFailsClosedOnDecryptError(t *testing.T) {
	ctx := context.Background()
	cp, _ := openTestControlPlane(t)
	if err := cp.ConfigureSecretKeys("secret-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := cp.CreateControlPlaneAdmin(ctx, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := cp.SetControlPlaneAdminTOTP(ctx, "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatal(err)
	}
	if err := cp.ConfigureSecretKeys("different-key-bbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}
	admin, err := cp.GetControlPlaneAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !admin.TOTPEnabled || !admin.TOTPUnreadable || admin.TOTPSecret != "" {
		t.Fatalf("TOTP must fail closed: %+v", admin)
	}
}
