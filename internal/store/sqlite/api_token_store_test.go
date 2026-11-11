package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAPITokenExpiryAndRotate(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))
	if err != nil {
		t.Fatal(err)
	}

	plain, tok, err := cp.CreateAPIToken(ctx, tenant.ID, "temp", APITokenScopeMetrics, "admin", 1)
	if err != nil {
		t.Fatal(err)
	}
	if tok.ExpiresAt == nil {
		t.Fatal("expected expiry")
	}
	ok, err := cp.AuthenticateAPIToken(ctx, tenant.ID, APITokenScopeMetrics, plain)
	if err != nil || !ok {
		t.Fatalf("fresh token should auth: ok=%v err=%v", ok, err)
	}

	if _, err := cp.db.ExecContext(ctx, `UPDATE api_tokens SET expires_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute), tok.ID); err != nil {
		t.Fatal(err)
	}
	ok, err = cp.AuthenticateAPIToken(ctx, tenant.ID, APITokenScopeMetrics, plain)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expired token must not authenticate")
	}

	plain2, tok2, err := cp.CreateAPIToken(ctx, tenant.ID, "rot", APITokenScopeMetrics, "admin", 7)
	if err != nil {
		t.Fatal(err)
	}
	rotated, next, err := cp.RotateAPIToken(ctx, tenant.ID, tok2.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rotated == "" || next.ID == tok2.ID {
		t.Fatalf("rotate failed: %+v", next)
	}
	if ok, _ := cp.AuthenticateAPIToken(ctx, tenant.ID, APITokenScopeMetrics, plain2); ok {
		t.Fatal("old token should be revoked after rotate")
	}
	if ok, _ := cp.AuthenticateAPIToken(ctx, tenant.ID, APITokenScopeMetrics, rotated); !ok {
		t.Fatal("rotated token should authenticate")
	}
}

func TestAPITokenScopeImplication(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))
	if err != nil {
		t.Fatal(err)
	}

	writePlain, _, err := cp.CreateAPIToken(ctx, tenant.ID, "write", APITokenScopeMonitorsWrite, "admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	readPlain, _, err := cp.CreateAPIToken(ctx, tenant.ID, "read", APITokenScopeMonitorsRead, "admin", 0)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := cp.AuthenticateAPITokenWithScopes(ctx, tenant.ID, writePlain, APITokenScopeMonitorsRead)
	if err != nil || !ok {
		t.Fatalf("write should satisfy read: ok=%v err=%v", ok, err)
	}
	ok, err = cp.AuthenticateAPITokenWithScopes(ctx, tenant.ID, readPlain, APITokenScopeMonitorsWrite)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("read must not satisfy write")
	}
	ok, err = cp.AuthenticateAPITokenWithScopes(ctx, tenant.ID, writePlain, APITokenScopeMetrics)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("monitors write must not satisfy metrics")
	}
}

func TestListStatusPageIncidentsOmitsCause(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Shop", Kind: "tcp", Target: "10.9.8.7:443", Interval: time.Minute, Timeout: time.Second,
		Enabled: true, TLSMode: "none", ConfirmAfter: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	cause := "dial tcp 10.9.8.7:443: connection refused"
	if err := st.RecordMonitorState(ctx, id, "down", cause, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveStatusPageSettings(ctx, StatusPageSettings{Enabled: true}, []StatusPageMonitor{{MonitorID: id, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}
	items, err := st.ListStatusPageIncidents(ctx, []int64{id}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("incidents = %d", len(items))
	}
	if items[0].DisplayName != "Online Shop" {
		t.Fatalf("display = %q", items[0].DisplayName)
	}
}
