package sqlite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func newPushTestStore(t *testing.T) (*ControlPlaneStore, Tenant, LocalUser, LocalUser) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	t.Cleanup(func() { cp.Close() })
	if err := cp.ConfigureSecretKey("test-secret-key-for-push-tests"); err != nil {
		t.Fatalf("configure secret key: %v", err)
	}
	tenant, err := cp.CreateTenant(ctx, "push", "Push", filepath.Join(dir, "push.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	admin, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "admin", "password-123456", "a@example.com", "Admin", "admin")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	viewer, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "viewer", "password-123456", "v@example.com", "Viewer", "viewer")
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	return cp, tenant, admin, viewer
}

func pushSub(tenantID, userID int64, endpoint string) PushSubscription {
	return PushSubscription{
		TenantID: tenantID, UserID: userID, Endpoint: endpoint, P256dh: "p256dh-value", Auth: "auth-value",
		DeviceLabel: "iPhone · Safari", NotifyDown: true, NotifyRecovery: true, NotifyDegraded: true, NotifyReminder: true,
	}
}

func TestPushSubscriptionCRUDAndReassign(t *testing.T) {
	ctx := context.Background()
	cp, tenant, admin, viewer := newPushTestStore(t)

	saved, err := cp.UpsertPushSubscription(ctx, pushSub(tenant.ID, admin.UserID, "https://web.push.apple.com/a"))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if saved.P256dh != "p256dh-value" || saved.Auth != "auth-value" || saved.ID == 0 {
		t.Fatalf("unexpected saved subscription: %#v", saved)
	}
	var cipher string
	if err := cp.db.QueryRowContext(ctx, `SELECT p256dh_ciphertext FROM push_subscriptions WHERE id = ?`, saved.ID).Scan(&cipher); err != nil || cipher == "p256dh-value" || cipher == "" {
		t.Fatalf("p256dh must be stored encrypted, got %q (%v)", cipher, err)
	}

	// Same endpoint, other user: reassigned, still one row.
	moved, err := cp.UpsertPushSubscription(ctx, pushSub(tenant.ID, viewer.UserID, "https://web.push.apple.com/a"))
	if err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if moved.ID != saved.ID || moved.UserID != viewer.UserID {
		t.Fatalf("endpoint should move to the new user, got %#v", moved)
	}
	if list, _ := cp.ListUserPushSubscriptions(ctx, tenant.ID, admin.UserID); len(list) != 0 {
		t.Fatalf("old owner still has %d subscriptions", len(list))
	}

	// Ownership: admin cannot delete the viewer's device.
	if removed, err := cp.DeleteUserPushSubscriptionByEndpoint(ctx, tenant.ID, admin.UserID, "https://web.push.apple.com/a"); err != nil || removed {
		t.Fatalf("foreign delete removed=%v err=%v", removed, err)
	}
	if ok, err := cp.UpdatePushSubscriptionPrefs(ctx, tenant.ID, admin.UserID, moved.ID, PushPrefs{}); err != nil || ok {
		t.Fatalf("foreign prefs update ok=%v err=%v", ok, err)
	}
	if ok, err := cp.UpdatePushSubscriptionPrefs(ctx, tenant.ID, viewer.UserID, moved.ID, PushPrefs{Down: true}); err != nil || !ok {
		t.Fatalf("own prefs update ok=%v err=%v", ok, err)
	}
	list, _ := cp.ListUserPushSubscriptions(ctx, tenant.ID, viewer.UserID)
	if len(list) != 1 || !list[0].NotifyDown || list[0].NotifyRecovery || list[0].NotifyDegraded || list[0].NotifyReminder {
		t.Fatalf("prefs not stored: %#v", list)
	}

	if err := cp.RecordPushResult(ctx, moved.ID, false, "boom"); err != nil {
		t.Fatal(err)
	}
	list, _ = cp.ListUserPushSubscriptions(ctx, tenant.ID, viewer.UserID)
	if list[0].LastError != "boom" || list[0].LastErrorAt == nil {
		t.Fatalf("error not recorded: %#v", list[0])
	}
	if err := cp.RecordPushResult(ctx, moved.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	list, _ = cp.ListUserPushSubscriptions(ctx, tenant.ID, viewer.UserID)
	if list[0].LastError != "" || list[0].LastSuccessAt == nil {
		t.Fatalf("success not recorded: %#v", list[0])
	}

	if removed, err := cp.DeleteUserPushSubscriptionByEndpoint(ctx, tenant.ID, viewer.UserID, "https://web.push.apple.com/a"); err != nil || !removed {
		t.Fatalf("own delete removed=%v err=%v", removed, err)
	}
}

func TestPushSubscriptionLimit(t *testing.T) {
	ctx := context.Background()
	cp, tenant, admin, _ := newPushTestStore(t)
	for i := 0; i < MaxPushSubscriptionsPerUser; i++ {
		if _, err := cp.UpsertPushSubscription(ctx, pushSub(tenant.ID, admin.UserID, fmt.Sprintf("https://web.push.apple.com/%d", i))); err != nil {
			t.Fatalf("subscription %d: %v", i, err)
		}
	}
	if _, err := cp.UpsertPushSubscription(ctx, pushSub(tenant.ID, admin.UserID, "https://web.push.apple.com/extra")); !errors.Is(err, ErrPushSubscriptionLimit) {
		t.Fatalf("expected limit error, got %v", err)
	}
	// Refreshing an existing endpoint is still allowed at the limit.
	if _, err := cp.UpsertPushSubscription(ctx, pushSub(tenant.ID, admin.UserID, "https://web.push.apple.com/3")); err != nil {
		t.Fatalf("refresh at limit: %v", err)
	}
}

func TestPushTargetsSkipBlockedMembersAndFilterAdmins(t *testing.T) {
	ctx := context.Background()
	cp, tenant, admin, viewer := newPushTestStore(t)
	if _, err := cp.UpsertPushSubscription(ctx, pushSub(tenant.ID, admin.UserID, "https://web.push.apple.com/admin")); err != nil {
		t.Fatal(err)
	}
	if _, err := cp.UpsertPushSubscription(ctx, pushSub(tenant.ID, viewer.UserID, "https://web.push.apple.com/viewer")); err != nil {
		t.Fatal(err)
	}

	all, err := cp.ListTenantPushTargets(ctx, tenant.ID, false)
	if err != nil || len(all) != 2 {
		t.Fatalf("all targets = %d (%v), want 2", len(all), err)
	}
	admins, err := cp.ListTenantPushTargets(ctx, tenant.ID, true)
	if err != nil || len(admins) != 1 || admins[0].UserID != admin.UserID {
		t.Fatalf("admin targets = %#v (%v)", admins, err)
	}

	if _, err := cp.db.ExecContext(ctx, `UPDATE tenant_memberships SET blocked = 1 WHERE tenant_id = ? AND user_id = ?`, tenant.ID, viewer.UserID); err != nil {
		t.Fatal(err)
	}
	all, _ = cp.ListTenantPushTargets(ctx, tenant.ID, false)
	if len(all) != 1 || all[0].UserID != admin.UserID {
		t.Fatalf("blocked member must not receive pushes, got %#v", all)
	}
}

func TestVAPIDKeysAreStableAndEncrypted(t *testing.T) {
	ctx := context.Background()
	cp, _, _, _ := newPushTestStore(t)
	priv1, pub1, err := cp.GetOrCreateVAPIDKeys(ctx)
	if err != nil || priv1 == "" || pub1 == "" {
		t.Fatalf("create keys: %v", err)
	}
	priv2, pub2, err := cp.GetOrCreateVAPIDKeys(ctx)
	if err != nil || priv1 != priv2 || pub1 != pub2 {
		t.Fatalf("keys changed between calls: %v", err)
	}
	var stored string
	if err := cp.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = ?`, vapidPrivateSettingKey).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == priv1 {
		t.Fatal("private key must be stored encrypted")
	}
}
