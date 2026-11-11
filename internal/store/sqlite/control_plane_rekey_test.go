package sqlite

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReencryptAllSecretsWithPreviousKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	oldKey := "old-sso-secret-key-1234567890abcdef"
	newKey := "new-sso-secret-key-1234567890abcdef"

	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	if err := cp.ConfigureSecretKeys(oldKey); err != nil {
		t.Fatalf("configure old key: %v", err)
	}

	tenant, err := cp.CreateTenant(ctx, "rekey", "Rekey", filepath.Join(dir, "rekey.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	user, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "admin", "password-123456", "admin@example.com", "Admin", "admin")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := cp.EnsureDefaultOIDCProvider(ctx, tenant.ID, "https://issuer.example", "client-id", "oidc-client-secret"); err != nil {
		t.Fatalf("ensure oidc provider: %v", err)
	}
	if err := cp.UpsertGlobalSMTPSettings(ctx, GlobalSMTPSettings{
		Host: "smtp.example.com", Port: 587, Username: "mailer", FromEmail: "noreply@example.com", TLSMode: "starttls",
	}, "smtp-password"); err != nil {
		t.Fatalf("smtp: %v", err)
	}
	if err := cp.CreateControlPlaneAdmin(ctx, "root", "hash"); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := cp.SetControlPlaneAdminTOTP(ctx, "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatalf("set totp: %v", err)
	}
	if err := cp.SaveTenantNotificationEndpointSecret(ctx, tenant.ID, 1, "webhook", "webhook-secret"); err != nil {
		t.Fatalf("endpoint secret: %v", err)
	}
	if err := cp.SaveUserNotificationSettings(ctx, tenant.ID, user.UserID, true, true, "https://matrix.example", "!room:example", "matrix-token"); err != nil {
		t.Fatalf("matrix settings: %v", err)
	}
	node, bootstrap, err := cp.CreateRemoteNode(ctx, tenant.ID, "edge-1", 60)
	if err != nil {
		t.Fatalf("create remote node: %v", err)
	}
	if bootstrap == "" || node.ID == 0 {
		t.Fatalf("unexpected remote node: %+v bootstrap=%q", node, bootstrap)
	}
	if _, _, err := cp.GetOrCreateVAPIDKeys(ctx); err != nil {
		t.Fatalf("vapid: %v", err)
	}
	if _, err := cp.UpsertPushSubscription(ctx, PushSubscription{
		TenantID: tenant.ID, UserID: user.UserID, Endpoint: "https://push.example/1",
		P256dh: "p256dh-value", Auth: "auth-value",
	}); err != nil {
		t.Fatalf("push subscription: %v", err)
	}

	if err := cp.ConfigureSecretKeys(newKey, oldKey); err != nil {
		t.Fatalf("configure new+old keys: %v", err)
	}
	updated, err := cp.ReencryptAllSecrets(ctx)
	if err != nil {
		t.Fatalf("reencrypt: %v", err)
	}
	if updated < 8 {
		t.Fatalf("updated = %d, want at least 8 ciphertext columns", updated)
	}

	if err := cp.ConfigureSecretKeys(newKey); err != nil {
		t.Fatalf("configure new key only: %v", err)
	}

	secret, err := cp.GetAuthProviderSecret(ctx, tenant.ID, "oidc-primary")
	if err != nil || secret != "oidc-client-secret" {
		t.Fatalf("provider secret = %q err=%v", secret, err)
	}
	smtp, err := cp.GetGlobalSMTPDeliveryConfig(ctx)
	if err != nil || smtp.Password != "smtp-password" {
		t.Fatalf("smtp password = %q err=%v", smtp.Password, err)
	}
	admin, err := cp.GetControlPlaneAdmin(ctx)
	if err != nil || admin.TOTPSecret != "JBSWY3DPEHPK3PXP" || admin.TOTPUnreadable {
		t.Fatalf("admin totp = %+v err=%v", admin, err)
	}
	endpointSecret, err := cp.GetTenantNotificationEndpointSecret(ctx, tenant.ID, 1, "webhook")
	if err != nil || endpointSecret != "webhook-secret" {
		t.Fatalf("endpoint secret = %q err=%v", endpointSecret, err)
	}
	notify, err := cp.GetUserNotificationSettings(ctx, tenant.ID, user.UserID)
	if err != nil || notify.MatrixAccessToken != "matrix-token" {
		t.Fatalf("matrix token = %+v err=%v", notify, err)
	}
	var bootstrapCipher string
	if err := cp.db.QueryRowContext(ctx, `SELECT bootstrap_key_ciphertext FROM remote_nodes WHERE id = ?`, node.ID).Scan(&bootstrapCipher); err != nil {
		t.Fatalf("load bootstrap cipher: %v", err)
	}
	gotBootstrap, err := cp.decryptSecret(bootstrapCipher)
	if err != nil || gotBootstrap != bootstrap {
		t.Fatalf("bootstrap = %q want %q err=%v", gotBootstrap, bootstrap, err)
	}
	priv, _, err := cp.GetOrCreateVAPIDKeys(ctx)
	if err != nil || priv == "" {
		t.Fatalf("vapid after rekey: priv=%q err=%v", priv, err)
	}
	subs, err := cp.ListUserPushSubscriptions(ctx, tenant.ID, user.UserID)
	if err != nil || len(subs) != 1 || subs[0].P256dh != "p256dh-value" || subs[0].Auth != "auth-value" {
		t.Fatalf("push subs = %+v err=%v", subs, err)
	}
}

func TestCountDecryptableSecretsDryRun(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer cp.Close()

	oldKey := "old-dry-run-key-1234567890abcdef"
	newKey := "new-dry-run-key-1234567890abcdef"
	if err := cp.ConfigureSecretKeys(oldKey); err != nil {
		t.Fatalf("old key: %v", err)
	}
	if err := cp.CreateControlPlaneAdmin(ctx, "root", "hash"); err != nil {
		t.Fatalf("admin: %v", err)
	}
	if err := cp.SetControlPlaneAdminTOTP(ctx, "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatalf("totp: %v", err)
	}

	if err := cp.ConfigureSecretKeys(newKey, oldKey); err != nil {
		t.Fatalf("new+old: %v", err)
	}
	count, err := cp.CountDecryptableSecrets(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count < 1 {
		t.Fatalf("count = %d", count)
	}
	admin, err := cp.GetControlPlaneAdmin(ctx)
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	// Ciphertext must still be readable via fallback (dry-run did not rewrite).
	var stored string
	if err := cp.db.QueryRowContext(ctx, `SELECT totp_secret_ciphertext FROM control_plane_admins WHERE id = 1`).Scan(&stored); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if stored == "" || admin.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("dry-run mutated or broke secret: stored empty=%v admin=%+v", stored == "", admin)
	}
}
