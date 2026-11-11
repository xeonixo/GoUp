package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestTenantNotificationEndpointSecretRotateGrace(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	if err := cp.ConfigureSecretKey("test-secret-key-for-webhook-rotate"); err != nil {
		t.Fatal(err)
	}
	tenant, err := cp.CreateTenant(ctx, "hooks", "Hooks", filepath.Join(dir, "tenant.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	if err := cp.SaveTenantNotificationEndpointSecret(ctx, tenant.ID, 9, "webhook", "first-secret-value"); err != nil {
		t.Fatalf("save first secret: %v", err)
	}
	first, err := cp.GetTenantNotificationEndpointSigningSecrets(ctx, tenant.ID, 9, "webhook")
	if err != nil || first.Current != "first-secret-value" || first.PreviousGraceActive {
		t.Fatalf("first secrets = %+v err=%v", first, err)
	}

	if err := cp.SaveTenantNotificationEndpointSecret(ctx, tenant.ID, 9, "webhook", "second-secret-value"); err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	rotated, err := cp.GetTenantNotificationEndpointSigningSecrets(ctx, tenant.ID, 9, "webhook")
	if err != nil {
		t.Fatalf("load rotated secrets: %v", err)
	}
	if rotated.Current != "second-secret-value" {
		t.Fatalf("current = %q", rotated.Current)
	}
	if !rotated.PreviousGraceActive || rotated.Previous != "first-secret-value" {
		t.Fatalf("previous grace missing: %+v", rotated)
	}
	if rotated.PreviousExpiresAt == nil {
		t.Fatalf("expected previous expires_at")
	}
	grace := rotated.PreviousExpiresAt.Sub(time.Now().UTC())
	if grace < 23*time.Hour || grace > 25*time.Hour {
		t.Fatalf("unexpected grace window remaining: %v", grace)
	}

	currentOnly, err := cp.GetTenantNotificationEndpointSecret(ctx, tenant.ID, 9, "webhook")
	if err != nil || currentOnly != "second-secret-value" {
		t.Fatalf("current-only getter = %q err=%v", currentOnly, err)
	}
}
