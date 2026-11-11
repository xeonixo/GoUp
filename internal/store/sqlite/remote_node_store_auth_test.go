package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthenticateRemoteNodeAccessToken(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	if err := cp.ConfigureSecretKey("test-secret-key-for-node-auth"); err != nil {
		t.Fatal(err)
	}
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	node, _, err := cp.CreateRemoteNode(ctx, tenant.ID, "edge", 120)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	seen := time.Now().UTC().Truncate(time.Second)
	if err := cp.UpdateRemoteNodeAgentVersion(ctx, node.ID, "v1.4.0", seen); err != nil {
		t.Fatalf("set agent version: %v", err)
	}

	token, expiresAt, err := cp.IssueRemoteNodeAccessToken(ctx, node.ID, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	if token == "" || expiresAt.Before(time.Now().UTC()) {
		t.Fatalf("unexpected token/expiry: %q %v", token, expiresAt)
	}

	got, err := cp.AuthenticateRemoteNodeAccessToken(ctx, token)
	if err != nil {
		t.Fatalf("authenticate access token: %v", err)
	}
	if got.ID != node.ID || got.NodeID != node.NodeID || got.TenantID != tenant.ID {
		t.Fatalf("authenticated node mismatch: %+v", got)
	}
	if got.AgentVersion != "v1.4.0" {
		t.Fatalf("agent version = %q, want v1.4.0", got.AgentVersion)
	}
	if got.AgentVersionSeenAt == nil || !got.AgentVersionSeenAt.Equal(seen) {
		t.Fatalf("agent version seen at = %v, want %v", got.AgentVersionSeenAt, seen)
	}

	if _, err := cp.AuthenticateRemoteNodeAccessToken(ctx, "not-the-token"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("wrong token error = %v, want sql.ErrNoRows", err)
	}
}

func TestRemoteNodeAccessTokenGraceAcceptsPreviousToken(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	if err := cp.ConfigureSecretKey("test-secret-key-for-node-auth-grace"); err != nil {
		t.Fatal(err)
	}
	tenant, err := cp.CreateTenant(ctx, "grace", "Grace", filepath.Join(dir, "grace.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	node, _, err := cp.CreateRemoteNode(ctx, tenant.ID, "edge-grace", 120)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	oldToken, _, err := cp.IssueRemoteNodeAccessToken(ctx, node.ID, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue first token: %v", err)
	}
	newToken, _, err := cp.IssueRemoteNodeAccessToken(ctx, node.ID, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue rotated token: %v", err)
	}
	if oldToken == newToken {
		t.Fatal("expected rotated token to differ")
	}

	if _, err := cp.AuthenticateRemoteNodeAccessToken(ctx, newToken); err != nil {
		t.Fatalf("authenticate current token: %v", err)
	}
	if _, err := cp.AuthenticateRemoteNodeAccessToken(ctx, oldToken); err != nil {
		t.Fatalf("authenticate previous token during grace: %v", err)
	}

	_, err = cp.db.ExecContext(ctx, `
UPDATE remote_nodes
SET previous_access_token_expires_at = ?
WHERE id = ?
`, time.Now().UTC().Add(-time.Second), node.ID)
	if err != nil {
		t.Fatalf("expire previous token: %v", err)
	}
	if _, err := cp.AuthenticateRemoteNodeAccessToken(ctx, oldToken); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expired previous token error = %v, want sql.ErrNoRows", err)
	}
}
