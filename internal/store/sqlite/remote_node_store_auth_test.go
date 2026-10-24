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
