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

	var ciphertext, fingerprint string
	if err := cp.db.QueryRowContext(ctx, `
SELECT access_token_ciphertext, access_token_fingerprint FROM remote_nodes WHERE id = ?
`, node.ID).Scan(&ciphertext, &fingerprint); err != nil {
		t.Fatalf("load issued token material: %v", err)
	}
	if ciphertext != "" {
		t.Fatalf("expected empty access token ciphertext, got %q", ciphertext)
	}
	if fingerprint != remoteNodeTokenFingerprint(token) {
		t.Fatalf("fingerprint = %q, want %q", fingerprint, remoteNodeTokenFingerprint(token))
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

	var (
		currentCipher, previousCipher string
		currentFP, previousFP         string
	)
	if err := cp.db.QueryRowContext(ctx, `
SELECT access_token_ciphertext, access_token_fingerprint,
	previous_access_token_ciphertext, previous_access_token_fingerprint
FROM remote_nodes WHERE id = ?
`, node.ID).Scan(&currentCipher, &currentFP, &previousCipher, &previousFP); err != nil {
		t.Fatalf("load rotated token material: %v", err)
	}
	if currentCipher != "" || previousCipher != "" {
		t.Fatalf("expected empty ciphertexts, got current=%q previous=%q", currentCipher, previousCipher)
	}
	if currentFP != remoteNodeTokenFingerprint(newToken) {
		t.Fatalf("current fingerprint = %q, want %q", currentFP, remoteNodeTokenFingerprint(newToken))
	}
	if previousFP != remoteNodeTokenFingerprint(oldToken) {
		t.Fatalf("previous fingerprint = %q, want %q", previousFP, remoteNodeTokenFingerprint(oldToken))
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

func TestAuthenticateRemoteNodeBootstrapFingerprint(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	tenant, err := cp.CreateTenant(ctx, "boot", "Boot", filepath.Join(dir, "boot.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	node, bootstrapKey, err := cp.CreateRemoteNode(ctx, tenant.ID, "edge-boot", 120)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	var ciphertext, fingerprint string
	if err := cp.db.QueryRowContext(ctx, `
SELECT bootstrap_key_ciphertext, bootstrap_key_fingerprint FROM remote_nodes WHERE id = ?
`, node.ID).Scan(&ciphertext, &fingerprint); err != nil {
		t.Fatalf("load bootstrap material: %v", err)
	}
	if ciphertext != "" {
		t.Fatalf("expected empty bootstrap ciphertext, got %q", ciphertext)
	}
	if fingerprint != remoteNodeTokenFingerprint(bootstrapKey) {
		t.Fatalf("bootstrap fingerprint = %q, want %q", fingerprint, remoteNodeTokenFingerprint(bootstrapKey))
	}

	got, err := cp.AuthenticateRemoteNodeBootstrap(ctx, node.NodeID, bootstrapKey)
	if err != nil {
		t.Fatalf("authenticate bootstrap: %v", err)
	}
	if got.ID != node.ID {
		t.Fatalf("authenticated node = %+v, want id %d", got, node.ID)
	}
	if _, err := cp.AuthenticateRemoteNodeBootstrap(ctx, node.NodeID, "wrong-key"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("wrong bootstrap error = %v, want sql.ErrNoRows", err)
	}

	rotated, err := cp.RotateRemoteNodeBootstrapKey(ctx, tenant.ID, node.NodeID)
	if err != nil {
		t.Fatalf("rotate bootstrap: %v", err)
	}
	if rotated == bootstrapKey {
		t.Fatal("expected rotated bootstrap key to differ")
	}
	if _, err := cp.AuthenticateRemoteNodeBootstrap(ctx, node.NodeID, bootstrapKey); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old bootstrap should fail after rotate: %v", err)
	}
	if _, err := cp.AuthenticateRemoteNodeBootstrap(ctx, node.NodeID, rotated); err != nil {
		t.Fatalf("authenticate rotated bootstrap: %v", err)
	}
}

func TestAuthenticateRemoteNodeAccessTokenLegacyCiphertext(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	if err := cp.ConfigureSecretKey("test-secret-key-for-legacy-token"); err != nil {
		t.Fatal(err)
	}
	tenant, err := cp.CreateTenant(ctx, "legacy", "Legacy", filepath.Join(dir, "legacy.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	node, _, err := cp.CreateRemoteNode(ctx, tenant.ID, "edge-legacy", 120)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	legacyToken := "legacy-access-token-value"
	sealed, err := encryptProviderSecret(cp.secretKey, legacyToken)
	if err != nil {
		t.Fatalf("encrypt legacy token: %v", err)
	}
	expires := time.Now().UTC().Add(5 * time.Minute)
	_, err = cp.db.ExecContext(ctx, `
UPDATE remote_nodes
SET access_token_ciphertext = ?,
	access_token_fingerprint = ?,
	access_token_expires_at = ?
WHERE id = ?
`, sealed, remoteNodeTokenFingerprint(legacyToken), expires, node.ID)
	if err != nil {
		t.Fatalf("seed legacy token: %v", err)
	}

	got, err := cp.AuthenticateRemoteNodeAccessToken(ctx, legacyToken)
	if err != nil {
		t.Fatalf("authenticate legacy ciphertext token: %v", err)
	}
	if got.ID != node.ID {
		t.Fatalf("authenticated node = %+v, want id %d", got, node.ID)
	}
}

func TestAuthenticateRemoteNodeBootstrapLegacyCiphertext(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	if err := cp.ConfigureSecretKey("test-secret-key-for-legacy-boot"); err != nil {
		t.Fatal(err)
	}
	tenant, err := cp.CreateTenant(ctx, "legacyboot", "LegacyBoot", filepath.Join(dir, "legacyboot.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	node, _, err := cp.CreateRemoteNode(ctx, tenant.ID, "edge-legacy-boot", 120)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}

	legacyKey := "legacy-bootstrap-key-value"
	sealed, err := encryptProviderSecret(cp.secretKey, legacyKey)
	if err != nil {
		t.Fatalf("encrypt legacy bootstrap: %v", err)
	}
	_, err = cp.db.ExecContext(ctx, `
UPDATE remote_nodes
SET bootstrap_key_ciphertext = ?, bootstrap_key_fingerprint = ''
WHERE id = ?
`, sealed, node.ID)
	if err != nil {
		t.Fatalf("seed legacy bootstrap: %v", err)
	}

	got, err := cp.AuthenticateRemoteNodeBootstrap(ctx, node.NodeID, legacyKey)
	if err != nil {
		t.Fatalf("authenticate legacy bootstrap: %v", err)
	}
	if got.ID != node.ID {
		t.Fatalf("authenticated node = %+v, want id %d", got, node.ID)
	}
}
