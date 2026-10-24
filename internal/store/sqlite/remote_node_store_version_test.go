package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeRemoteNodeAgentVersion(t *testing.T) {
	cases := map[string]string{
		"  v1.2.3 ":             "v1.2.3",
		"dev":                   "dev",
		"":                      "",
		"v1.2\n3":               "",
		"bad version":           "",
		strings.Repeat("a", 64): strings.Repeat("a", 64),
		strings.Repeat("a", 65): "",
		"v1.\x00":               "",
		"v1.2.3-é":              "",
	}
	for in, want := range cases {
		if got := NormalizeRemoteNodeAgentVersion(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRemoteNodeAgentVersionPersists(t *testing.T) {
	ctx := context.Background()
	cp, dir := openTestControlPlane(t)
	if err := cp.ConfigureSecretKey("test-secret-key-for-node-version"); err != nil {
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
	if node.AgentVersion != "" || node.AgentVersionSeenAt != nil {
		t.Fatalf("new node has version %q / %v", node.AgentVersion, node.AgentVersionSeenAt)
	}
	seen := time.Now().UTC().Truncate(time.Second)
	if err := cp.UpdateRemoteNodeAgentVersion(ctx, node.ID, " v1.4.0 ", seen); err != nil {
		t.Fatalf("update: %v", err)
	}
	nodes, err := cp.ListRemoteNodesByTenant(ctx, tenant.ID)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("list: %v %d", err, len(nodes))
	}
	if nodes[0].AgentVersion != "v1.4.0" || nodes[0].AgentVersionSeenAt == nil || !nodes[0].AgentVersionSeenAt.Equal(seen) {
		t.Fatalf("unexpected version state: %q %v", nodes[0].AgentVersion, nodes[0].AgentVersionSeenAt)
	}
	// Re-running the schema setup (migration path) must be idempotent.
	if err := cp.ensureRemoteNodesTable(ctx); err != nil {
		t.Fatalf("re-ensure table: %v", err)
	}
}
