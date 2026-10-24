package httpserver

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	store "goup/internal/store/sqlite"
	"goup/internal/version"
)

func TestRemoteNodeVersionState(t *testing.T) {
	cases := []struct{ node, server, want string }{
		{"", "v1.2.0", "unknown"},
		{"", "dev", "unknown"},
		{"v1.2.0", "v1.2.0", "current"},
		{"v1.1.9", "v1.2.0", "outdated"},
		{"v0.9.9", "v1.0.0", "outdated"},
		{"v1.10.0", "v1.9.0", "current"},
		{"v1.9.0", "v1.10.0", "outdated"},
		{"v2.0.0", "v1.9.9", "current"},
		{"1.2.0", "v1.2.1", "outdated"},
		{"v1.2.0", "dev", "unknown"},
		{"dev", "v1.2.0", "unknown"},
		{"dev", "dev", "current"},
		{"remote-node/0.1", "v1.2.0", "unknown"},
		{"v1.2", "v1.2.0", "unknown"},
	}
	for _, c := range cases {
		if got := remoteNodeVersionState(c.node, c.server); got != c.want {
			t.Errorf("state(%q, %q) = %q, want %q", c.node, c.server, got, c.want)
		}
	}
}

func TestRemoteNodeVersionSummary(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	if err := cp.ConfigureSecretKey("test-secret-key-for-node-version"); err != nil {
		t.Fatal(err)
	}
	t1, err := cp.CreateTenant(ctx, "tenant-a", "A", filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t2, err := cp.CreateTenant(ctx, "tenant-b", "B", filepath.Join(dir, "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	old := version.Version
	version.Version = "v1.5.0"
	defer func() { version.Version = old }()

	mk := func(tenantID int64, name, agent string, online bool) {
		node, _, err := cp.CreateRemoteNode(ctx, tenantID, name, 120)
		if err != nil {
			t.Fatal(err)
		}
		if agent != "" {
			if err := cp.UpdateRemoteNodeAgentVersion(ctx, node.ID, agent, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		if online {
			if err := cp.TouchRemoteNodeLastSeen(ctx, node.ID, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk(t1.ID, "n1", "v1.4.0", true)
	mk(t1.ID, "n2", "v1.5.0", false)
	mk(t2.ID, "n3", "", true)

	s := &Server{controlStore: cp}
	all, err := s.remoteNodeVersionSummary(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := (remoteNodeVersionSummaryResult{Total: 3, Online: 2, Offline: 1, Outdated: 1}); all != want {
		t.Fatalf("global = %+v, want %+v", all, want)
	}
	one, err := s.remoteNodeVersionSummary(ctx, t2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := (remoteNodeVersionSummaryResult{Total: 1, Online: 1}); one != want {
		t.Fatalf("tenant = %+v, want %+v", one, want)
	}
}
