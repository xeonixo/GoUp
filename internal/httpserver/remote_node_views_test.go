package httpserver

import (
	"strings"
	"testing"
	"time"

	store "goup/internal/store/sqlite"
)

func TestBuildMonitorExecutorOptionsOnlineOffline(t *testing.T) {
	now := time.Now().UTC()
	seen := now.Add(-30 * time.Second)
	stale := now.Add(-10 * time.Minute)
	nodes := []store.RemoteNode{
		{NodeID: "rn_online", Name: "Edge A", Enabled: true, HeartbeatTimeoutSeconds: 120, LastSeenAt: &seen},
		{NodeID: "rn_offline", Name: "Edge B", Enabled: true, HeartbeatTimeoutSeconds: 120, LastSeenAt: &stale},
	}
	options := buildMonitorExecutorOptions(nodes, now, "Control plane (local)", "ONLINE", "OFFLINE")
	if len(options) != 3 {
		t.Fatalf("options len = %d", len(options))
	}
	if options[0].Value != "local" || !options[0].Online || options[0].Label != "Control plane (local)" {
		t.Fatalf("local option = %+v", options[0])
	}
	if options[1].Value != "remote:rn_online" || !options[1].Online || !strings.Contains(options[1].Label, "ONLINE") {
		t.Fatalf("online option = %+v", options[1])
	}
	if options[2].Value != "remote:rn_offline" || options[2].Online || !strings.Contains(options[2].Label, "OFFLINE") {
		t.Fatalf("offline option = %+v", options[2])
	}
}
