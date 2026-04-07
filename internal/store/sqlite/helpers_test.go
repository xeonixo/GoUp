package sqlite

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizePreferredLanguage(t *testing.T) {
	if got := normalizePreferredLanguage("de-DE"); got != "de" {
		t.Fatalf("got %q", got)
	}
	if got := normalizePreferredLanguage("fr-CA"); got != "fr" {
		t.Fatalf("got %q", got)
	}
	if got := normalizePreferredLanguage(""); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeSMTPMode(t *testing.T) {
	if got := normalizeSMTPMode("TLS"); got != "tls" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeSMTPMode("none"); got != "none" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeSMTPMode("invalid"); got != "starttls" {
		t.Fatalf("got %q", got)
	}
}

func TestSQLiteDSN(t *testing.T) {
	dsn := sqliteDSN("./data/app.db")
	if !strings.HasPrefix(dsn, "file:") {
		t.Fatalf("unexpected dsn: %q", dsn)
	}
	if !strings.Contains(dsn, "foreign_keys") {
		t.Fatalf("dsn missing pragma: %q", dsn)
	}
}

func TestReorderHelpers(t *testing.T) {
	items, ok := reorderStrings([]string{"a", "b", "c"}, "c", "a")
	if !ok || strings.Join(items, ",") != "c,a,b" {
		t.Fatalf("unexpected reorderStrings result: %v ok=%v", items, ok)
	}
	nums, ok := reorderInt64([]int64{1, 2, 3}, 1, 3)
	if !ok || len(nums) != 3 || nums[0] != 2 || nums[1] != 1 || nums[2] != 3 {
		t.Fatalf("unexpected reorderInt64 result: %v ok=%v", nums, ok)
	}
}

func TestBoolHelpers(t *testing.T) {
	if boolToInt(true) != 1 || boolToInt(false) != 0 {
		t.Fatalf("unexpected boolToInt values")
	}
	vTrue := true
	vFalse := false
	if nullableBoolInt(nil) != nil {
		t.Fatalf("nil should map to nil")
	}
	if nullableBoolInt(&vTrue) != 1 {
		t.Fatalf("true should map to 1")
	}
	if nullableBoolInt(&vFalse) != 0 {
		t.Fatalf("false should map to 0")
	}
}

func TestRemoteNodeHelpers(t *testing.T) {
	now := time.Now().UTC()
	seen := now.Add(-30 * time.Second)
	node := RemoteNode{Enabled: true, LastSeenAt: &seen, HeartbeatTimeoutSeconds: 120}
	if !node.IsOnline(now) {
		t.Fatalf("node should be online")
	}
	if node.IsOnline(now.Add(3 * time.Minute)) {
		t.Fatalf("node should be offline")
	}
	if remoteNodeTokenFingerprint(" a ") != remoteNodeTokenFingerprint("a") {
		t.Fatalf("fingerprint should trim input")
	}
}

func TestMaintenanceInterval(t *testing.T) {
	if MaintenanceInterval() <= 0 {
		t.Fatalf("maintenance interval must be positive")
	}
}
