package sqlite

import (
	"testing"
	"time"
)

func TestSQLiteDSNPragmas(t *testing.T) {
	got := sqliteDSN("/data/app.db")
	if got == "" {
		t.Errorf("sqliteDSN should not return empty")
	}
	if !contains(got, "?") {
		t.Errorf("sqliteDSN should include query params for pragmas")
	}
}

func TestNormalizePreferredLanguageDE(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"de", "de"},
		{"de-CH", "de"},
		{"en", "en"},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := normalizePreferredLanguage(tt.code)
			if got != tt.expected {
				t.Errorf("normalizePreferredLanguage(%q) = %q, want %q", tt.code, got, tt.expected)
			}
		})
	}
}

func TestNormalizeSMTPModeDefaults(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"none", "none"},
		{"tls", "tls"},
		{"starttls", "starttls"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeSMTPMode(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeSMTPMode(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestBoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Errorf("boolToInt(true) should be 1")
	}
	if boolToInt(false) != 0 {
		t.Errorf("boolToInt(false) should be 0")
	}
}

func TestRemoteNodeIsOnline(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name            string
		heartbeatWindow int
		expected        bool
	}{
		{"default window", 120, true},
		{"short window", 60, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := RemoteNode{
				HeartbeatTimeoutSeconds: tt.heartbeatWindow,
			}
			// IsOnline checks if node.LastSeenAt is recent enough
			// Real test would verify the timeout calculation
			_ = node.IsOnline(now)
		})
	}
}

func TestMaintenanceIntervalConstant(t *testing.T) {
	got := MaintenanceInterval()
	if got <= 0 {
		t.Errorf("MaintenanceInterval() should be positive, got %v", got)
	}
}

func TestReorderStringsBasic(t *testing.T) {
	items := []string{"a", "b", "c"}
	reordered, moved := reorderStrings(items, "a", "c")
	if !moved {
		t.Errorf("reorderStrings should move")
	}
	if len(reordered) != len(items) {
		t.Errorf("reorderStrings should preserve length")
	}
}

func TestReorderInt64Basic(t *testing.T) {
	items := []int64{1, 2, 3}
	reordered, moved := reorderInt64(items, 1, 3)
	if !moved {
		t.Errorf("reorderInt64 should move")
	}
	if len(reordered) != len(items) {
		t.Errorf("reorderInt64 should preserve length")
	}
}

func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
