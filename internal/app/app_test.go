package app

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	if got := parseLogLevel("debug"); got != slog.LevelDebug {
		t.Fatalf("debug => %v", got)
	}
	if got := parseLogLevel("warn"); got != slog.LevelWarn {
		t.Fatalf("warn => %v", got)
	}
	if got := parseLogLevel("error"); got != slog.LevelError {
		t.Fatalf("error => %v", got)
	}
	if got := parseLogLevel("unknown"); got != slog.LevelInfo {
		t.Fatalf("unknown => %v", got)
	}
}

func TestTenantHasAppDatabase(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "tenant.db")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if !tenantHasAppDatabase(filePath) {
		t.Fatalf("expected file path to be recognized as database")
	}
	if tenantHasAppDatabase(tempDir) {
		t.Fatalf("directory must not be recognized as database")
	}
	if tenantHasAppDatabase(filepath.Join(tempDir, "missing.db")) {
		t.Fatalf("missing file must not be recognized as database")
	}
}
