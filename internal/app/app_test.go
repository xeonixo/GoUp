package app

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
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

func TestMarkRemoteNodeMonitorsUnknown(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	appStore, err := store.Open(ctx, filepath.Join(dir, "tenant.db"))
	if err != nil {
		t.Fatalf("open tenant store: %v", err)
	}
	defer appStore.Close()

	monitorID, err := appStore.CreateMonitor(ctx, store.CreateMonitorParams{
		Name:         "Remote HTTPS",
		ExecutorKind: "remote",
		ExecutorRef:  "rn_test",
		Kind:         monitor.KindHTTPS,
		Target:       "https://example.com",
		Interval:     time.Minute,
		Timeout:      5 * time.Second,
		Enabled:      true,
		TLSMode:      monitor.TLSModeTLS,
	})
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}
	checkedAt := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	if err := appStore.SaveMonitorResult(ctx, monitor.Result{
		MonitorID: monitorID,
		CheckedAt: checkedAt.Add(-time.Minute),
		Status:    monitor.StatusUp,
		Message:   "ok",
	}); err != nil {
		t.Fatalf("save initial result: %v", err)
	}
	if err := appStore.RecordMonitorState(ctx, monitorID, monitor.StatusUp, "ok", checkedAt.Add(-time.Minute)); err != nil {
		t.Fatalf("record initial state: %v", err)
	}

	a := &App{logger: slog.New(slog.NewTextHandler(os.Stdout, nil))}
	a.markRemoteNodeMonitorsUnknown(ctx, appStore, store.RemoteNode{
		TenantID: 1,
		NodeID:   "rn_test",
		Name:     "Remote Test",
	}, checkedAt)

	snapshots, err := appStore.ListMonitorSnapshots(ctx)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snapshots) != 1 || snapshots[0].LastResult == nil {
		t.Fatalf("unexpected snapshots: %#v", snapshots)
	}
	if got := snapshots[0].LastResult.Status; got != monitor.StatusUnknown {
		t.Fatalf("last status = %q, want %q", got, monitor.StatusUnknown)
	}
}
