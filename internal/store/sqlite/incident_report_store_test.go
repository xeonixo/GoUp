package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"goup/internal/monitor"
)

func TestListIncidentsStartedSince(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	monID, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "api", Kind: monitor.KindHTTPS, Target: "https://example.com/health",
		Interval: time.Minute, Timeout: 5 * time.Second, Enabled: true, TLSMode: monitor.TLSModeTLS,
	})
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}

	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	resolved := start.Add(15 * time.Minute)
	if _, err := st.db.ExecContext(ctx, `
INSERT INTO incidents (monitor_id, started_at, resolved_at, cause, last_state)
VALUES (?, ?, ?, 'x', 'down'), (?, ?, NULL, 'y', 'down'), (?, ?, NULL, 'old', 'down')
`, monID, start, resolved, monID, start.Add(time.Hour), monID, start.Add(-48*time.Hour)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	items, err := st.ListIncidentsStartedSince(ctx, start.Add(-time.Minute))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d incidents, want 2 (excluding older)", len(items))
	}
	if items[0].ResolvedAt == nil || items[1].ResolvedAt != nil {
		t.Fatalf("unexpected resolve state: %+v %+v", items[0], items[1])
	}
}
