package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/monitor"
)

func TestLatestResultIndexSeeksInsteadOfSortingHistory(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	indexes := monitorResultIndexes(t, st)
	if _, ok := indexes["idx_monitor_results_latest"]; !ok {
		t.Fatalf("missing latest-result index, got %v", indexes)
	}
	if _, ok := indexes["idx_monitor_results_monitor_checked_at"]; ok {
		t.Fatal("redundant checked_at index still present; every insert would maintain it")
	}
	if !strings.Contains(strings.ToLower(indexes["idx_monitor_results_latest"]), "id") {
		t.Fatalf("latest index must include id for a stable tie break, sql=%s", indexes["idx_monitor_results_latest"])
	}

	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Web", Kind: monitor.KindHTTPS, Target: "https://example.com", Interval: time.Minute,
		Timeout: 10 * time.Second, Enabled: true, TLSMode: monitor.TLSModeTLS,
	})
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 40; i++ {
		if err := st.SaveMonitorResult(ctx, monitor.Result{
			MonitorID: id,
			CheckedAt: base.Add(time.Duration(i) * 15 * time.Second),
			Status:    monitor.StatusUp,
			Latency:   20 * time.Millisecond,
			Message:   "old",
		}); err != nil {
			t.Fatalf("save historical result: %v", err)
		}
	}
	// Retries store the same checked_at. The highest id is the latest result.
	tied := base.Add(time.Hour)
	if err := st.SaveMonitorResult(ctx, monitor.Result{
		MonitorID: id, CheckedAt: tied, Status: monitor.StatusUp, Latency: time.Millisecond, Message: "first",
	}); err != nil {
		t.Fatalf("save tied result: %v", err)
	}
	if err := st.SaveMonitorResult(ctx, monitor.Result{
		MonitorID: id, CheckedAt: tied, Status: monitor.StatusDown, Latency: 2 * time.Millisecond, Message: "second",
	}); err != nil {
		t.Fatalf("save newer tied result: %v", err)
	}

	snapshots, err := st.ListMonitorSnapshots(ctx)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snapshots) != 1 || snapshots[0].LastResult == nil {
		t.Fatalf("expected one snapshot with a result, got %+v", snapshots)
	}
	if snapshots[0].LastResult.Status != monitor.StatusDown || snapshots[0].LastResult.Message != "second" {
		t.Fatalf("snapshot kept %s (%q), want the higher id", snapshots[0].LastResult.Status, snapshots[0].LastResult.Message)
	}

	statuses, err := st.RecentMonitorStatuses(ctx, id, 2)
	if err != nil {
		t.Fatalf("recent statuses: %v", err)
	}
	if len(statuses) != 2 || statuses[0] != monitor.StatusDown || statuses[1] != monitor.StatusUp {
		t.Fatalf("recent statuses = %v, want [down up]", statuses)
	}

	statusPlan := explainQueryPlan(t, st, `
SELECT status FROM monitor_results WHERE monitor_id = ? ORDER BY checked_at DESC, id DESC LIMIT 2`, id)
	assertLatestResultSeek(t, statusPlan)

	snapshotPlan := explainQueryPlan(t, st, monitorSnapshotSelect+`ORDER BY m.sort_order ASC, m.id ASC`)
	joined := strings.Join(snapshotPlan, "\n")
	if strings.Contains(joined, "monitor_results") {
		t.Fatalf("snapshot query must read denormalized last_* columns, not monitor_results:\n%s", joined)
	}
}

// assertLatestResultSeek fails when finding the newest rows sorts or scans
// monitor_results. Ordering the small monitors table is a separate step and is fine.
func assertLatestResultSeek(t *testing.T, plan []string) {
	t.Helper()
	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, "idx_monitor_results_latest") {
		t.Fatalf("plan does not use the latest-result index:\n%s", joined)
	}
	if strings.Contains(joined, "LAST TERM") {
		t.Fatalf("plan still sorts every historical row to break checked_at ties:\n%s", joined)
	}
	for _, detail := range plan {
		if strings.Contains(detail, "SCAN monitor_results") || strings.Contains(detail, "SCAN mr") {
			t.Fatalf("plan scans monitor_results:\n%s", joined)
		}
	}
}

func TestLatestResultIndexReplacesLegacyIndex(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := raw.Exec(`
CREATE TABLE monitor_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    checked_at DATETIME NOT NULL,
    status TEXT NOT NULL
);
CREATE INDEX idx_monitor_results_monitor_checked_at
ON monitor_results(monitor_id, checked_at DESC);
INSERT INTO monitor_results (monitor_id, checked_at, status) VALUES (1, '2026-01-01T00:00:00Z', 'up');
`); err != nil {
		t.Fatalf("seed legacy db: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	defer st.Close()

	indexes := monitorResultIndexes(t, st)
	if _, ok := indexes["idx_monitor_results_latest"]; !ok {
		t.Fatalf("migration did not create the latest index, got %v", indexes)
	}
	if _, ok := indexes["idx_monitor_results_monitor_checked_at"]; ok {
		t.Fatal("migration left the redundant index in place")
	}
	var tempDir string
	if err := st.db.QueryRow(`PRAGMA temp_store_directory`).Scan(&tempDir); err != nil {
		t.Fatalf("read temp directory: %v", err)
	}
	if tempDir != filepath.Dir(path) {
		t.Fatalf("temp directory = %q, want the database directory %q", tempDir, filepath.Dir(path))
	}

	var status string
	if err := st.db.QueryRowContext(ctx, `
SELECT status FROM monitor_results WHERE monitor_id = ? ORDER BY checked_at DESC, id DESC LIMIT 1
`, 1).Scan(&status); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if status != "up" {
		t.Fatalf("status = %q", status)
	}
	for _, detail := range explainQueryPlan(t, st, `
SELECT status FROM monitor_results WHERE monitor_id = ? ORDER BY checked_at DESC, id DESC LIMIT 1`, 1) {
		if strings.Contains(detail, "TEMP B-TREE") {
			t.Fatalf("migrated database still sorts history: %s", detail)
		}
	}
}

func monitorResultIndexes(t *testing.T, st *Store) map[string]string {
	t.Helper()
	rows, err := st.db.Query(`SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE type = 'index' AND tbl_name = 'monitor_results'`)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, sqlText string
		if err := rows.Scan(&name, &sqlText); err != nil {
			t.Fatalf("scan index: %v", err)
		}
		out[name] = sqlText
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate indexes: %v", err)
	}
	return out
}

func explainQueryPlan(t *testing.T, st *Store, query string, args ...any) []string {
	t.Helper()
	rows, err := st.db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, query)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan explain: %v", err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate explain: %v", err)
	}
	if len(details) == 0 {
		t.Fatalf("empty query plan for %s", query)
	}
	return details
}
