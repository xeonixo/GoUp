package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"goup/internal/monitor"
)

func TestListMonitorGroupMetadataDoesNotWrite(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	if _, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "A", Group: "Alpha", Kind: monitor.KindTCP, Target: "127.0.0.1:1",
		Interval: time.Minute, Timeout: time.Second, Enabled: true, TLSMode: monitor.TLSModeNone,
	}); err != nil {
		t.Fatalf("create monitor: %v", err)
	}

	before, err := st.ListMonitorGroupMetadata(ctx)
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if len(before) != 1 || before[0].Name != "Alpha" {
		t.Fatalf("groups = %+v", before)
	}

	var updatedAtBefore time.Time
	var sortBefore int
	if err := st.db.QueryRowContext(ctx, `SELECT updated_at, sort_order FROM monitor_groups WHERE name = ?`, "Alpha").Scan(&updatedAtBefore, &sortBefore); err != nil {
		t.Fatalf("read group before: %v", err)
	}
	if _, err := st.ListMonitorGroupMetadata(ctx); err != nil {
		t.Fatalf("list groups again: %v", err)
	}
	var updatedAtAfter time.Time
	var sortAfter int
	if err := st.db.QueryRowContext(ctx, `SELECT updated_at, sort_order FROM monitor_groups WHERE name = ?`, "Alpha").Scan(&updatedAtAfter, &sortAfter); err != nil {
		t.Fatalf("read group after: %v", err)
	}
	if !updatedAtAfter.Equal(updatedAtBefore) || sortAfter != sortBefore {
		t.Fatalf("ListMonitorGroupMetadata mutated group metadata (%v/%d -> %v/%d)", updatedAtBefore, sortBefore, updatedAtAfter, sortAfter)
	}
}

func TestSaveMonitorResultDenormalizesLatestStatus(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Web", Kind: monitor.KindHTTPS, Target: "https://example.com",
		Interval: time.Minute, Timeout: 10 * time.Second, Enabled: true, TLSMode: monitor.TLSModeTLS,
	})
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}

	checked := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := st.SaveMonitorResult(ctx, monitor.Result{
		MonitorID: id, CheckedAt: checked, Status: monitor.StatusUp, Latency: 42 * time.Millisecond, Message: "ok",
	}); err != nil {
		t.Fatalf("save result: %v", err)
	}
	if err := st.SaveMonitorResult(ctx, monitor.Result{
		MonitorID: id, CheckedAt: checked.Add(time.Minute), Status: monitor.StatusDown, Latency: 5 * time.Millisecond, Message: "fail",
	}); err != nil {
		t.Fatalf("save newer result: %v", err)
	}

	snapshots, err := st.ListMonitorSnapshots(ctx)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snapshots) != 1 || snapshots[0].LastResult == nil {
		t.Fatalf("expected snapshot with result, got %+v", snapshots)
	}
	got := snapshots[0].LastResult
	if got.Status != monitor.StatusDown || got.Message != "fail" || got.Latency != 5*time.Millisecond {
		t.Fatalf("denormalized result = %+v", got)
	}

	var lastStatus string
	var lastLatency int
	if err := st.db.QueryRowContext(ctx, `
SELECT last_status, last_latency_ms FROM monitors WHERE id = ?
`, id).Scan(&lastStatus, &lastLatency); err != nil {
		t.Fatalf("read denorm columns: %v", err)
	}
	if lastStatus != "down" || lastLatency != 5 {
		t.Fatalf("monitors.last_* = %s/%d", lastStatus, lastLatency)
	}
}

func TestDashboardRevisionBumpsOnResult(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	before := st.DashboardRevision()
	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Web", Kind: monitor.KindTCP, Target: "127.0.0.1:9",
		Interval: time.Minute, Timeout: time.Second, Enabled: true, TLSMode: monitor.TLSModeNone,
	})
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}
	afterCreate := st.DashboardRevision()
	if afterCreate <= before {
		t.Fatalf("create should bump revision (%d -> %d)", before, afterCreate)
	}
	if err := st.SaveMonitorResult(ctx, monitor.Result{
		MonitorID: id, CheckedAt: time.Now().UTC(), Status: monitor.StatusUp, Latency: time.Millisecond,
	}); err != nil {
		t.Fatalf("save result: %v", err)
	}
	afterResult := st.DashboardRevision()
	if afterResult <= afterCreate {
		t.Fatalf("save result should bump revision (%d -> %d)", afterCreate, afterResult)
	}
}

func TestDailyRollupsWrittenAndListed(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Web", Kind: monitor.KindTCP, Target: "127.0.0.1:9",
		Interval: time.Minute, Timeout: time.Second, Enabled: true, TLSMode: monitor.TLSModeNone,
	})
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}

	day1 := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{day1, day1.Add(time.Hour), day2} {
		if err := st.SaveMonitorResult(ctx, monitor.Result{
			MonitorID: id, CheckedAt: at, Status: monitor.StatusUp, Latency: 10 * time.Millisecond,
		}); err != nil {
			t.Fatalf("save result: %v", err)
		}
	}
	if err := st.SaveMonitorResult(ctx, monitor.Result{
		MonitorID: id, CheckedAt: day2.Add(2 * time.Hour), Status: monitor.StatusDown, Latency: 0,
	}); err != nil {
		t.Fatalf("save down result: %v", err)
	}

	items, err := st.ListMonitorDailyRollupsSince(ctx, day1)
	if err != nil {
		t.Fatalf("list daily rollups: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 daily buckets, got %d (%+v)", len(items), items)
	}
	if items[0].TotalChecks != 2 || items[0].UpChecks != 2 {
		t.Fatalf("day1 rollup = %+v", items[0])
	}
	if items[1].TotalChecks != 2 || items[1].UpChecks != 1 || items[1].DownChecks != 1 {
		t.Fatalf("day2 rollup = %+v", items[1])
	}
}

func TestDashboardStatsFromSnapshots(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	enabledID, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "On", Kind: monitor.KindTCP, Target: "127.0.0.1:1",
		Interval: time.Minute, Timeout: time.Second, Enabled: true, TLSMode: monitor.TLSModeNone,
	})
	if err != nil {
		t.Fatalf("create enabled: %v", err)
	}
	if _, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Off", Kind: monitor.KindTCP, Target: "127.0.0.1:2",
		Interval: time.Minute, Timeout: time.Second, Enabled: false, TLSMode: monitor.TLSModeNone,
	}); err != nil {
		t.Fatalf("create disabled: %v", err)
	}
	if err := st.RecordMonitorState(ctx, enabledID, monitor.StatusDown, "down", time.Now().UTC()); err != nil {
		t.Fatalf("open incident: %v", err)
	}

	snapshots, err := st.ListMonitorSnapshots(ctx)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	stats, err := st.DashboardStatsFromSnapshots(ctx, snapshots)
	if err != nil {
		t.Fatalf("stats from snapshots: %v", err)
	}
	if stats.MonitorCount != 2 || stats.EnabledMonitorCount != 1 || stats.OpenIncidentCount != 1 {
		t.Fatalf("stats = %+v", stats)
	}

	var indexName string
	err = st.db.QueryRowContext(ctx, `
SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_incidents_open'
`).Scan(&indexName)
	if err != nil || indexName != "idx_incidents_open" {
		t.Fatalf("missing open incidents index: %v %q", err, indexName)
	}
}

func TestOpenIncidentsIndexExists(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	plan := explainQueryPlan(t, st, `
SELECT COUNT(*)
FROM incidents i
JOIN monitors m ON m.id = i.monitor_id
WHERE i.resolved_at IS NULL
  AND m.enabled = 1`)
	joined := ""
	for _, line := range plan {
		joined += line + "\n"
	}
	if joined == "" {
		t.Fatal("empty query plan")
	}
}

func TestDailyRollupsReduceTwelveMonthPayload(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Web", Kind: monitor.KindTCP, Target: "127.0.0.1:9",
		Interval: time.Minute, Timeout: time.Second, Enabled: true, TLSMode: monitor.TLSModeNone,
	})
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}

	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for day := 0; day < 60; day++ {
		for hour := 0; hour < 24; hour++ {
			at := now.AddDate(0, 0, -day).Truncate(24 * time.Hour).Add(time.Duration(hour) * time.Hour)
			if err := st.SaveMonitorResult(ctx, monitor.Result{
				MonitorID: id, CheckedAt: at, Status: monitor.StatusUp, Latency: 8 * time.Millisecond,
			}); err != nil {
				t.Fatalf("save result: %v", err)
			}
		}
	}

	since := now.AddDate(0, 0, -59)
	hourly, err := st.ListMonitorHourlyRollupsSince(ctx, since)
	if err != nil {
		t.Fatalf("hourly: %v", err)
	}
	daily, err := st.ListMonitorDailyRollupsSince(ctx, since)
	if err != nil {
		t.Fatalf("daily: %v", err)
	}
	if len(hourly) < 24*50 {
		t.Fatalf("expected dense hourly history, got %d", len(hourly))
	}
	if len(daily) > 61 || len(daily)*10 > len(hourly) {
		t.Fatalf("daily rollups should be far smaller than hourly: daily=%d hourly=%d", len(daily), len(hourly))
	}

	revBefore := st.DashboardRevision()
	if _, err := st.ListMonitorSnapshots(ctx); err != nil {
		t.Fatalf("snapshots: %v", err)
	}
	if _, err := st.ListMonitorGroupMetadata(ctx); err != nil {
		t.Fatalf("groups: %v", err)
	}
	if st.DashboardRevision() != revBefore {
		t.Fatal("read path bumped dashboard revision")
	}
}
