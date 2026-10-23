package httpserver

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/config"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

func TestUptimeFormattingTruncatesToTwoDecimals(t *testing.T) {
	for _, tc := range []struct {
		up, effective int
		want          string
	}{
		{9995, 10000, "99.95%"},
		{9999, 10000, "99.99%"},
		{99999, 100000, "99.99%"}, // never rounds up to a perfect 100.00%
		{1, 3, "33.33%"},
		{2, 3, "66.66%"},
		{3, 3, "100.00%"},
		{0, 5, "0.00%"},
		{0, 0, "0.00%"},
	} {
		if got := formatUptimePercent(tc.up, tc.effective); got != tc.want {
			t.Errorf("formatUptimePercent(%d, %d) = %q, want %q", tc.up, tc.effective, got, tc.want)
		}
	}
}

func rollupFor(hour time.Time, up, down, unknown int) store.MonitorHourlyRollup {
	return store.MonitorHourlyRollup{
		MonitorID: 1, HourBucket: hour,
		TotalChecks: up + down + unknown, UpChecks: up, DownChecks: down, UnknownChecks: unknown,
		LatencySumMS: up * 100, LatencyMinMS: 100, LatencyMaxMS: 100,
	}
}

func TestTrendPointsExcludeUnknownFromDenominator(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 30, 0, 0, time.UTC)
	trend := supportedTrendRanges[0] // 24h, hourly buckets
	rollups := []store.MonitorHourlyRollup{
		rollupFor(now.Truncate(time.Hour), 1, 0, 9),                      // only 1 of 1 real checks
		rollupFor(now.Truncate(time.Hour).Add(-time.Hour), 0, 0, 10),     // only unknown: no data
		rollupFor(now.Truncate(time.Hour).Add(-2*time.Hour), 3999, 1, 0), // 99.97%
	}
	points := buildTrendPoints(rollups, now, trend)
	last := points[len(points)-1]
	if last.Class != "trend-up" || last.Percent != 100 || last.EffectiveChecks != 1 || last.Checks != 10 {
		t.Fatalf("unknown checks must not lower uptime: %+v", last)
	}
	if points[len(points)-2].Class != "trend-none" {
		t.Fatalf("a bucket with only unknown checks has no data: %+v", points[len(points)-2])
	}
	third := points[len(points)-3]
	if third.Percent != 99.97 || !strings.HasPrefix(third.Label, "99.97% Uptime") {
		t.Fatalf("expected 99.97%%, got %v label %q", third.Percent, third.Label)
	}
}

func TestSummariesAreWeightedByCheckCounts(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 30, 0, 0, time.UTC)
	trend := supportedTrendRanges[0]
	// One busy hour with 1 failure in 1000 checks, one tiny hour that is fully down.
	rollups := []store.MonitorHourlyRollup{
		rollupFor(now.Truncate(time.Hour).Add(-time.Hour), 999, 1, 0),
		rollupFor(now.Truncate(time.Hour), 0, 1, 0),
	}
	points := buildTrendPoints(rollups, now, trend)
	got := summarizeTrend(points, trend)
	// Weighted: 999 / 1001 = 99.80%; an average of percentages would give about 49.95%.
	if got != "99.80% Uptime / 24h" {
		t.Fatalf("summary = %q, want weighted 99.80%%", got)
	}

	// Group level: two monitors with very different volume.
	busy := monitorView{TrendPoints: buildTrendPoints([]store.MonitorHourlyRollup{rollupFor(now.Truncate(time.Hour), 9990, 10, 0)}, now, trend)}
	small := monitorView{TrendPoints: buildTrendPoints([]store.MonitorHourlyRollup{rollupFor(now.Truncate(time.Hour), 0, 10, 0)}, now, trend)}
	aggregate := aggregateServiceTrendPoints([]monitorView{busy, small})
	if label := summarizeTrendPoints(aggregate); label != "99.80% Uptime" {
		t.Fatalf("group summary = %q, want 99.80%% (9990 of 10010 checks)", label)
	}
	lastAggregate := aggregate[len(aggregate)-1]
	if lastAggregate.UpChecks != 9990 || lastAggregate.EffectiveChecks != 10010 || lastAggregate.Class != "trend-degraded" {
		t.Fatalf("aggregate bucket not built from raw counts: %+v", lastAggregate)
	}
}

func TestDetailTilesAgreeWithSummaries(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 30, 0, 0, time.UTC)
	rollups := []store.MonitorHourlyRollup{
		rollupFor(now.Truncate(time.Hour).Add(-time.Hour), 999, 1, 5),
		rollupFor(now.Truncate(time.Hour), 1000, 0, 0),
	}
	tiles := buildUptimeTiles(rollups, now, map[string]string{})
	if tiles[0].Percent != "99.95%" || tiles[0].Checks != 2000 {
		t.Fatalf("24h tile = %+v, want 99.95%% over 2000 effective checks", tiles[0])
	}
	trend := supportedTrendRanges[0]
	if summary := summarizeTrend(buildTrendPoints(rollups, now, trend), trend); summary != "99.95% Uptime / 24h" {
		t.Fatalf("summary %q disagrees with tile %q", summary, tiles[0].Percent)
	}
}

func TestPercentileLatency(t *testing.T) {
	if _, ok := percentileLatency(nil, 95); ok {
		t.Fatalf("empty input must report no percentile")
	}
	values := make([]int, 0, 100)
	for i := 100; i >= 1; i-- {
		values = append(values, i)
	}
	if got, _ := percentileLatency(values, 95); got != 95 {
		t.Fatalf("p95 = %d, want 95", got)
	}
	if got, _ := percentileLatency([]int{42}, 95); got != 42 {
		t.Fatalf("p95 of one value = %d", got)
	}
}

// The remote-node report path must use the shared dispatcher: webhook endpoints are notified
// and failed deliveries land in the persistent retry queue, exactly like the local runner.
func TestRemoteNodeDispatcherUsesWebhooksAndRetryQueue(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	appStore, err := store.Open(ctx, filepath.Join(dir, "acme.db"))
	if err != nil {
		t.Fatalf("open tenant store: %v", err)
	}
	defer appStore.Close()

	// Loopback is rejected by the webhook URL guard, so delivery fails deterministically.
	if _, err := appStore.UpsertWebhookEndpoint(ctx, store.WebhookEndpoint{Name: "Hook", Enabled: true, URL: "https://127.0.0.1:9/hook"}); err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	monitorID, err := appStore.CreateMonitor(ctx, store.CreateMonitorParams{
		Name: "Remote", Kind: monitor.KindTCP, Target: "example.com:443", Interval: time.Minute, Timeout: 5 * time.Second,
		Enabled: true, NotifyOnRecovery: true, ExecutorKind: "remote", ExecutorRef: "node-1",
	})
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}

	srv := &Server{
		cfg:          config.Config{BaseURL: "https://goup.example"},
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		controlStore: cp,
	}
	dispatcher := srv.remoteNodeDispatcher(ctx, appStore, tenant.ID)

	assigned, err := appStore.ListMonitorsByExecutor(ctx, "remote", "node-1")
	if err != nil || len(assigned) != 1 {
		t.Fatalf("list assigned: %v (%d)", err, len(assigned))
	}
	previous := monitor.Result{MonitorID: monitorID, Status: monitor.StatusUp, CheckedAt: time.Now().UTC().Add(-time.Minute)}
	if err := appStore.SaveMonitorResult(ctx, previous); err != nil {
		t.Fatalf("save previous: %v", err)
	}
	result := monitor.Result{MonitorID: monitorID, Status: monitor.StatusDown, CheckedAt: time.Now().UTC(), Message: "refused"}
	if !dispatcher.ProcessResult(ctx, monitor.Snapshot{Monitor: assigned[0], LastResult: &previous}, result) {
		t.Fatalf("ProcessResult reported failure")
	}

	events, err := appStore.ListRecentNotificationEvents(ctx, 10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	webhookEvents := 0
	for _, event := range events {
		if strings.HasSuffix(event.EventType, "webhook") {
			webhookEvents++
			if event.DeliveredAt != nil || event.Error == "" {
				t.Fatalf("expected a failed webhook delivery, got %+v", event)
			}
		}
	}
	if webhookEvents != 1 {
		t.Fatalf("webhook events = %d (events: %+v), want 1", webhookEvents, events)
	}
	retries, err := appStore.ListDueNotificationRetries(ctx, time.Now().UTC().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("list retries: %v", err)
	}
	webhookRetries := 0
	for _, retry := range retries {
		if strings.HasSuffix(retry.EventType, "webhook") && retry.Transition.Current == monitor.StatusDown {
			webhookRetries++
		}
	}
	if webhookRetries != 1 {
		t.Fatalf("expected one queued webhook retry, got %+v", retries)
	}

	// A muted monitor stays silent on the remote path as well, and logs the suppression.
	until := time.Now().Add(time.Hour)
	muted := assigned[0]
	muted.MutedUntil = &until
	recovered := monitor.Result{MonitorID: monitorID, Status: monitor.StatusUp, CheckedAt: time.Now().UTC().Add(time.Second)}
	downPrev := result
	before, _ := appStore.ListRecentNotificationEvents(ctx, 50)
	dispatcher.ProcessResult(ctx, monitor.Snapshot{Monitor: muted, LastResult: &downPrev}, recovered)
	after, _ := appStore.ListRecentNotificationEvents(ctx, 50)
	if len(after) != len(before)+1 || !after[0].Suppressed {
		t.Fatalf("muted remote transition should add exactly one suppressed event: before=%d after=%+v", len(before), after)
	}
}
