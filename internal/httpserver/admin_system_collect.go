package httpserver

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	store "goup/internal/store/sqlite"
	"goup/internal/version"
)

const (
	systemTenantTimeout   = 5 * time.Second
	systemMemStatsTTL     = 5 * time.Second
	systemNotifyWindow    = 24 * time.Hour
	systemFailureLimit    = 10
	systemFailureMsgRunes = 200
)

// systemMemCache rate-limits runtime.ReadMemStats, which briefly stops the world.
type systemMemCache struct {
	mu   sync.Mutex
	at   time.Time
	data runtime.MemStats
}

func (c *systemMemCache) read(now time.Time) runtime.MemStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || now.Sub(c.at) >= systemMemStatsTTL {
		runtime.ReadMemStats(&c.data)
		c.at = now
	}
	return c.data
}

// collectSystemView gathers all system health data. Failures of a single tenant are reported in
// that tenant's row; only a failing tenant list is returned as an error.
func (s *Server) collectSystemView(ctx context.Context) (systemPageView, error) {
	now := time.Now().UTC()
	view := systemPageView{GeneratedAt: now.Format(time.RFC3339)}

	tenants, err := s.controlStore.GetAllTenants(ctx)
	if err != nil {
		return view, fmt.Errorf("load tenants: %w", err)
	}

	view.Tenants = make([]systemTenantView, len(tenants))
	files := make([]systemDBFileView, len(tenants))
	failures := make([][]systemFailureView, len(tenants))

	var wg sync.WaitGroup
	for i, tenant := range tenants {
		wg.Add(1)
		go func(i int, tenant store.Tenant) {
			defer wg.Done()
			tenantCtx, cancel := context.WithTimeout(ctx, systemTenantTimeout)
			defer cancel()
			files[i] = statDBFiles(s.cfg.DataDir, tenant.Name, tenant.DBPath)
			view.Tenants[i], failures[i] = s.collectSystemTenant(tenantCtx, tenant, &files[i], now)
		}(i, tenant)
	}
	view.RemoteNodes = s.collectSystemRemoteNodes(ctx, now)
	wg.Wait()

	controlFile := statDBFiles(s.cfg.DataDir, "Control plane", s.cfg.ControlPlaneDBPath)
	view.Storage = systemStorageView{DataDir: s.cfg.DataDir, Files: append([]systemDBFileView{controlFile}, files...)}
	if free, ok := freeDiskBytes(s.cfg.DataDir); ok {
		view.Storage.FreeKnown = true
		view.Storage.FreeSpace = formatByteSize(int64(free))
	}

	for _, list := range failures {
		view.Failures = append(view.Failures, list...)
	}
	sort.SliceStable(view.Failures, func(a, b int) bool { return view.Failures[a].TimeRaw > view.Failures[b].TimeRaw })
	if len(view.Failures) > systemFailureLimit {
		view.Failures = view.Failures[:systemFailureLimit]
	}

	view.Process = s.collectSystemProcess(now, view.Tenants)
	return view, nil
}

func (s *Server) collectSystemProcess(now time.Time, tenants []systemTenantView) systemProcessView {
	mem := s.memCache.read(now)
	process := systemProcessView{
		Version:     version.Version,
		GoVersion:   runtime.Version(),
		Uptime:      formatSystemDuration(now.Sub(s.startedAt)),
		Goroutines:  runtime.NumGoroutine(),
		HeapInUse:   formatByteSize(int64(mem.HeapInuse)),
		Sys:         formatByteSize(int64(mem.Sys)),
		GOMAXPROCS:  runtime.GOMAXPROCS(0),
		TenantCount: len(tenants),
	}
	for _, tenant := range tenants {
		if tenant.HasRunner {
			process.ActiveRunners++
		}
	}
	return process
}

// collectSystemTenant fills the per-tenant check and notification sections and records the
// maintenance timestamps on the tenant's database file row.
func (s *Server) collectSystemTenant(ctx context.Context, tenant store.Tenant, file *systemDBFileView, now time.Time) (systemTenantView, []systemFailureView) {
	row := systemTenantView{Name: tenant.Name, Slug: tenant.Slug, Active: tenant.Active}
	if !tenant.Active {
		return row, nil
	}
	if _, err := os.Stat(tenant.DBPath); err != nil {
		row.Err = "database file not found"
		return row, nil
	}
	tenantStore, err := s.tenantStores.StoreForTenant(ctx, tenant.ID)
	if err != nil {
		row.Err = err.Error()
		return row, nil
	}

	if stats, statsErr := tenantStore.DashboardStats(ctx); statsErr != nil {
		row.Err = statsErr.Error()
	} else {
		row.EnabledMonitor = stats.EnabledMonitorCount
	}

	if s.runnerFor != nil {
		if runner := s.runnerFor(tenant.ID); runner != nil {
			row.HasRunner = true
			snap := runner.Stats()
			row.Workers = snap.Workers
			row.ChecksLast5Min = snap.ChecksLast5Min
			row.Running = snap.Running
			row.Backlog = snap.Backlog
			row.LastLoop = formatSystemDuration(snap.LastLoopDuration)
			row.AvgCheck = formatSystemDuration(snap.AvgCheckDuration)
			if queue, queueErr := runner.RetryQueueStats(ctx); queueErr == nil {
				row.RetryQueue = queue.Pending
				if queue.OldestAttemptAt != nil {
					row.OldestRetryRaw = queue.OldestAttemptAt.UTC().Format(time.RFC3339)
				}
			}
		}
	}

	since := now.Add(-systemNotifyWindow)
	var failures []systemFailureView
	if counts, countErr := tenantStore.NotificationOutcomeCountsSince(ctx, since); countErr != nil {
		row.Err = countErr.Error()
	} else {
		row.Delivered24h, row.Failed24h, row.Suppressed24h = counts.Delivered, counts.Failed, counts.Suppressed
	}
	if row.Failed24h > 0 {
		list, listErr := tenantStore.ListRecentNotificationFailures(ctx, since, systemFailureLimit)
		if listErr != nil {
			row.Err = listErr.Error()
		}
		for _, f := range list {
			failures = append(failures, systemFailureView{
				TimeRaw:  f.CreatedAt.UTC().Format(time.RFC3339),
				Tenant:   tenant.Name,
				Monitor:  f.MonitorName,
				Endpoint: endpointLabel(f.EndpointKind, f.EndpointName),
				Event:    f.EventType,
				Error:    truncateRunes(f.Error, systemFailureMsgRunes),
			})
		}
	}

	if runs, runsErr := tenantStore.MaintenanceRuns(ctx); runsErr == nil {
		if !runs.RawRetention.IsZero() {
			file.RetentionRaw = runs.RawRetention.UTC().Format(time.RFC3339)
		}
		if !runs.RollupRetention.IsZero() {
			file.RollupRaw = runs.RollupRetention.UTC().Format(time.RFC3339)
		}
	}
	return row, failures
}

func endpointLabel(kind, name string) string {
	switch {
	case kind != "" && name != "":
		return kind + " / " + name
	case name != "":
		return name
	default:
		return kind
	}
}

func (s *Server) collectSystemRemoteNodes(ctx context.Context, now time.Time) systemRemoteNodesView {
	nodes, err := s.controlStore.ListAllEnabledRemoteNodes(ctx)
	if err != nil {
		return systemRemoteNodesView{Err: err.Error()}
	}
	view := systemRemoteNodesView{Total: len(nodes)}
	for _, node := range nodes {
		if node.IsOnline(now) {
			view.Online++
		}
	}
	view.Offline = view.Total - view.Online
	return view
}
