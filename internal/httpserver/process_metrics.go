package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// handleProcessMetrics serves process-level Prometheus metrics for control-plane admins.
func (s *Server) handleProcessMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.writeProcessMetrics(w, r)
}

// handleProcessMetricsInternal serves the same metrics without auth, but only to loopback peers.
func (s *Server) handleProcessMetricsInternal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requestFromLoopback(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.writeProcessMetrics(w, r)
}

func requestFromLoopback(r *http.Request) bool {
	addr, ok := remoteAddrIP(r)
	return ok && addr.IsLoopback()
}

func (s *Server) writeProcessMetrics(w http.ResponseWriter, r *http.Request) {
	body := s.renderProcessMetrics(r.Context())
	w.Header().Set("Content-Type", metricsContentType)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(body))
}

func (s *Server) renderProcessMetrics(ctx context.Context) string {
	now := time.Now().UTC()
	mem := s.memCache.read(now)

	var b strings.Builder
	family := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, escapeMetricHelp(help), name, typ)
	}

	family("goup_process_goroutines", "Number of goroutines in the GoUp process.", "gauge")
	fmt.Fprintf(&b, "goup_process_goroutines %d\n", runtime.NumGoroutine())

	family("goup_process_heap_alloc_bytes", "Bytes of allocated heap objects (runtime.MemStats.HeapAlloc).", "gauge")
	fmt.Fprintf(&b, "goup_process_heap_alloc_bytes %d\n", mem.HeapAlloc)

	family("goup_process_heap_inuse_bytes", "Bytes in in-use spans (runtime.MemStats.HeapInuse).", "gauge")
	fmt.Fprintf(&b, "goup_process_heap_inuse_bytes %d\n", mem.HeapInuse)

	family("goup_process_heap_sys_bytes", "Bytes of heap memory obtained from the OS (runtime.MemStats.HeapSys).", "gauge")
	fmt.Fprintf(&b, "goup_process_heap_sys_bytes %d\n", mem.HeapSys)

	family("goup_process_sys_bytes", "Total bytes of memory obtained from the OS (runtime.MemStats.Sys).", "gauge")
	fmt.Fprintf(&b, "goup_process_sys_bytes %d\n", mem.Sys)

	family("goup_process_stack_inuse_bytes", "Bytes in stack spans (runtime.MemStats.StackInuse).", "gauge")
	fmt.Fprintf(&b, "goup_process_stack_inuse_bytes %d\n", mem.StackInuse)

	family("goup_process_gc_cycles_total", "Number of completed GC cycles (runtime.MemStats.NumGC).", "counter")
	fmt.Fprintf(&b, "goup_process_gc_cycles_total %d\n", mem.NumGC)

	family("goup_open_dbs", "Number of open SQLite databases (control plane plus tenant stores).", "gauge")
	fmt.Fprintf(&b, "goup_open_dbs %d\n", s.openDBCount())

	if summary, err := s.remoteNodeVersionSummary(ctx, 0); err == nil {
		family("goup_remote_nodes", "Remote-node last_seen summary by state.", "gauge")
		fmt.Fprintf(&b, "goup_remote_nodes%s %d\n", metricLabels("state", "total"), summary.Total)
		fmt.Fprintf(&b, "goup_remote_nodes%s %d\n", metricLabels("state", "online"), summary.Online)
		fmt.Fprintf(&b, "goup_remote_nodes%s %d\n", metricLabels("state", "offline"), summary.Offline)
		fmt.Fprintf(&b, "goup_remote_nodes%s %d\n", metricLabels("state", "outdated"), summary.Outdated)
	}

	if depth, ok := s.notificationQueueDepth(ctx); ok {
		family("goup_notification_retry_queue_depth", "Pending notification retry queue depth across tenants.", "gauge")
		fmt.Fprintf(&b, "goup_notification_retry_queue_depth %d\n", depth)
	}

	return b.String()
}

func (s *Server) openDBCount() int {
	n := 0
	if s.controlStore != nil {
		n++
	}
	if s.tenantStores != nil {
		n += s.tenantStores.OpenStoreCount()
	} else if s.store != nil {
		n++
	}
	return n
}

func (s *Server) notificationQueueDepth(ctx context.Context) (int, bool) {
	if s.controlStore == nil {
		return 0, false
	}
	tenants, err := s.controlStore.GetAllTenants(ctx)
	if err != nil {
		return 0, false
	}
	total := 0
	found := false
	for _, tenant := range tenants {
		if !tenant.Active {
			continue
		}
		if s.runnerFor != nil {
			if runner := s.runnerFor(tenant.ID); runner != nil {
				stats, err := runner.RetryQueueStats(ctx)
				if err == nil {
					found = true
					total += stats.Pending
					continue
				}
			}
		}
		if s.tenantStores == nil {
			continue
		}
		st, err := s.tenantStores.StoreForTenant(ctx, tenant.ID)
		if err != nil || st == nil {
			continue
		}
		pending, _, err := st.NotificationRetryQueueStats(ctx)
		if err != nil {
			continue
		}
		found = true
		total += pending
	}
	return total, found
}
