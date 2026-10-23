package httpserver

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
	"goup/internal/version"
)

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

var metricsUptimeWindows = []struct {
	Label    string
	Duration time.Duration
}{
	{"24h", 24 * time.Hour},
	{"7d", 7 * 24 * time.Hour},
	{"30d", 30 * 24 * time.Hour},
}

// bearerToken extracts the token of an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

// handleTenantMetrics serves GET /{slug}/metrics in the Prometheus text format, protected by a
// tenant API token with scope "metrics". Failed attempts are rate limited per client IP.
func (s *Server) handleTenantMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID <= 0 {
		http.NotFound(w, r)
		return
	}

	limiterKey := "metrics|" + s.rateLimitIP(r)
	if allowed, wait := s.bootstrapAllowed(limiterKey, time.Now()); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return
	}
	ok, err := s.controlStore.AuthenticateAPIToken(r.Context(), tenantID, store.APITokenScopeMetrics, bearerToken(r))
	if err != nil {
		s.logger.Error("metrics token lookup failed", "tenant_id", tenantID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.registerBootstrapFailure(limiterKey, time.Now())
		w.Header().Set("WWW-Authenticate", `Bearer realm="goup-metrics"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	appStore, err := s.appStore(r)
	if err != nil {
		s.logger.Error("metrics resolve tenant store failed", "tenant_id", tenantID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	snapshots, err := appStore.ListMonitorSnapshots(r.Context())
	if err != nil {
		s.logger.Error("metrics list monitors failed", "tenant_id", tenantID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	rollups, err := appStore.ListMonitorHourlyRollupsSince(r.Context(), now.Add(-metricsUptimeWindows[len(metricsUptimeWindows)-1].Duration).Truncate(time.Hour))
	if err != nil {
		s.logger.Warn("metrics load rollups failed", "tenant_id", tenantID, "error", err)
		rollups = nil
	}

	w.Header().Set("Content-Type", metricsContentType)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(renderMetrics(snapshots, rollups, now, version.Version)))
}

func escapeMetricLabel(value string) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func escapeMetricHelp(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, "\n", `\n`)
}

func metricLabels(pairs ...string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(pairs[i])
		b.WriteString(`="`)
		b.WriteString(escapeMetricLabel(pairs[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func formatMetricFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// renderMetrics renders the Prometheus text exposition format (version 0.0.4). It never contains
// monitor targets, hosts or URLs.
func renderMetrics(snapshots []monitor.Snapshot, rollups []store.MonitorHourlyRollup, now time.Time, buildVersion string) string {
	sorted := append([]monitor.Snapshot(nil), snapshots...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Monitor.ID < sorted[j].Monitor.ID })
	rollupsByMonitor := groupRollupsByMonitor(rollups)

	var b strings.Builder
	family := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, escapeMetricHelp(help), name, typ)
	}
	base := func(snap monitor.Snapshot, extra ...string) string {
		pairs := []string{
			"monitor", snap.Monitor.Name,
			"monitor_id", strconv.FormatInt(snap.Monitor.ID, 10),
			"kind", string(snap.Monitor.Kind),
			"group", strings.TrimSpace(snap.Monitor.Group),
		}
		return metricLabels(append(pairs, extra...)...)
	}

	family("goup_build_info", "GoUp build information.", "gauge")
	fmt.Fprintf(&b, "goup_build_info%s 1\n", metricLabels("version", buildVersion))

	family("goup_monitor_up", "1 if the last check was up or degraded, 0 if down; absent without a verdict.", "gauge")
	for _, snap := range sorted {
		switch publicMonitorStatus(snap) {
		case "up", "degraded":
			fmt.Fprintf(&b, "goup_monitor_up%s 1\n", base(snap))
		case "down":
			fmt.Fprintf(&b, "goup_monitor_up%s 0\n", base(snap))
		}
	}

	family("goup_monitor_status", "One-hot monitor status (up, degraded, down, unknown, paused).", "gauge")
	for _, snap := range sorted {
		current := publicMonitorStatus(snap)
		for _, status := range []string{"up", "degraded", "down", "unknown", "paused"} {
			value := 0
			if status == current {
				value = 1
			}
			fmt.Fprintf(&b, "goup_monitor_status%s %d\n", base(snap, "status", status), value)
		}
	}

	family("goup_monitor_latency_milliseconds", "Latency of the last successful or degraded check.", "gauge")
	for _, snap := range sorted {
		if snap.LastResult == nil {
			continue
		}
		if snap.LastResult.Status != monitor.StatusUp && snap.LastResult.Status != monitor.StatusDegraded {
			continue
		}
		fmt.Fprintf(&b, "goup_monitor_latency_milliseconds%s %s\n", base(snap), formatMetricFloat(float64(snap.LastResult.Latency)/float64(time.Millisecond)))
	}

	family("goup_monitor_cert_expiry_timestamp_seconds", "Expiry time of the TLS certificate seen by the last check (Unix time).", "gauge")
	for _, snap := range sorted {
		if snap.LastResult == nil || snap.LastResult.TLSNotAfter == nil {
			continue
		}
		fmt.Fprintf(&b, "goup_monitor_cert_expiry_timestamp_seconds%s %d\n", base(snap), snap.LastResult.TLSNotAfter.Unix())
	}

	family("goup_monitor_uptime_ratio", "Uptime ratio (0-1) over the window, from hourly rollups without unknown and maintenance checks.", "gauge")
	for _, snap := range sorted {
		items := rollupsByMonitor[snap.Monitor.ID]
		for _, window := range metricsUptimeWindows {
			cutoff := now.Add(-window.Duration).Truncate(time.Hour)
			up, effective := 0, 0
			for _, item := range items {
				if item.HourBucket.Before(cutoff) {
					continue
				}
				up += item.UpChecks
				effective += item.EffectiveChecks()
			}
			if effective == 0 {
				continue
			}
			fmt.Fprintf(&b, "goup_monitor_uptime_ratio%s %s\n", base(snap, "window", window.Label), formatMetricFloat(float64(up)/float64(effective)))
		}
	}

	family("goup_monitor_paused", "1 if the monitor is paused (disabled).", "gauge")
	for _, snap := range sorted {
		fmt.Fprintf(&b, "goup_monitor_paused%s %d\n", base(snap), boolToInt(!snap.Monitor.Enabled))
	}

	family("goup_monitor_muted", "1 if notifications of the monitor are muted.", "gauge")
	for _, snap := range sorted {
		fmt.Fprintf(&b, "goup_monitor_muted%s %d\n", base(snap), boolToInt(snap.Monitor.IsMuted(now)))
	}

	family("goup_monitor_last_check_timestamp_seconds", "Time of the last check (Unix time).", "gauge")
	for _, snap := range sorted {
		if snap.LastResult == nil {
			continue
		}
		fmt.Fprintf(&b, "goup_monitor_last_check_timestamp_seconds%s %d\n", base(snap), snap.LastResult.CheckedAt.Unix())
	}
	return b.String()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
