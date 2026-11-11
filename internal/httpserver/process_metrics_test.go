package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/config"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

func TestProcessMetricsRequiresAdmin(t *testing.T) {
	s := &Server{adminCookieKey: strings.Repeat("a", 32)}
	handler := s.requireControlPlaneAdmin(http.HandlerFunc(s.handleProcessMetrics))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/system/metrics", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/access" {
		t.Fatalf("unauthenticated: code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestProcessMetricsInternalLoopbackOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	s := &Server{
		cfg:          config.Config{DataDir: dir, ControlPlaneDBPath: filepath.Join(dir, "controlplane.db")},
		controlStore: cp,
		tenantStores: store.NewTenantStoreManager(cp, store.Tenant{}, nil),
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		startedAt:    time.Now().UTC(),
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics-internal", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	s.handleProcessMetricsInternal(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback: code=%d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics-internal", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec = httptest.NewRecorder()
	s.handleProcessMetricsInternal(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback: code=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"goup_process_goroutines",
		"goup_process_heap_alloc_bytes",
		"goup_open_dbs",
		"goup_remote_nodes{state=\"total\"}",
		"goup_remote_nodes{state=\"online\"}",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, "goup_open_dbs 1") {
		t.Fatalf("expected control-plane open db count, body:\n%s", body)
	}
}

func TestProcessMetricsIncludesNotificationQueue(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	tenantDB := filepath.Join(dir, "acme.db")
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme", tenantDB)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	st, err := store.Open(ctx, tenantDB)
	if err != nil {
		t.Fatalf("open tenant store: %v", err)
	}
	defer st.Close()

	monitorID, err := st.CreateMonitor(ctx, store.CreateMonitorParams{
		Name:     "Web",
		Kind:     monitor.KindHTTPS,
		Target:   "https://example.com",
		Interval: time.Minute,
		Timeout:  5 * time.Second,
		Enabled:  true,
		TLSMode:  monitor.TLSModeTLS,
	})
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}
	endpointID, err := st.EnsureSystemNotificationEndpoint(ctx, "webhook", "hook", `{"url":"https://example.com/hook"}`, true)
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	now := time.Now().UTC()
	if err := st.EnqueueNotificationRetry(ctx, monitor.NotificationRetryParams{
		MonitorID:     monitorID,
		EndpointID:    endpointID,
		EventType:     "webhook",
		NextAttemptAt: now.Add(time.Minute),
		MaxAttempts:   3,
		Transition: monitor.Transition{
			Monitor: monitor.Monitor{
				ID:     monitorID,
				Name:   "Web",
				Kind:   monitor.KindHTTPS,
				Target: "https://example.com",
			},
			Previous:  monitor.StatusUp,
			Current:   monitor.StatusDown,
			CheckedAt: now,
		},
	}); err != nil {
		t.Fatalf("enqueue retry: %v", err)
	}

	mgr := store.NewTenantStoreManager(cp, tenant, st)
	s := &Server{
		cfg:          config.Config{DataDir: dir, ControlPlaneDBPath: filepath.Join(dir, "controlplane.db")},
		controlStore: cp,
		tenantStores: mgr,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		startedAt:    time.Now().UTC(),
	}

	body := s.renderProcessMetrics(ctx)
	if !strings.Contains(body, "goup_notification_retry_queue_depth 1") {
		t.Fatalf("queue depth missing:\n%s", body)
	}
	if !strings.Contains(body, "goup_open_dbs 2") {
		t.Fatalf("open dbs want 2 (control+tenant):\n%s", body)
	}
}

func TestProcessMetricsMethodNotAllowed(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/metrics-internal", nil)
	req.RemoteAddr = "127.0.0.1:1"
	s.handleProcessMetricsInternal(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d", rec.Code)
	}
}
