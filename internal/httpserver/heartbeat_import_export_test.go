package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/auth"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

func TestHeartbeatExportOmitsTokenAndImportIssuesNewOne(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	s := &Server{
		store:    st,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessions: auth.NewSessionManager([]byte(strings.Repeat("k", 32)), false),
	}

	id, err := st.CreateMonitor(ctx, store.CreateMonitorParams{
		Name: "nightly backup", Kind: monitor.KindHeartbeat, Interval: 24 * time.Hour, Timeout: 10 * time.Minute, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	original, _ := st.GetMonitorSnapshot(ctx, id)

	rec := httptest.NewRecorder()
	s.handleMonitorExport(rec, httptest.NewRequest(http.MethodGet, "/monitors/export", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `"kind": "heartbeat"`) {
		t.Fatalf("export failed: %d %s", rec.Code, body)
	}
	if strings.Contains(body, original.Monitor.HeartbeatToken) || strings.Contains(strings.ToLower(body), "token") {
		t.Fatalf("export must not contain the heartbeat token: %s", body)
	}

	// Import the exported record: a new monitor with its own token is created.
	form := url.Values{
		"count": {"1"}, "name_0": {"nightly backup (import)"}, "kind_0": {"heartbeat"}, "target_0": {"heartbeat"},
		"interval_seconds_0": {"86400"}, "timeout_seconds_0": {"600"}, "enabled_0": {"on"}, "tls_mode_0": {"none"},
	}
	req := httptest.NewRequest(http.MethodPost, "/monitors/import/confirm", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	s.handleMonitorImportConfirm(rec, req)
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Fatalf("import failed: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	snapshots, _ := st.ListMonitorSnapshots(ctx)
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 monitors, got %d", len(snapshots))
	}
	imported := snapshots[1].Monitor
	if imported.Kind != monitor.KindHeartbeat || len(imported.HeartbeatToken) != 43 || imported.HeartbeatToken == original.Monitor.HeartbeatToken {
		t.Fatalf("imported monitor must get a fresh token: %+v", imported)
	}
	if imported.Timeout != 10*time.Minute || imported.Interval != 24*time.Hour {
		t.Fatalf("period/grace not imported: %+v", imported)
	}
}

func TestHeartbeatViewsBuildPingURL(t *testing.T) {
	s := &Server{
		sessions: auth.NewSessionManager([]byte(strings.Repeat("k", 32)), false),
	}
	s.cfg.BaseURL = "https://goup.example.com/"
	views := []monitorView{{ID: 1, HeartbeatToken: "tok"}, {ID: 2}}
	req := httptest.NewRequest(http.MethodGet, "/acme/", nil)
	req = requestWithTenantSlug(req, "acme")
	s.applyHeartbeatURLs(req, views)
	if views[0].HeartbeatURL != "https://goup.example.com/hb/acme/tok" || views[0].HeartbeatToken != "" {
		t.Fatalf("unexpected view: %+v", views[0])
	}
	if !strings.Contains(views[0].HeartbeatCurlFail, "/hb/acme/tok/fail") || views[1].HeartbeatURL != "" {
		t.Fatalf("unexpected curl/empty views: %+v %+v", views[0], views[1])
	}
}
