package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"goup/internal/auth"
	"goup/internal/config"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type statusTestEnv struct {
	s        *Server
	st       *store.Store
	tenantID int64
	upID     int64
	hiddenID int64
}

const (
	leakHost    = "internal-db.corp.example"
	leakMessage = "dial tcp 10.9.8.7:5432: connection refused"
)

func newStatusTestEnv(t *testing.T) *statusTestEnv {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	tenant, err := cp.CreateTenant(ctx, "acme", "Acme Corp", filepath.Join(dir, "acme.db"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(dir, "acme.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	mk := func(name, target string, status monitor.Status, message string) int64 {
		id, err := st.CreateMonitor(ctx, store.CreateMonitorParams{
			Name: name, Kind: monitor.KindTCP, Target: target, Interval: time.Minute, Timeout: 5 * time.Second,
			Enabled: true, ExecutorKind: "local", TLSMode: monitor.TLSModeNone, CertWarningDays: 7, ConfirmAfter: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SaveMonitorResult(ctx, monitor.Result{MonitorID: id, CheckedAt: time.Now().UTC(), Status: status, Latency: 42 * time.Millisecond, Message: message}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	env := &statusTestEnv{st: st, tenantID: tenant.ID}
	env.upID = mk(`Web "Shop"`, leakHost+":443", monitor.StatusUp, "ok")
	env.hiddenID = mk("Secret DB", leakHost+":5432", monitor.StatusDown, leakMessage)

	s := renderTestServer(t)
	s.controlStore = cp
	s.store = st
	s.cfg = config.Config{BaseURL: "http://example.test"}
	s.bootstrapAttempts = make(map[string]localLoginAttempt)
	s.appMux = s.buildAppMux()
	env.s = s
	return env
}

func (e *statusTestEnv) get(path string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	e.s.handleRoot(rec, req)
	return rec
}

func TestStatusPageDisabledIs404(t *testing.T) {
	env := newStatusTestEnv(t)
	if rec := env.get("/acme/status"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestStatusPageShowsOnlySelectedMonitorsWithoutLeaks(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{Enabled: true, Title: "Acme Status", Description: "Our services"},
		[]store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}
	rec := env.get("/acme/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=30" {
		t.Fatalf("cache-control = %q", cc)
	}
	body := rec.Body.String()
	for _, want := range []string{"Acme Status", "Our services", "Online Shop", "All systems operational", "status-UP", "trend-bar"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	for _, leak := range []string{leakHost, leakMessage, "Secret DB", "10.9.8.7", `Web &#34;Shop&#34;`, "42ms", "<script>"} {
		if strings.Contains(body, leak) {
			t.Errorf("body leaks %q", leak)
		}
	}
	if strings.Count(body, `<article class="card status-item">`) != 1 {
		t.Errorf("expected exactly one monitor card")
	}
}

func TestStatusPageOverallPartialAndCacheInvalidation(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{Enabled: true},
		[]store.StatusPageMonitor{{MonitorID: env.upID}, {MonitorID: env.hiddenID, DisplayName: "Database"}}); err != nil {
		t.Fatal(err)
	}
	body := env.get("/acme/status").Body.String()
	if !strings.Contains(body, "Partial outage") || !strings.Contains(body, "Database") {
		t.Fatalf("expected partial outage banner and public name, got: %s", body)
	}
	if strings.Contains(body, leakHost) || strings.Contains(body, leakMessage) {
		t.Fatal("status page leaks internals")
	}
	// Enabled is checked before the body cache, so disable takes effect immediately.
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{Enabled: false}, nil); err != nil {
		t.Fatal(err)
	}
	if rec := env.get("/acme/status"); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after disable, got %d", rec.Code)
	}
}

func TestStatusPageUnknownTenant(t *testing.T) {
	env := newStatusTestEnv(t)
	rec := env.get("/nope/status")
	if rec.Code == http.StatusOK {
		t.Fatalf("unexpected 200 for unknown tenant")
	}
}

func TestMetricsAuthAndFormat(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()

	if rec := env.get("/acme/metrics"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
	if rec := env.get("/acme/metrics", "Authorization", "Bearer wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec.Code)
	}

	plain, tok, err := env.s.controlStore.CreateAPIToken(ctx, env.tenantID, "prom", store.APITokenScopeMetrics, "admin@example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := env.get("/acme/metrics", "Authorization", "Bearer "+plain)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: status = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type = %q", ct)
	}
	body := rec.Body.String()
	upLabels := `{monitor="Web \"Shop\"",monitor_id="` + strconv.FormatInt(env.upID, 10) + `",kind="tcp",group=""`
	for _, want := range []string{
		"# TYPE goup_monitor_up gauge",
		"goup_build_info{version=",
		"goup_monitor_up" + upLabels + "} 1\n",
		"goup_monitor_up{monitor=\"Secret DB\"",
		"goup_monitor_status" + strings.TrimSuffix(upLabels, "") + `,status="up"} 1`,
		"goup_monitor_latency_milliseconds" + upLabels + "} 42\n",
		"goup_monitor_uptime_ratio" + upLabels + `,window="24h"} 1`,
		"goup_monitor_paused" + upLabels + "} 0\n",
		"goup_monitor_muted" + upLabels + "} 0\n",
		"goup_monitor_last_check_timestamp_seconds" + upLabels + "} ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, leakHost) || strings.Contains(body, leakMessage) {
		t.Error("metrics leak targets or messages")
	}

	// A token of another tenant must not work, and a revoked token stops working.
	if ok, _ := env.s.controlStore.AuthenticateAPIToken(ctx, env.tenantID+99, store.APITokenScopeMetrics, plain); ok {
		t.Fatal("token valid for foreign tenant")
	}
	if removed, err := env.s.controlStore.RevokeAPIToken(ctx, env.tenantID, tok.ID); err != nil || !removed {
		t.Fatalf("revoke: removed=%v err=%v", removed, err)
	}
	if rec := env.get("/acme/metrics", "Authorization", "Bearer "+plain); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: status = %d, want 401", rec.Code)
	}
}

func TestMetricsFailedAttemptsAreRateLimited(t *testing.T) {
	env := newStatusTestEnv(t)
	var last int
	for i := 0; i < bootstrapMaxFailures+2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/acme/metrics", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		req.Header.Set("Authorization", "Bearer nope")
		rec := httptest.NewRecorder()
		env.s.handleRoot(rec, req)
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after repeated failures", last)
	}
}

func TestEscapeMetricLabel(t *testing.T) {
	got := escapeMetricLabel("a\\b\"c\nd")
	if got != `a\\b\"c\nd` {
		t.Fatalf("escape = %q", got)
	}
}

func TestSettingsStatusPageTemplateRenders(t *testing.T) {
	s := renderTestServer(t)
	user := &auth.UserSession{UserID: 1, Role: "admin", TenantSlug: "acme", Email: "a@example.com"}
	rec := httptest.NewRecorder()
	s.render(rec, "settings_status_page", pageData{User: user, AppBase: "/acme/", StatusAdmin: &statusPageAdminView{
		PublicURL: "http://example.test/acme/status", NewToken: "goup_tok",
		Monitors: []statusPageAdminMonitorView{{ID: 7, Name: "Web", DisplayName: "Web", Selected: true}},
		Tokens:   []apiTokenView{{ID: 3, Name: "prom", Scope: "metrics", CreatedAt: "2026-01-01 00:00 UTC"}},
	}})
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	for _, want := range []string{
		`name="monitor_7"`, `name="display_7"`, `name="ttl_days"`, `name="scope"`, `name="access_mode"`, `name="brand_color"`,
		`/acme/settings/status-page/tokens/3/revoke`, `/acme/settings/status-page/tokens/3/rotate`,
		`goup_tok`, `data-action="copy"`, `enctype="multipart/form-data"`, `monitors:write`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, " style=") {
		t.Error("inline style found")
	}
}

func TestStatusPageTokenGateAndNoIndex(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	plain, hash, err := store.GenerateStatusPageAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{
		Enabled: true, Title: "Secret Status", AccessMode: "token", AccessTokenHash: hash, NoIndex: true,
	}, []store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}

	if rec := env.get("/acme/status"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d", rec.Code)
	}
	if rec := env.get("/acme/status", "Authorization", "Bearer wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d", rec.Code)
	}
	rec := env.get("/acme/status", "Authorization", "Bearer "+plain)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: status = %d body=%s", rec.Code, rec.Body.String())
	}
	if robots := rec.Header().Get("X-Robots-Tag"); robots != "noindex, nofollow" {
		t.Fatalf("robots = %q", robots)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("cache-control = %q", cc)
	}
	if !strings.Contains(rec.Body.String(), "Online Shop") {
		t.Fatal("expected monitor on gated page")
	}
}

func TestStatusPageIncidentsScrubCause(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	cause := "dial tcp 10.9.8.7:5432: connection refused"
	if err := env.st.RecordMonitorState(ctx, env.upID, monitor.StatusDown, cause, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{Enabled: true, Title: "Acme Status"},
		[]store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}
	rec := env.get("/acme/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Online Shop") || !strings.Contains(body, "Recent incidents") {
		t.Fatalf("expected public incident list, got: %s", body)
	}
	for _, leak := range []string{cause, "10.9.8.7", leakHost, leakMessage} {
		if strings.Contains(body, leak) {
			t.Errorf("incident list leaks %q", leak)
		}
	}
}

func TestStatusPageAtomFeed(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	cause := "dial tcp 10.9.8.7:5432: connection refused"
	if err := env.st.RecordMonitorState(ctx, env.upID, monitor.StatusDown, cause, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{Enabled: true, Title: "Acme Status"},
		[]store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}

	if rec := env.get("/acme/status/feed.xml"); rec.Code != http.StatusOK {
		t.Fatalf("feed = %d body=%s", rec.Code, rec.Body.String())
	}
	rec := env.get("/acme/status/feed.atom", "Accept-Language", "en")
	if rec.Code != http.StatusOK {
		t.Fatalf("atom alias = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/atom+xml") {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`xmlns="http://www.w3.org/2005/Atom"`,
		"<title>Acme Status",
		"Online Shop",
		`rel="self"`,
		"/acme/status/feed.xml",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("feed missing %q", want)
		}
	}
	for _, leak := range []string{cause, "10.9.8.7", leakHost, leakMessage, "Secret DB"} {
		if strings.Contains(body, leak) {
			t.Errorf("feed leaks %q", leak)
		}
	}
}

func TestStatusPageAtomFeedTokenGateAndDisabled(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	if rec := env.get("/acme/status/feed.xml"); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled feed = %d", rec.Code)
	}
	plain, hash, err := store.GenerateStatusPageAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{
		Enabled: true, Title: "Secret", AccessMode: "token", AccessTokenHash: hash,
	}, []store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}
	if rec := env.get("/acme/status/feed.xml"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token feed = %d", rec.Code)
	}
	rec := env.get("/acme/status/feed.xml", "Authorization", "Bearer "+plain)
	if rec.Code != http.StatusOK {
		t.Fatalf("authed feed = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Online Shop") && !strings.Contains(rec.Body.String(), "Secret") {
		t.Fatalf("unexpected feed body: %s", rec.Body.String())
	}
}

func TestStatusPageShowsSubscribeAndFeedLinks(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{Enabled: true, Title: "Acme Status"},
		[]store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}
	rec := env.get("/acme/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`/acme/status/feed.xml`,
		"Atom feed",
		"Online Shop",
		"Email subscriptions are not configured",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}

	if err := env.s.controlStore.ConfigureSecretKeys("test-secret-key-1234567890abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := env.s.controlStore.UpsertGlobalSMTPSettings(ctx, store.GlobalSMTPSettings{
		Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com", TLSMode: "starttls",
	}, "smtp-password"); err != nil {
		t.Fatal(err)
	}
	rec = env.get("/acme/status")
	body = rec.Body.String()
	for _, want := range []string{
		`action="/acme/status/subscribe"`,
		`name="email"`,
		`name="monitor_id"`,
		`value="` + strconv.FormatInt(env.upID, 10) + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("with smtp missing %q", want)
		}
	}
}

