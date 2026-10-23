package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"goup/internal/auth"
	"goup/internal/config"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type maintenanceEnv struct {
	*statusTestEnv
	tenant  store.Tenant
	cookies map[string][]*http.Cookie
}

func newMaintenanceEnv(t *testing.T) *maintenanceEnv {
	t.Helper()
	env := newStatusTestEnv(t)
	ctx := context.Background()
	env.s.sessions = auth.NewSessionManager([]byte(strings.Repeat("k", 32)), false)
	env.s.cfg = config.Config{BaseURL: "http://example.test"}
	env.s.appMux = env.s.buildAppMux()
	tenant, err := env.s.controlStore.GetTenantByID(ctx, env.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	me := &maintenanceEnv{statusTestEnv: env, tenant: tenant, cookies: map[string][]*http.Cookie{}}
	for role, name := range map[string]string{"admin": "alice", "viewer": "bob"} {
		user, err := env.s.controlStore.CreateLocalUserForTenant(ctx, tenant.ID, name, "a-long-password-123", name+"@example.com", name, role)
		if err != nil {
			t.Fatal(err)
		}
		version, err := env.s.controlStore.GetTenantMembershipSessionVersion(ctx, tenant.ID, user.UserID)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		if err := env.s.sessions.Set(rec, auth.UserSession{
			UserID: user.UserID, TenantID: tenant.ID, TenantSlug: tenant.Slug, Role: role, Email: name + "@example.com",
			SessionVersion: version, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		me.cookies[role] = rec.Result().Cookies()
	}
	return me
}

// do sends a request through the real routing (tenant prefix, auth middleware, handlers).
func (e *maintenanceEnv) do(role, method, path string, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Origin", "http://example.test")
	for _, c := range e.cookies[role] {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.s.handleRoot(rec, req)
	return rec
}

func maintForm(title, starts, ends string) url.Values {
	return url.Values{"title": {title}, "starts_at": {starts}, "ends_at": {ends}, "recurrence": {"none"}, "scope": {"all"}}
}

func TestMaintenanceSettingsAdminOnly(t *testing.T) {
	env := newMaintenanceEnv(t)
	for _, tc := range []struct {
		role, method, path string
		want               int
	}{
		{"viewer", http.MethodGet, "/acme/settings/maintenance", http.StatusForbidden},
		{"viewer", http.MethodPost, "/acme/settings/maintenance/save", http.StatusForbidden},
		{"viewer", http.MethodPost, "/acme/settings/maintenance/1/delete", http.StatusForbidden},
		{"", http.MethodGet, "/acme/settings/maintenance", http.StatusSeeOther},
		{"admin", http.MethodGet, "/acme/settings/maintenance", http.StatusOK},
	} {
		var form url.Values
		if tc.method == http.MethodPost {
			form = url.Values{}
		}
		if rec := env.do(tc.role, tc.method, tc.path, form); rec.Code != tc.want {
			t.Errorf("%s %s as %q = %d, want %d", tc.method, tc.path, tc.role, rec.Code, tc.want)
		}
	}
	if windows, _ := env.st.ListMaintenanceWindows(context.Background()); len(windows) != 0 {
		t.Fatalf("a viewer created %d windows", len(windows))
	}
}

func TestMaintenanceSettingsValidationAndCRUD(t *testing.T) {
	env := newMaintenanceEnv(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Minute)
	fmtT := func(d time.Duration) string { return start.Add(d).Format(time.RFC3339) }

	// End before start, empty title and missing targets are rejected without creating anything.
	bad := []url.Values{
		maintForm("x", fmtT(0), fmtT(-time.Hour)),
		maintForm("x", fmtT(0), fmtT(0)),
		maintForm("  ", fmtT(0), fmtT(time.Hour)),
		maintForm("x", "", ""),
		func() url.Values { v := maintForm("x", fmtT(0), fmtT(time.Hour)); v.Set("scope", "monitors"); return v }(),
		func() url.Values {
			v := maintForm("x", fmtT(0), fmtT(30*time.Hour))
			v.Set("recurrence", "daily")
			return v
		}(),
	}
	for i, form := range bad {
		rec := env.do("admin", http.MethodPost, "/acme/settings/maintenance/save", form)
		if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error=") {
			t.Errorf("case %d: %d %q, want redirect with error", i, rec.Code, rec.Header().Get("Location"))
		}
	}
	if windows, _ := env.st.ListMaintenanceWindows(ctx); len(windows) != 0 {
		t.Fatalf("invalid input created %d windows", len(windows))
	}

	// Valid create: UTC instants from the hidden fields, scoped to a real monitor only.
	form := maintForm("DB upgrade", fmtT(0), fmtT(2*time.Hour))
	form.Set("scope", "monitors")
	form["monitor_id"] = []string{strconv.FormatInt(env.upID, 10), "99999"}
	rec := env.do("admin", http.MethodPost, "/acme/settings/maintenance/save", form)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=") {
		t.Fatalf("create: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	windows, _ := env.st.ListMaintenanceWindows(ctx)
	if len(windows) != 1 || windows[0].Title != "DB upgrade" || !windows[0].StartsAt.Equal(start) || len(windows[0].MonitorIDs) != 1 || windows[0].MonitorIDs[0] != env.upID {
		t.Fatalf("stored windows = %+v", windows)
	}

	// The list page shows it, and edit mode prefills it.
	page := env.do("admin", http.MethodGet, "/acme/settings/maintenance?edit="+strconv.FormatInt(windows[0].ID, 10), nil)
	body := page.Body.String()
	for _, want := range []string{"DB upgrade", `name="starts_local"`, `data-utc="` + start.Format(time.RFC3339) + `"`, "settings/maintenance/" + strconv.FormatInt(windows[0].ID, 10) + "/delete"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page missing %q", want)
		}
	}
	if strings.Contains(body, " style=") {
		t.Error("inline style on settings page")
	}

	// Update, then delete.
	upd := maintForm("DB upgrade v2", fmtT(0), fmtT(3*time.Hour))
	upd.Set("id", strconv.FormatInt(windows[0].ID, 10))
	if rec := env.do("admin", http.MethodPost, "/acme/settings/maintenance/save", upd); !strings.Contains(rec.Header().Get("Location"), "notice=") {
		t.Fatalf("update: %q", rec.Header().Get("Location"))
	}
	windows, _ = env.st.ListMaintenanceWindows(ctx)
	if len(windows) != 1 || windows[0].Title != "DB upgrade v2" || windows[0].Scope != monitor.MaintenanceScopeAll {
		t.Fatalf("after update = %+v", windows)
	}
	if rec := env.do("admin", http.MethodPost, "/acme/settings/maintenance/"+strconv.FormatInt(windows[0].ID, 10)+"/delete", url.Values{}); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", rec.Code)
	}
	if windows, _ = env.st.ListMaintenanceWindows(ctx); len(windows) != 0 {
		t.Fatalf("window not deleted")
	}
}

func TestMaintenanceNoJSFallbackIsUTC(t *testing.T) {
	env := newMaintenanceEnv(t)
	form := url.Values{"title": {"x"}, "starts_local": {"2030-01-02T03:04"}, "ends_local": {"2030-01-02T05:00"}, "recurrence": {"none"}, "scope": {"all"}}
	env.do("admin", http.MethodPost, "/acme/settings/maintenance/save", form)
	windows, _ := env.st.ListMaintenanceWindows(context.Background())
	if len(windows) != 1 || !windows[0].StartsAt.Equal(time.Date(2030, 1, 2, 3, 4, 0, 0, time.UTC)) {
		t.Fatalf("fallback parsing = %+v", windows)
	}
}

func TestStatusPageMaintenanceNoticesAndStatus(t *testing.T) {
	env := newMaintenanceEnv(t)
	ctx := context.Background()
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{Enabled: true},
		[]store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}, {MonitorID: env.hiddenID, DisplayName: "Database"}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mk := func(title string, from, to time.Duration, id int64) {
		t.Helper()
		if _, err := env.st.CreateMaintenanceWindow(ctx, monitor.MaintenanceWindow{
			Title: title, Description: "secret internal detail", StartsAt: now.Add(from), EndsAt: now.Add(to),
			Scope: monitor.MaintenanceScopeMonitors, MonitorIDs: []int64{id},
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("Running work", -time.Hour, time.Hour, env.hiddenID)
	mk("Planned work", 48*time.Hour, 50*time.Hour, env.upID)
	mk("Far future", 20*24*time.Hour, 20*24*time.Hour+time.Hour, env.upID)
	mk("Ended work", -5*time.Hour, -4*time.Hour, env.upID)
	other, err := env.st.CreateMonitor(ctx, store.CreateMonitorParams{Name: "Not shown", Kind: monitor.KindTCP, Target: "10.0.0.9:1", Interval: time.Minute, Timeout: time.Second, Enabled: true, TLSMode: monitor.TLSModeNone})
	if err != nil {
		t.Fatal(err)
	}
	mk("Unrelated", -time.Hour, time.Hour, other)
	env.s.statusCache.invalidate()

	body := env.get("/acme/status").Body.String()
	for _, want := range []string{"Running work", "Planned work", "status-MAINTENANCE", "Maintenance"} {
		if !strings.Contains(body, want) {
			t.Errorf("status page missing %q", want)
		}
	}
	for _, unwanted := range []string{"Far future", "Ended work", "Unrelated", "secret internal detail", "Down", "status-DOWN"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("status page must not contain %q", unwanted)
		}
	}
	if !strings.Contains(body, "Partial outage") && !strings.Contains(body, "All systems operational") {
		t.Errorf("unexpected overall banner: %s", body)
	}
}

func TestStatusPageAllInMaintenanceBanner(t *testing.T) {
	env := newMaintenanceEnv(t)
	ctx := context.Background()
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{Enabled: true}, []store.StatusPageMonitor{{MonitorID: env.hiddenID}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := env.st.CreateMaintenanceWindow(ctx, monitor.MaintenanceWindow{Title: "All", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), Scope: monitor.MaintenanceScopeAll}); err != nil {
		t.Fatal(err)
	}
	env.s.statusCache.invalidate()
	body := env.get("/acme/status").Body.String()
	if !strings.Contains(body, "is-maintenance") || !strings.Contains(body, "Scheduled maintenance") || strings.Contains(body, "status-DOWN") {
		t.Fatalf("expected maintenance banner instead of an outage: %s", body)
	}
}

func TestDashboardAndMetricsShowMaintenance(t *testing.T) {
	env := newMaintenanceEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := env.st.CreateMaintenanceWindow(ctx, monitor.MaintenanceWindow{
		Title: "Window", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour), Scope: monitor.MaintenanceScopeMonitors, MonitorIDs: []int64{env.hiddenID},
	}); err != nil {
		t.Fatal(err)
	}
	snapshots, _ := env.st.ListMonitorSnapshots(ctx)
	views := buildMonitorViews(snapshots, nil, now, supportedTrendRanges[0], nil, env.st.MaintenanceSet(ctx))
	found := false
	for _, v := range views {
		if v.ID == env.hiddenID {
			found = true
			if !v.InMaintenance || v.StatusLabel != "MAINTENANCE" || v.StatusClass != "status-MAINTENANCE" {
				t.Fatalf("monitor in maintenance view = %+v", v)
			}
		} else if v.InMaintenance {
			t.Fatalf("monitor %d wrongly in maintenance", v.ID)
		}
	}
	if !found {
		t.Fatal("monitor missing")
	}
	if label, class, _ := aggregateServiceStatus([]monitorView{{StatusLabel: "MAINTENANCE"}, {StatusLabel: "UP"}}); label != "UP" || class != "status-UP" {
		t.Fatalf("maintenance + up group = %s", label)
	}
	if label, _, _ := aggregateServiceStatus([]monitorView{{StatusLabel: "MAINTENANCE"}}); label != "MAINTENANCE" {
		t.Fatalf("all maintenance group = %s", label)
	}

	text := renderMetrics(snapshots, nil, now, "test", env.st.MaintenanceSet(ctx))
	wantHidden := `goup_monitor_in_maintenance{monitor="Secret DB",monitor_id="` + strconv.FormatInt(env.hiddenID, 10) + `"`
	wantUp := `goup_monitor_in_maintenance{monitor="Web \"Shop\"",monitor_id="` + strconv.FormatInt(env.upID, 10) + `"`
	var gotHidden, gotUp string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, wantHidden) {
			gotHidden = line
		}
		if strings.HasPrefix(line, wantUp) {
			gotUp = line
		}
	}
	if !strings.HasSuffix(gotHidden, " 1") || !strings.HasSuffix(gotUp, " 0") {
		t.Fatalf("in_maintenance metric lines: %q / %q\n%s", gotHidden, gotUp, text)
	}
}

func TestMaintenanceTemplateRenders(t *testing.T) {
	s := renderTestServer(t)
	user := &auth.UserSession{UserID: 1, Role: "admin", TenantSlug: "acme", Email: "a@example.com"}
	view := buildMaintenanceAdminView(nil, nil, time.Now().UTC(), 0)
	rec := httptest.NewRecorder()
	s.render(rec, "settings_maintenance", pageData{User: user, AppBase: "/acme/", MaintenanceAdm: &view})
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	for _, want := range []string{`/acme/settings/maintenance/save`, `name="starts_at"`, "/static/settings-maintenance.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestSanitizeRemindEvery(t *testing.T) {
	for in, want := range map[int]int{0: 0, 15: 15, 1440: 1440, 45: 0, -5: 0, 99999: 0} {
		if got := sanitizeRemindEvery(in); got != want {
			t.Errorf("sanitizeRemindEvery(%d) = %d, want %d", in, got, want)
		}
	}
}
