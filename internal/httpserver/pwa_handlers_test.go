package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/auth"
	"goup/internal/config"
	store "goup/internal/store/sqlite"
)

func pwaTestServer(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	if _, err := cp.CreateTenant(ctx, "acme", "Acme Corporation Ltd", filepath.Join(dir, "acme.db")); err != nil {
		t.Fatal(err)
	}
	s := renderTestServer(t)
	s.controlStore = cp
	s.cfg = config.Config{BaseURL: "http://example.test"}
	return s
}

func TestTenantManifest(t *testing.T) {
	s := pwaTestServer(t)

	// No session cookie: the manifest must be reachable for installation.
	rec := httptest.NewRecorder()
	s.handleRoot(rec, httptest.NewRequest(http.MethodGet, "/acme/manifest.webmanifest", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/manifest+json") {
		t.Fatalf("content type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age") || strings.Contains(cc, "no-store") {
		t.Fatalf("cache-control = %q, want short public cache", cc)
	}
	var m webManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("invalid manifest JSON: %v", err)
	}
	if m.Scope != "/acme/" || m.StartURL != "/acme/" || m.ID != "/acme/" || m.Display != "standalone" {
		t.Fatalf("unexpected scope/start/id/display: %+v", m)
	}
	if m.Name != "GoUp · Acme Corporation Ltd" || m.ShortName != "GoUp" {
		t.Fatalf("unexpected names: %q / %q", m.Name, m.ShortName)
	}
	if m.ThemeColor != "#0b1020" || m.BackgroundColor != "#0b1020" {
		t.Fatalf("unexpected colors: %+v", m)
	}
	maskable := false
	for _, icon := range m.Icons {
		if icon.Purpose == "maskable" && icon.Sizes == "512x512" {
			maskable = true
		}
	}
	if !maskable || len(m.Shortcuts) != 2 {
		t.Fatalf("expected maskable icon and 2 shortcuts: %+v", m)
	}
	for _, sc := range m.Shortcuts {
		if !strings.HasPrefix(sc.URL, m.Scope) {
			t.Fatalf("shortcut %q outside scope", sc.URL)
		}
	}

	for _, path := range []string{"/unknown/manifest.webmanifest", "/admin/manifest.webmanifest"} {
		rec = httptest.NewRecorder()
		s.handleRoot(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: status = %d, want 404/redirect", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "webmanifest") && rec.Code == http.StatusOK {
			t.Fatalf("%s must not yield a manifest", path)
		}
	}
}

func TestShortNameUsesShortTenantName(t *testing.T) {
	if got := pwaShortName("Acme"); got != "Acme" {
		t.Fatalf("short tenant name = %q", got)
	}
	if got := pwaShortName("A very long tenant name"); got != "GoUp" {
		t.Fatalf("long tenant name = %q", got)
	}
}

func TestServiceWorkerHeaders(t *testing.T) {
	s := renderTestServer(t)
	rec := httptest.NewRecorder()
	s.handleServiceWorker(rec, httptest.NewRequest(http.MethodGet, "/sw.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	h := rec.Header()
	if !strings.HasPrefix(h.Get("Content-Type"), "text/javascript") {
		t.Fatalf("content type = %q", h.Get("Content-Type"))
	}
	if h.Get("Cache-Control") != "no-cache" || h.Get("Service-Worker-Allowed") != "/" {
		t.Fatalf("headers: cache=%q allowed=%q", h.Get("Cache-Control"), h.Get("Service-Worker-Allowed"))
	}
	body := rec.Body.String()
	if strings.Contains(body, swVersionPlaceholder) || !strings.Contains(body, assetVersion()) {
		t.Fatalf("version placeholder was not injected")
	}

	rec = httptest.NewRecorder()
	s.handleServiceWorker(rec, httptest.NewRequest(http.MethodPost, "/sw.js", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", rec.Code)
	}
}

func TestOfflinePage(t *testing.T) {
	s := renderTestServer(t)
	rec := httptest.NewRecorder()
	s.handleOffline(rec, httptest.NewRequest(http.MethodGet, "/offline", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`data-action="reload"`, `/static/style.css?v=` + assetVersion(), `rel="manifest"`, `viewport-fit=cover`} {
		if !strings.Contains(body, want) {
			t.Errorf("offline page missing %q", want)
		}
	}
	if strings.Contains(body, `class="topbar"`) {
		t.Errorf("offline page must not render the topbar")
	}
}

func TestStaticVersionedCaching(t *testing.T) {
	h := staticFileHandler(os.DirFS("../../web/static"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/theme.js?v="+assetVersion(), nil))
	if !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("versioned asset cache-control = %q", rec.Header().Get("Cache-Control"))
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/theme.js", nil))
	if rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("unversioned asset cache-control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestLayoutPWAMetaAndBackLink(t *testing.T) {
	s := renderTestServer(t)
	user := &auth.UserSession{UserID: 1, Role: "admin", TenantSlug: "acme", TenantName: "Acme", Email: "a@example.com"}
	rec := httptest.NewRecorder()
	s.render(rec, "settings_users", pageData{User: user, AppBase: "/acme/"})
	body := rec.Body.String()
	for _, want := range []string{
		`href="/acme/manifest.webmanifest"`,
		`apple-mobile-web-app-capable`,
		`black-translucent`,
		`apple-mobile-web-app-title" content="Acme"`,
		`class="page-back-link" href="/acme/"`,
		`data-action="refresh"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(body, `name="theme-color"`) != 2 {
		t.Errorf("expected two theme-color metas")
	}
}

func TestSessionCookieIsPersistentAndSecureViaProxy(t *testing.T) {
	s := &Server{
		cfg:      config.Config{BaseURL: "http://example.test", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		sessions: auth.NewSessionManager([]byte(strings.Repeat("k", 32)), false),
	}
	session := auth.UserSession{TenantSlug: "acme", ExpiresAt: time.Now().Add(auth.RememberedSessionLifetime)}

	issue := func(r *http.Request) *http.Cookie {
		rec := httptest.NewRecorder()
		if err := s.sessions.SetSecure(rec, session, s.requestIsHTTPS(r)); err != nil {
			t.Fatal(err)
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("cookies = %d", len(cookies))
		}
		return cookies[0]
	}

	c := issue(reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-Proto": "https"}))
	if !c.Secure || !c.HttpOnly {
		t.Fatalf("cookie behind trusted TLS proxy must be Secure+HttpOnly: %+v", c)
	}
	if c.Expires.IsZero() || c.MaxAge < int((29*24*time.Hour).Seconds()) {
		t.Fatalf("remembered session must be a persistent 30 day cookie: expires=%v maxage=%d", c.Expires, c.MaxAge)
	}
	c = issue(reqFrom("203.0.113.2:1", map[string]string{"X-Forwarded-Proto": "https"}))
	if c.Secure {
		t.Fatalf("untrusted peer must not make the cookie Secure")
	}
}
