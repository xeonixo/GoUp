package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/auth"
	"goup/internal/config"
	store "goup/internal/store/sqlite"
)

func serverWithProxies(t *testing.T, proxies ...string) *Server {
	t.Helper()
	var prefixes []netip.Prefix
	for _, p := range proxies {
		prefixes = append(prefixes, netip.MustParsePrefix(p))
	}
	return &Server{cfg: config.Config{BaseURL: "http://example.test", TrustedProxies: prefixes}}
}

func reqFrom(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	s := serverWithProxies(t, "10.0.0.0/8")
	r := reqFrom("203.0.113.9:4444", map[string]string{"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"})
	if got := s.clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want peer address", got)
	}
	// No trusted proxies configured at all: headers are never honored.
	s = serverWithProxies(t)
	r = reqFrom("10.1.1.1:80", map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if got := s.clientIP(r); got != "10.1.1.1" {
		t.Fatalf("clientIP = %q, want 10.1.1.1", got)
	}
}

func TestClientIPUsesRightmostUntrustedHop(t *testing.T) {
	s := serverWithProxies(t, "10.0.0.0/8", "192.168.0.0/16")
	// client-supplied "6.6.6.6" is spoofed; the real client is 198.51.100.7.
	r := reqFrom("10.0.0.2:5555", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7, 192.168.1.1"})
	if got := s.clientIP(r); got != "198.51.100.7" {
		t.Fatalf("clientIP = %q, want 198.51.100.7", got)
	}
	// Multiple header lines are combined.
	r = reqFrom("10.0.0.2:5555", nil)
	r.Header.Add("X-Forwarded-For", "6.6.6.6")
	r.Header.Add("X-Forwarded-For", "198.51.100.8")
	if got := s.clientIP(r); got != "198.51.100.8" {
		t.Fatalf("clientIP = %q, want 198.51.100.8", got)
	}
	// X-Real-IP is used when there is no XFF.
	r = reqFrom("10.0.0.2:5555", map[string]string{"X-Real-IP": "198.51.100.9"})
	if got := s.clientIP(r); got != "198.51.100.9" {
		t.Fatalf("clientIP = %q, want 198.51.100.9", got)
	}
	// Garbage falls back to the peer.
	r = reqFrom("10.0.0.2:5555", map[string]string{"X-Forwarded-For": "not-an-ip"})
	if got := s.clientIP(r); got != "10.0.0.2" {
		t.Fatalf("clientIP = %q, want peer", got)
	}
}

func TestRateLimitIPNormalizesIPv6ToSlash64(t *testing.T) {
	s := serverWithProxies(t)
	a := s.rateLimitIP(reqFrom("[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:1000", nil))
	b := s.rateLimitIP(reqFrom("[2001:db8:1:2:1111:2222:3333:4444]:2000", nil))
	c := s.rateLimitIP(reqFrom("[2001:db8:1:3::1]:2000", nil))
	if a != b {
		t.Fatalf("same /64 must share a key: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("different /64 must not share a key")
	}
	if got := s.rateLimitIP(reqFrom("192.0.2.5:1", nil)); got != "192.0.2.5" {
		t.Fatalf("IPv4 unchanged, got %q", got)
	}
}

func TestRequestIsHTTPSHonorsTrustedProxyOnly(t *testing.T) {
	s := serverWithProxies(t, "10.0.0.0/8")
	r := reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-Proto": "https"})
	if !s.requestIsHTTPS(r) {
		t.Fatalf("trusted proxy X-Forwarded-Proto=https must count as https")
	}
	r = reqFrom("203.0.113.2:1", map[string]string{"X-Forwarded-Proto": "https"})
	if s.requestIsHTTPS(r) {
		t.Fatalf("untrusted peer must not be able to claim https")
	}
	s.cfg.BaseURL = "https://example.test"
	if !s.requestIsHTTPS(reqFrom("203.0.113.2:1", nil)) {
		t.Fatalf("https base URL implies secure")
	}
}

func TestHSTSAndCookieSecureViaTrustedProxy(t *testing.T) {
	s := serverWithProxies(t, "10.0.0.0/8")
	h := s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-Proto": "https"}))
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatalf("HSTS expected behind trusted TLS-terminating proxy")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqFrom("203.0.113.2:1", map[string]string{"X-Forwarded-Proto": "https"}))
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatalf("HSTS must not be driven by untrusted headers")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("dynamic responses must be no-store")
	}
}

func TestStaticAssetsKeepCaching(t *testing.T) {
	s := serverWithProxies(t)
	h := s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") != "" {
		t.Fatalf("static assets must not get no-store")
	}
}

func TestSameOriginBypassOnlyForExactNodeAPIPaths(t *testing.T) {
	s := &Server{cfg: config.Config{BaseURL: "https://goup.example.test"}}
	called := 0
	h := s.requireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++ }))

	for _, path := range []string{"/node/bootstrap", "/node/poll", "/node/report"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code == http.StatusForbidden {
			t.Fatalf("%s must bypass the origin check", path)
		}
	}
	for _, path := range []string{"/node/", "/node/settings/users/1/role", "/node/bootstrap/x", "/node/bootstrapx", "/node"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s must be subject to the origin check, got %d", path, rec.Code)
		}
	}
	if called != 3 {
		t.Fatalf("next handler called %d times, want 3", called)
	}
}

func TestLogoutIsPostOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	tenant, err := cp.CreateTenant(ctx, "logout-test", "Logout", filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	user, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "alice", "a-long-password-123", "a@example.com", "Alice", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	versionBefore, err := cp.GetTenantMembershipSessionVersion(ctx, tenant.ID, user.UserID)
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{
		cfg:          config.Config{BaseURL: "http://example.test"},
		controlStore: cp,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessions:     auth.NewSessionManager([]byte(strings.Repeat("k", 32)), false),
	}

	// GET must neither log out nor change state.
	rec := httptest.NewRecorder()
	s.handleLogout(rec, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout status = %d, want 405", rec.Code)
	}
	if v, _ := cp.GetTenantMembershipSessionVersion(ctx, tenant.ID, user.UserID); v != versionBefore {
		t.Fatalf("GET logout changed the session version")
	}

	// POST with a valid session logs out and bumps the version.
	setRec := httptest.NewRecorder()
	if err := s.sessions.Set(setRec, auth.UserSession{
		UserID: user.UserID, TenantID: tenant.ID, TenantSlug: tenant.Slug,
		SessionVersion: versionBefore, ExpiresAt: timeInOneHour(),
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	for _, c := range setRec.Result().Cookies() {
		req.AddCookie(c)
	}
	req = requestWithTenantSlug(req, tenant.Slug)
	rec = httptest.NewRecorder()
	s.handleLogout(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST logout status = %d, want 303", rec.Code)
	}
	if v, _ := cp.GetTenantMembershipSessionVersion(ctx, tenant.ID, user.UserID); v <= versionBefore {
		t.Fatalf("logout must bump the session version (before=%d after=%d)", versionBefore, v)
	}
}

func TestSetupTokenRequired(t *testing.T) {
	s := &Server{cfg: config.Config{SetupToken: "my-setup-token"}}
	if !s.verifySetupToken("my-setup-token") {
		t.Fatalf("configured token must verify")
	}
	for _, bad := range []string{"", "my-setup-toke", "MY-SETUP-TOKEN", "other"} {
		if s.verifySetupToken(bad) {
			t.Fatalf("token %q must not verify", bad)
		}
	}

	generated := &Server{}
	token := generated.currentSetupToken()
	if len(token) < 32 {
		t.Fatalf("generated token too short: %q", token)
	}
	if generated.currentSetupToken() != token {
		t.Fatalf("generated token must be stable within a process")
	}
	if !generated.verifySetupToken(token) || generated.verifySetupToken("") {
		t.Fatalf("generated token verification broken")
	}
}

func TestAdminSetupRejectsMissingToken(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	s := &Server{
		cfg:                 config.Config{BaseURL: "http://example.test", SetupToken: "tok-123"},
		controlStore:        cp,
		logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		adminAccessAttempts: make(map[string]localLoginAttempt),
	}
	form := strings.NewReader("username=root&password=a-very-long-password&password_confirm=a-very-long-password&setup_token=wrong")
	req := httptest.NewRequest(http.MethodPost, "/admin/setup", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.handleAdminSetup(rec, req)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Fatalf("expected error redirect, got %q", loc)
	}
	if required, _ := cp.IsSetupRequired(ctx); !required {
		t.Fatalf("setup must remain required after a bad token")
	}
}

func TestRequestBodyLimit(t *testing.T) {
	s := &Server{}
	h := s.limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		}
	}))
	big := strings.NewReader(strings.Repeat("a", defaultMaxRequestBodyBytes+10))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/monitors/save", big))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", rec.Code)
	}
	if maxBodyBytesForPath("/x/monitors/import/preview") <= defaultMaxRequestBodyBytes {
		t.Fatalf("import route must allow larger bodies")
	}
}

func TestReservedSlugHandledBeforeTenantLookup(t *testing.T) {
	if !store.IsReservedTenantSlug("node") || !store.IsReservedTenantSlug("sw.js") {
		t.Fatalf("expected reserved slugs")
	}
}

func timeInOneHour() time.Time { return time.Now().Add(time.Hour) }
