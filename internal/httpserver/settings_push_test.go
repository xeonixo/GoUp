package httpserver

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/auth"
	"goup/internal/config"
	store "goup/internal/store/sqlite"
)

type pushHandlerEnv struct {
	s       *Server
	cp      *store.ControlPlaneStore
	tenant  store.Tenant
	alice   store.LocalUser
	bob     store.LocalUser
	cookies map[int64][]*http.Cookie
}

func newPushHandlerEnv(t *testing.T) *pushHandlerEnv {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cp.Close() })
	if err := cp.ConfigureSecretKey("test-secret-key-for-push-handlers"); err != nil {
		t.Fatal(err)
	}
	tenant, err := cp.CreateTenant(ctx, "pushtest", "Push", filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	alice, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "alice", "a-long-password-123", "a@example.com", "Alice", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := cp.CreateLocalUserForTenant(ctx, tenant.ID, "bob", "a-long-password-123", "b@example.com", "Bob", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg:          config.Config{BaseURL: "https://goup.example"},
		controlStore: cp,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessions:     auth.NewSessionManager([]byte(strings.Repeat("k", 32)), false),
	}
	env := &pushHandlerEnv{s: s, cp: cp, tenant: tenant, alice: alice, bob: bob, cookies: map[int64][]*http.Cookie{}}
	for _, u := range []store.LocalUser{alice, bob} {
		version, err := cp.GetTenantMembershipSessionVersion(ctx, tenant.ID, u.UserID)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		if err := s.sessions.Set(rec, auth.UserSession{
			UserID: u.UserID, TenantID: tenant.ID, TenantSlug: tenant.Slug, Role: "viewer",
			SessionVersion: version, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		env.cookies[u.UserID] = rec.Result().Cookies()
	}
	return env
}

func (e *pushHandlerEnv) call(user store.LocalUser, h http.HandlerFunc, method string, body any) (int, map[string]any) {
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, "/settings/push/x", reader)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1")
	for _, c := range e.cookies[user.UserID] {
		req.AddCookie(c)
	}
	req = requestWithTenantSlug(req, e.tenant.Slug)
	rec := httptest.NewRecorder()
	h(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func validSubscription(t *testing.T, endpoint string) map[string]any {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	_, _ = rand.Read(auth)
	return map[string]any{
		"endpoint": endpoint,
		"keys": map[string]string{
			"p256dh": base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
			"auth":   base64.RawURLEncoding.EncodeToString(auth),
		},
	}
}

func TestPushSubscribeValidatesEndpointAndKeys(t *testing.T) {
	e := newPushHandlerEnv(t)
	for _, endpoint := range []string{
		"https://evil.example.com/push",
		"http://web.push.apple.com/x",
		"https://127.0.0.1/x",
		"https://web.push.apple.com.evil.example/x",
	} {
		if code, body := e.call(e.alice, e.s.handlePushSubscribe, http.MethodPost, validSubscription(t, endpoint)); code != http.StatusBadRequest || body["error"] != "invalid_endpoint" {
			t.Errorf("%s: %d %v, want 400 invalid_endpoint", endpoint, code, body)
		}
	}

	bad := validSubscription(t, "https://web.push.apple.com/abc")
	bad["keys"] = map[string]string{"p256dh": "AAAA", "auth": "AAAA"}
	if code, body := e.call(e.alice, e.s.handlePushSubscribe, http.MethodPost, bad); code != http.StatusBadRequest || body["error"] != "invalid_keys" {
		t.Errorf("bad keys: %d %v", code, body)
	}

	if code, body := e.call(e.alice, e.s.handlePushSubscribe, http.MethodPost, validSubscription(t, "https://web.push.apple.com/abc")); code != http.StatusOK || body["ok"] != true {
		t.Fatalf("valid subscription rejected: %d %v", code, body)
	}
	subs, _ := e.cp.ListUserPushSubscriptions(context.Background(), e.tenant.ID, e.alice.UserID)
	if len(subs) != 1 || subs[0].DeviceLabel != "iPhone · Safari" || !subs[0].NotifyDown {
		t.Fatalf("stored subscription = %#v", subs)
	}
}

func TestPushRequiresLoginAndMethod(t *testing.T) {
	e := newPushHandlerEnv(t)
	anon := store.LocalUser{UserID: 9999}
	if code, _ := e.call(anon, e.s.handlePushKey, http.MethodGet, nil); code != http.StatusUnauthorized {
		t.Errorf("anonymous key request = %d, want 401", code)
	}
	if code, _ := e.call(e.alice, e.s.handlePushSubscribe, http.MethodGet, nil); code != http.StatusMethodNotAllowed {
		t.Errorf("GET subscribe = %d, want 405", code)
	}
	code, body := e.call(e.alice, e.s.handlePushKey, http.MethodGet, nil)
	key, _ := body["publicKey"].(string)
	if code != http.StatusOK || len(key) < 80 {
		t.Errorf("key response = %d %v", code, body)
	}
}

func TestPushUnsubscribeAndPrefsOnlyAffectOwnDevices(t *testing.T) {
	e := newPushHandlerEnv(t)
	endpoint := "https://web.push.apple.com/alices-phone"
	_, body := e.call(e.alice, e.s.handlePushSubscribe, http.MethodPost, validSubscription(t, endpoint))
	id := int64(body["id"].(float64))

	// Bob can neither remove nor change Alice's device.
	if code, _ := e.call(e.bob, e.s.handlePushUnsubscribe, http.MethodPost, map[string]any{"endpoint": endpoint}); code != http.StatusNotFound {
		t.Errorf("foreign unsubscribe by endpoint = %d, want 404", code)
	}
	if code, _ := e.call(e.bob, e.s.handlePushUnsubscribe, http.MethodPost, map[string]any{"id": id}); code != http.StatusNotFound {
		t.Errorf("foreign unsubscribe by id = %d, want 404", code)
	}
	if code, _ := e.call(e.bob, e.s.handlePushPrefs, http.MethodPost, map[string]any{"id": id, "down": false}); code != http.StatusNotFound {
		t.Errorf("foreign prefs = %d, want 404", code)
	}
	subs, _ := e.cp.ListUserPushSubscriptions(context.Background(), e.tenant.ID, e.alice.UserID)
	if len(subs) != 1 || !subs[0].NotifyDown {
		t.Fatalf("Alice's device was touched: %#v", subs)
	}

	// Alice can change prefs (missing fields keep their value) and remove it.
	if code, _ := e.call(e.alice, e.s.handlePushPrefs, http.MethodPost, map[string]any{"id": id, "down": false}); code != http.StatusOK {
		t.Fatalf("own prefs = %d", code)
	}
	subs, _ = e.cp.ListUserPushSubscriptions(context.Background(), e.tenant.ID, e.alice.UserID)
	if subs[0].NotifyDown || !subs[0].NotifyRecovery {
		t.Errorf("prefs = %#v", subs[0])
	}
	if code, _ := e.call(e.alice, e.s.handlePushUnsubscribe, http.MethodPost, map[string]any{"endpoint": endpoint}); code != http.StatusOK {
		t.Errorf("own unsubscribe = %d", code)
	}
}

func TestPushSubscribeLimitAndOldEndpointInheritance(t *testing.T) {
	e := newPushHandlerEnv(t)
	for i := 0; i < store.MaxPushSubscriptionsPerUser; i++ {
		if code, body := e.call(e.alice, e.s.handlePushSubscribe, http.MethodPost, validSubscription(t, fmt.Sprintf("https://web.push.apple.com/d%d", i))); code != http.StatusOK {
			t.Fatalf("device %d: %d %v", i, code, body)
		}
	}
	if code, body := e.call(e.alice, e.s.handlePushSubscribe, http.MethodPost, validSubscription(t, "https://web.push.apple.com/overflow")); code != http.StatusConflict || body["error"] != "limit_reached" {
		t.Errorf("11th device: %d %v", code, body)
	}

	// A rotated subscription replaces its predecessor and keeps its preferences.
	subs, _ := e.cp.ListUserPushSubscriptions(context.Background(), e.tenant.ID, e.alice.UserID)
	old := subs[0]
	e.call(e.alice, e.s.handlePushPrefs, http.MethodPost, map[string]any{"id": old.ID, "reminder": false})
	rotated := validSubscription(t, "https://web.push.apple.com/rotated")
	rotated["oldEndpoint"] = old.Endpoint
	if code, body := e.call(e.alice, e.s.handlePushSubscribe, http.MethodPost, rotated); code != http.StatusOK {
		t.Fatalf("rotate at limit: %d %v", code, body)
	}
	subs, _ = e.cp.ListUserPushSubscriptions(context.Background(), e.tenant.ID, e.alice.UserID)
	if len(subs) != store.MaxPushSubscriptionsPerUser {
		t.Fatalf("device count = %d", len(subs))
	}
	for _, s := range subs {
		if s.Endpoint == old.Endpoint {
			t.Fatal("old endpoint still registered")
		}
		if s.Endpoint == "https://web.push.apple.com/rotated" && s.NotifyReminder {
			t.Error("preferences were not inherited from the old endpoint")
		}
	}
}

func TestPushTestIsRateLimitedPerUser(t *testing.T) {
	e := newPushHandlerEnv(t)
	// Without devices the call is answered locally (no outbound request) but still counts.
	if code, body := e.call(e.alice, e.s.handlePushTest, http.MethodPost, nil); code != http.StatusNotFound || body["error"] != "no_devices" {
		t.Fatalf("first test = %d %v", code, body)
	}
	if code, body := e.call(e.alice, e.s.handlePushTest, http.MethodPost, nil); code != http.StatusTooManyRequests || body["error"] != "rate_limited" {
		t.Fatalf("second test = %d %v, want 429", code, body)
	}
	// Another user has an own budget.
	if code, _ := e.call(e.bob, e.s.handlePushTest, http.MethodPost, nil); code == http.StatusTooManyRequests {
		t.Fatal("rate limit must be per user")
	}
	if e.s.allowPushTest(e.tenant.ID, e.alice.UserID, time.Now().Add(11*time.Second)) != true {
		t.Fatal("limit must expire after 10s")
	}
}

func TestDeviceLabelFromUserAgent(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1": "iPhone · Safari",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36":                                "Android · Chrome",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0":                                              "Linux · Firefox",
		"": "Browser",
	}
	for ua, want := range cases {
		if got := deviceLabelFromUserAgent(ua); got != want {
			t.Errorf("%q = %q, want %q", ua, got, want)
		}
	}
}

func TestSettingsProfileRendersPushSection(t *testing.T) {
	s := renderTestServer(t)
	user := &auth.UserSession{UserID: 1, Role: "viewer", TenantSlug: "acme", Email: "a@example.com"}
	rec := httptest.NewRecorder()
	s.render(rec, "settings_profile", pageData{
		User: user, AppBase: "/acme/",
		PushDevices: []pushDeviceView{{ID: 4, Label: "iPhone · Safari", Endpoint: "https://web.push.apple.com/x", Down: true}},
	})
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, body)
	}
	for _, want := range []string{`data-push-key-url="/acme/settings/push/key"`, `data-push-enable`, `data-id="4"`, `data-push-pref="down" checked`, `iPhone · Safari`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "style=") {
		t.Error("inline styles are blocked by the CSP")
	}
}
