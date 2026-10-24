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

	"goup/internal/monitor"
	store "goup/internal/store/sqlite"
)

type heartbeatEnv struct {
	s     *Server
	st    *store.Store
	mux   *http.ServeMux
	id    int64
	token string
}

func newHeartbeatEnv(t *testing.T) *heartbeatEnv {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	t.Cleanup(func() { cp.Close() })
	if _, err := cp.CreateTenant(ctx, "acme", "Acme", filepath.Join(dir, "acme.db")); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	st, err := store.Open(ctx, filepath.Join(dir, "tenant.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{
		store:             st,
		controlStore:      cp,
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		bootstrapAttempts: make(map[string]localLoginAttempt),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hb/{tenantSlug}/{token}", s.handleHeartbeatPing)
	mux.HandleFunc("/hb/{tenantSlug}/{token}/fail", s.handleHeartbeatFail)

	id, err := st.CreateMonitor(ctx, store.CreateMonitorParams{
		Name: "backup", Kind: monitor.KindHeartbeat, Interval: time.Hour, Timeout: 5 * time.Minute, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create heartbeat monitor: %v", err)
	}
	snap, err := st.GetMonitorSnapshot(ctx, id)
	if err != nil || snap.Monitor.HeartbeatToken == "" {
		t.Fatalf("expected token, got %+v err=%v", snap.Monitor, err)
	}
	return &heartbeatEnv{s: s, st: st, mux: mux, id: id, token: snap.Monitor.HeartbeatToken}
}

func (e *heartbeatEnv) call(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.7:5555"
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func (e *heartbeatEnv) snapshot(t *testing.T) monitor.Snapshot {
	t.Helper()
	snap, err := e.st.GetMonitorSnapshot(context.Background(), e.id)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return snap
}

func TestHeartbeatPingRecordsUp(t *testing.T) {
	e := newHeartbeatEnv(t)
	rec := e.call(http.MethodPost, "/hb/acme/"+e.token, "backup done in 12s")
	if rec.Code != http.StatusOK || rec.Body.String() != "OK" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("unexpected response %d %q %q", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	snap := e.snapshot(t)
	if snap.Monitor.LastHeartbeatAt == nil || snap.Monitor.LastHeartbeatFailed {
		t.Fatalf("heartbeat not recorded: %+v", snap.Monitor)
	}
	if snap.LastResult == nil || snap.LastResult.Status != monitor.StatusUp || snap.LastResult.Message != "backup done in 12s" {
		t.Fatalf("unexpected result: %+v", snap.LastResult)
	}

	// GET without body uses the default message; HEAD has no body.
	time.Sleep(2100 * time.Millisecond)
	if rec := e.call(http.MethodGet, "/hb/acme/"+e.token, ""); rec.Code != http.StatusOK {
		t.Fatalf("GET status %d", rec.Code)
	}
	if got := e.snapshot(t).LastResult.Message; got != monitor.HeartbeatMessageReceived {
		t.Fatalf("message = %q", got)
	}
	if rec := e.call(http.MethodHead, "/hb/acme/"+e.token, ""); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD status %d body %q", rec.Code, rec.Body.String())
	}
	if rec := e.call(http.MethodDelete, "/hb/acme/"+e.token, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE status %d", rec.Code)
	}
}

func TestHeartbeatMessageTruncatedAndBinaryIgnored(t *testing.T) {
	e := newHeartbeatEnv(t)
	e.call(http.MethodPost, "/hb/acme/"+e.token, strings.Repeat("x", 500))
	if got := len(e.snapshot(t).LastResult.Message); got != heartbeatMessageMaxRunes {
		t.Fatalf("message length = %d, want %d", got, heartbeatMessageMaxRunes)
	}
	time.Sleep(2100 * time.Millisecond)
	e.call(http.MethodPost, "/hb/acme/"+e.token, "a\x00b\x01")
	if got := e.snapshot(t).LastResult.Message; got != monitor.HeartbeatMessageReceived {
		t.Fatalf("binary body must fall back to default, got %q", got)
	}
	if rec := e.call(http.MethodPost, "/hb/acme/"+e.token, strings.Repeat("x", heartbeatBodyLimit+1)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status %d", rec.Code)
	}
}

func TestHeartbeatFailRecordsDown(t *testing.T) {
	e := newHeartbeatEnv(t)
	rec := e.call(http.MethodPost, "/hb/acme/"+e.token+"/fail", "disk full")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	snap := e.snapshot(t)
	if snap.LastResult == nil || snap.LastResult.Status != monitor.StatusDown || snap.LastResult.Message != "disk full" {
		t.Fatalf("unexpected result: %+v", snap.LastResult)
	}
	if !snap.Monitor.LastHeartbeatFailed {
		t.Fatalf("failed flag not stored")
	}
	// The checker must keep the monitor down until a successful ping arrives.
	if got := (monitor.HeartbeatChecker{}).Check(context.Background(), snap.Monitor); got.Status != monitor.StatusDown {
		t.Fatalf("checker status after /fail = %s", got.Status)
	}
	time.Sleep(2100 * time.Millisecond)
	e.call(http.MethodGet, "/hb/acme/"+e.token, "")
	if got := e.snapshot(t).LastResult.Status; got != monitor.StatusUp {
		t.Fatalf("recovery status = %s", got)
	}
}

func TestHeartbeatUnknownTokenAndSlugLookAlike(t *testing.T) {
	e := newHeartbeatEnv(t)
	bad := e.call(http.MethodGet, "/hb/acme/does-not-exist", "")
	noTenant := e.call(http.MethodGet, "/hb/nobody/"+e.token, "")
	if bad.Code != http.StatusNotFound || noTenant.Code != http.StatusNotFound || bad.Body.String() != noTenant.Body.String() {
		t.Fatalf("expected identical 404s, got %d %q / %d %q", bad.Code, bad.Body.String(), noTenant.Code, noTenant.Body.String())
	}
	if e.snapshot(t).LastResult != nil {
		t.Fatalf("unknown token must not record anything")
	}
}

func TestHeartbeatPausedMonitorRemembersPingOnly(t *testing.T) {
	e := newHeartbeatEnv(t)
	if err := e.st.SetMonitorEnabled(context.Background(), e.id, false); err != nil {
		t.Fatal(err)
	}
	if rec := e.call(http.MethodGet, "/hb/acme/"+e.token, ""); rec.Code != http.StatusOK {
		t.Fatalf("paused status %d", rec.Code)
	}
	snap := e.snapshot(t)
	if snap.LastResult != nil {
		t.Fatalf("paused monitor must not record a result: %+v", snap.LastResult)
	}
	if snap.Monitor.LastHeartbeatAt == nil {
		t.Fatalf("ping time should still be remembered")
	}
}

func TestHeartbeatRateLimitsUnknownTokens(t *testing.T) {
	e := newHeartbeatEnv(t)
	for i := 0; i < bootstrapMaxFailures; i++ {
		if rec := e.call(http.MethodGet, "/hb/acme/wrong", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("attempt %d status %d", i, rec.Code)
		}
	}
	if rec := e.call(http.MethodGet, "/hb/acme/wrong", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated misses, got %d", rec.Code)
	}
	// Even a correct token from the locked-out address is refused.
	if rec := e.call(http.MethodGet, "/hb/acme/"+e.token, ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked-out client got %d", rec.Code)
	}
}

func TestHeartbeatPathsExemptFromSameOriginAndBodyLimited(t *testing.T) {
	if !isRemoteNodeAPIPath("/hb/acme/abc") || isRemoteNodeAPIPath("/acme/monitors/save") {
		t.Fatalf("same-origin exemption wrong")
	}
	if maxBodyBytesForPath("/hb/acme/abc") != heartbeatBodyLimit {
		t.Fatalf("heartbeat body limit not applied")
	}
}

func TestHeartbeatSubtitle(t *testing.T) {
	got := heartbeatSubtitle(monitor.Monitor{Interval: 24 * time.Hour, Timeout: 5 * time.Minute})
	if got != "Heartbeat · alle 1d · Toleranz 5m" {
		t.Fatalf("subtitle = %q", got)
	}
}
