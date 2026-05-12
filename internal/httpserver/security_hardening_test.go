package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/auth"
	"goup/internal/config"
	"goup/internal/monitor"
	store "goup/internal/store/sqlite"

	"golang.org/x/crypto/bcrypt"
)

func TestRequireAuthProtectsTenantWithoutProviders(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	tenant, err := cp.CreateTenant(ctx, "tenant-auth", "Tenant Auth", filepath.Join(dir, "tenant-auth.db"))
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	s := &Server{
		controlStore: cp,
		sessions:     auth.NewSessionManager([]byte(strings.Repeat("k", 32)), false),
	}
	nextCalled := false
	handler := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/tenant-auth/", nil)
	req = requestWithTenantSlug(req, tenant.Slug)
	req = requestWithTenantID(req, tenant.ID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatalf("protected tenant request reached next handler without session")
	}
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if location := rec.Header().Get("Location"); location != "/tenant-auth/login" {
		t.Fatalf("redirect location = %q", location)
	}
}

func TestControlPlaneAdminCookieInvalidAfterPasswordChange(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()
	if err := cp.ConfigureSecretKey(strings.Repeat("s", 32)); err != nil {
		t.Fatalf("configure secret key: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("initial-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := cp.CreateControlPlaneAdmin(ctx, "admin", string(hash)); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	admin, err := cp.GetControlPlaneAdmin(ctx)
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}

	s := &Server{
		cfg:            config.Config{BaseURL: "http://127.0.0.1"},
		controlStore:   cp,
		adminCookieKey: strings.Repeat("a", 32),
	}
	rec := httptest.NewRecorder()
	s.setControlPlaneAdminCookie(rec, admin.SessionVersion)

	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	if !s.hasControlPlaneAdminCookie(req) {
		t.Fatalf("fresh admin cookie should be valid")
	}

	nextHash, err := bcrypt.GenerateFromPassword([]byte("next-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash next password: %v", err)
	}
	if err := cp.UpdateControlPlaneAdminPassword(ctx, string(nextHash)); err != nil {
		t.Fatalf("update admin password: %v", err)
	}
	if s.hasControlPlaneAdminCookie(req) {
		t.Fatalf("admin cookie should be invalid after password change")
	}
}

func TestDecodeRemoteNodeResultValidation(t *testing.T) {
	now := time.Now().UTC()
	longMessage := strings.Repeat("x", remoteNodeReportMaxMessageLen+50)
	result, err := decodeRemoteNodeResult(remoteNodeResultPayload{
		MonitorID: 1,
		CheckedAt: now.Format(time.RFC3339),
		Status:    string(monitor.StatusUp),
		LatencyMS: 12,
		Message:   longMessage,
	}, now)
	if err != nil {
		t.Fatalf("decode valid result: %v", err)
	}
	if len(result.Message) != remoteNodeReportMaxMessageLen {
		t.Fatalf("message length = %d, want %d", len(result.Message), remoteNodeReportMaxMessageLen)
	}

	if _, err := decodeRemoteNodeResult(remoteNodeResultPayload{
		MonitorID: 1,
		CheckedAt: now.Add(remoteNodeReportMaxFutureSkew + time.Second).Format(time.RFC3339),
		Status:    string(monitor.StatusUp),
		LatencyMS: 12,
	}, now); err == nil {
		t.Fatalf("expected future timestamp to be rejected")
	}
	if _, err := decodeRemoteNodeResult(remoteNodeResultPayload{
		MonitorID: 1,
		CheckedAt: now.Format(time.RFC3339),
		Status:    string(monitor.StatusUp),
		LatencyMS: -1,
	}, now); err == nil {
		t.Fatalf("expected negative latency to be rejected")
	}
}
