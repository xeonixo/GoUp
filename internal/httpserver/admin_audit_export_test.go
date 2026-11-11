package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	store "goup/internal/store/sqlite"
)

func TestAdminAuditExportCSVAndJSON(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cp, err := store.OpenControlPlane(ctx, filepath.Join(dir, "controlplane.db"))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	defer cp.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("initial-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := cp.CreateControlPlaneAdmin(ctx, "admin", string(hash)); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	admin, err := cp.GetControlPlaneAdmin(ctx)
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}

	if err := cp.InsertAuditEvent(ctx, "alice@example.com", "tenant.create", "tenant", 1, "slug=acme"); err != nil {
		t.Fatalf("insert audit: %v", err)
	}
	if err := cp.InsertAuditEvent(ctx, "bob@example.com", "tenant.update", "tenant", 2, "slug=beta"); err != nil {
		t.Fatalf("insert audit: %v", err)
	}

	s := &Server{
		controlStore:   cp,
		adminCookieKey: strings.Repeat("a", 32),
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	cookieRec := httptest.NewRecorder()
	s.setControlPlaneAdminCookie(cookieRec, httptest.NewRequest(http.MethodGet, "/admin/", nil), admin.SessionVersion)

	handler := s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminAuditExport))

	req := httptest.NewRequest(http.MethodGet, "/admin/audit/export?format=csv&audit_action=tenant.create", nil)
	for _, cookie := range cookieRec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("csv export code=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/csv") {
		t.Fatalf("csv content-type = %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "tenant.create") || strings.Contains(body, "tenant.update") {
		t.Fatalf("csv body = %s", body)
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/audit/export?format=json&audit_actor=bob", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookieRec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("json export code=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode json export: %v\n%s", err, rec.Body.String())
	}
	if len(payload) != 1 || payload[0]["action"] != "tenant.update" {
		t.Fatalf("json payload = %+v", payload)
	}
}

func TestAdminAuditExportRequiresAdmin(t *testing.T) {
	s := &Server{adminCookieKey: strings.Repeat("a", 32)}
	handler := s.requireControlPlaneAdmin(http.HandlerFunc(s.handleAdminAuditExport))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/audit/export?format=csv", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/access" {
		t.Fatalf("unauthenticated: code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}
