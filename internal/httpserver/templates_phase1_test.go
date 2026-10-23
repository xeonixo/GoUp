package httpserver

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"goup/internal/auth"
	store "goup/internal/store/sqlite"
	"goup/web"
)

func renderTestServer(t *testing.T) *Server {
	t.Helper()
	templates, err := parseTemplates()
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	catalog, err := loadTranslationCatalog(web.FS, "i18n")
	if err != nil {
		t.Fatalf("load i18n: %v", err)
	}
	return &Server{templates: templates, i18n: catalog, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestSecurityTemplatesRender(t *testing.T) {
	s := renderTestServer(t)
	user := &auth.UserSession{UserID: 1, Role: "admin", TenantSlug: "acme", Email: "a@example.com"}
	blocked := []store.TenantUser{{UserID: 9, DisplayName: "Gone", Email: "gone@example.com", Blocked: true}}

	cases := []struct {
		name string
		data pageData
		want []string
	}{
		{"admin_setup", pageData{TOTPSecret: "S", TOTPProvisioningURI: "otpauth://x"}, []string{`name="setup_token"`}},
		{"settings_users", pageData{User: user, AppBase: "/acme/", BlockedTenantUsers: blocked}, []string{`/acme/settings/users/9/unblock`, `action="/acme/auth/logout"`}},
		{"admin_local_users", pageData{ControlPlaneAdmin: true, AdminTenant: store.Tenant{ID: 3}, BlockedTenantUsers: blocked}, []string{`/admin/tenants/3/users/9/unblock`, `action="/admin/access?logout=1"`}},
		{"settings_provider_form", pageData{User: user, AppBase: "/acme/", FormAction: "/acme/settings/providers/save", AdminProvider: store.AuthProvider{DefaultRole: "admin", AllowedGroups: "g1"}}, []string{`name="default_role"`, `name="allowed_email_domains"`, `value="g1"`}},
		{"admin_provider_form", pageData{ControlPlaneAdmin: true, AdminTenant: store.Tenant{ID: 3}, FormAction: "/x"}, []string{`name="allowed_groups"`}},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		s.render(rec, tc.name, tc.data)
		body := rec.Body.String()
		if rec.Code != 200 {
			t.Fatalf("%s: status %d body %s", tc.name, rec.Code, body)
		}
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q", tc.name, want)
			}
		}
		// Logout must be a POST form, never a plain link.
		if strings.Contains(body, `href="/admin/access?logout=1"`) || strings.Contains(body, `auth/logout" aria`) {
			t.Errorf("%s: logout rendered as a link", tc.name)
		}
	}
}

func TestNewI18nKeysExistInBothLanguages(t *testing.T) {
	s := renderTestServer(t)
	for _, key := range []string{
		"admin.setup.token_label", "admin.setup.token_hint",
		"admin.provider_form.default_role_label", "admin.provider_form.allowed_domains_label",
		"admin.provider_form.allowed_groups_label", "admin.provider_form.policy_note",
		"settings.users.blocked_title", "settings.users.blocked_hint", "settings.users.readd_button",
	} {
		for _, lang := range []string{"de", "en"} {
			if strings.TrimSpace(s.translationsForLanguage(lang)[key]) == "" {
				t.Errorf("missing translation %s/%s", lang, key)
			}
		}
	}
}
