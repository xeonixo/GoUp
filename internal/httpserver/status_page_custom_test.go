package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	store "goup/internal/store/sqlite"
)

func TestStatusPageCustomCSSInjectedAndSanitized(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{
		Enabled: true,
		Title:   "Acme Status",
		CustomCSS: `
.status-banner{outline:2px solid #f00;}
</style><script>alert(1)</script>
<img src=x>
`,
	}, []store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}

	rec := env.get("/acme/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<style>") || !strings.Contains(body, ".status-banner{outline:2px solid #f00;}") {
		t.Fatalf("expected sanitized custom CSS in style tag, got: %s", body)
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "</style><script") || strings.Contains(body, "<script>") || strings.Contains(body, "<img") {
		t.Fatalf("custom CSS leaked markup: %s", body)
	}
	if strings.Count(body, "<style>") != strings.Count(lower, "</style>") {
		t.Fatalf("unbalanced style tags in body")
	}
}

func TestStatusPageCustomDomainHostMapping(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{
		Enabled:      true,
		Title:        "Acme Status",
		CustomDomain: "status.acme.example",
		CustomCSS:    ".status-page{--accent:#123456;}",
	}, []store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}

	getHost := func(path, host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		env.s.handleRoot(rec, req)
		return rec
	}

	for _, path := range []string{"/", "/status"} {
		rec := getHost(path, "status.acme.example")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s host status = %d body=%s", path, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Acme Status") || !strings.Contains(body, "Online Shop") {
			t.Fatalf("%s missing status content: %s", path, body)
		}
		if strings.Contains(body, "/acme/status") {
			t.Fatalf("%s still uses slug paths on custom domain: %s", path, body)
		}
		if !strings.Contains(body, "/status/feed.xml") {
			t.Fatalf("%s missing slug-free feed path", path)
		}
		if !strings.Contains(body, ".status-page{--accent:#123456;}") {
			t.Fatalf("%s missing custom css", path)
		}
	}

	// Unknown host must not map to the tenant status page.
	if rec := getHost("/", "other.example"); rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "Acme Status") {
		t.Fatal("unexpected status page for unrelated host")
	}

	// Disabled page stops custom-domain hosting.
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{
		Enabled: false, Title: "Acme Status", CustomDomain: "status.acme.example",
	}, []store.StatusPageMonitor{{MonitorID: env.upID, DisplayName: "Online Shop"}}); err != nil {
		t.Fatal(err)
	}
	env.s.statusCache.invalidate()
	if rec := getHost("/", "status.acme.example"); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled custom domain status = %d, want 404", rec.Code)
	}
}

func TestLookupTenantByStatusCustomDomainNormalizesHost(t *testing.T) {
	env := newStatusTestEnv(t)
	ctx := context.Background()
	if err := env.st.SaveStatusPageSettings(ctx, store.StatusPageSettings{
		Enabled: true, Title: "Acme Status", CustomDomain: "status.acme.example",
	}, nil); err != nil {
		t.Fatal(err)
	}
	tenant, ok := env.s.lookupTenantByStatusCustomDomain(ctx, "STATUS.ACME.EXAMPLE:443")
	if !ok {
		t.Fatal("expected host mapping")
	}
	if tenant.Slug != "acme" {
		t.Fatalf("slug = %q", tenant.Slug)
	}
	if _, ok := env.s.lookupTenantByStatusCustomDomain(ctx, "nope.example"); ok {
		t.Fatal("unexpected mapping")
	}
}
