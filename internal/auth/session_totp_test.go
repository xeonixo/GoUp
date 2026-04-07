package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSafeSlugPath(t *testing.T) {
	if got := safeSlugPath("tenant-1"); got != "/tenant-1" {
		t.Fatalf("got %q", got)
	}
	if got := safeSlugPath("../bad"); got != "/" {
		t.Fatalf("invalid slug must map to root, got %q", got)
	}
}

func TestSessionManagerSetAndGetForTenant(t *testing.T) {
	m := NewSessionManager([]byte(strings.Repeat("k", 32)), false)
	rec := httptest.NewRecorder()
	exp := time.Now().UTC().Add(30 * time.Minute)
	err := m.Set(rec, UserSession{UserID: 1, TenantSlug: "demo", ExpiresAt: exp})
	if err != nil {
		t.Fatalf("set session: %v", err)
	}

	res := rec.Result()
	if len(res.Cookies()) == 0 {
		t.Fatalf("no cookies set")
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/demo/", nil)
	for _, c := range res.Cookies() {
		req.AddCookie(c)
	}
	sess, err := m.GetForTenant(req, "demo")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess.UserID != 1 || sess.TenantSlug != "demo" {
		t.Fatalf("unexpected session: %+v", sess)
	}
}

func TestTenantOIDCCookieNames(t *testing.T) {
	state, nonce, provider := tenantOIDCCookieNames("my tenant")
	if !strings.Contains(state, "my_tenant") || !strings.Contains(nonce, "my_tenant") || !strings.Contains(provider, "my_tenant") {
		t.Fatalf("unexpected names: %s %s %s", state, nonce, provider)
	}
}

func TestCleanSpaces(t *testing.T) {
	if got := cleanSpaces("a  b   c"); got != "a b c" {
		t.Fatalf("got %q", got)
	}
}

func TestTOTPValidate(t *testing.T) {
	secret, err := TOTPGenerateSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	code := totpGenerate(secret, time.Now().Unix()/30)
	if !TOTPValidate(secret, code) {
		t.Fatalf("expected generated code to validate")
	}
	if TOTPValidate(secret, "000000") {
		t.Fatalf("unexpected validation for wrong code")
	}
}
