package netguard

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":              true,
		"2606:4700:4700::1111": true,
		"127.0.0.1":            false,
		"10.1.2.3":             false,
		"192.168.1.1":          false,
		"172.16.0.1":           false,
		"100.64.0.1":           false,
		"169.254.169.254":      false,
		"::1":                  false,
		"fc00::1":              false,
		"fe80::1":              false,
		"::ffff:10.0.0.1":      false,
		"0.0.0.0":              false,
	}
	for in, want := range cases {
		if got := IsPublicIP(netip.MustParseAddr(in)); got != want {
			t.Errorf("IsPublicIP(%s)=%v want %v", in, got, want)
		}
	}
}

func TestAllowedPolicy(t *testing.T) {
	meta := []string{"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}
	for _, m := range meta {
		for _, priv := range []bool{false, true} {
			if Allowed(netip.MustParseAddr(m), priv) {
				t.Errorf("metadata %s must be blocked (allowPrivate=%v)", m, priv)
			}
		}
	}
	if Allowed(netip.MustParseAddr("10.0.0.5"), false) {
		t.Error("private must be blocked by default")
	}
	if !Allowed(netip.MustParseAddr("10.0.0.5"), true) {
		t.Error("private must be allowed when opted in")
	}
	if !Allowed(netip.MustParseAddr("8.8.8.8"), false) {
		t.Error("public must be allowed")
	}
}

func TestValidateURL(t *testing.T) {
	bad := []string{"http://example.com", "https://user:pw@example.com", "https://127.0.0.1/x", "https://localhost/x", "https:///x", "https://[::1]/"}
	for _, raw := range bad {
		if _, err := ValidateURL(raw, false); err == nil {
			t.Errorf("expected %q to be rejected", raw)
		}
	}
	if _, err := ValidateURL("https://192.168.1.10:8448", true); err != nil {
		t.Errorf("private allowed when opted in: %v", err)
	}
	if _, err := ValidateURL("https://169.254.169.254/", true); err == nil {
		t.Error("metadata must stay blocked")
	}
	if _, err := ValidateURL("https://example.com/path", false); err != nil {
		t.Errorf("public host should pass: %v", err)
	}
}

func TestClientBlocksLoopbackAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	client := NewHTTPClient(Options{Timeout: 2 * time.Second})
	if _, err := client.Get(srv.URL); err == nil {
		t.Fatal("expected loopback dial to be blocked")
	}
	allowed := NewHTTPClient(Options{Timeout: 2 * time.Second, AllowPrivate: true})
	resp, err := allowed.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected allowed with AllowPrivate: %v", err)
	}
	resp.Body.Close()
}

func TestClientBlocksMetadataEvenWhenPrivateAllowed(t *testing.T) {
	client := NewHTTPClient(Options{Timeout: time.Second, AllowPrivate: true})
	if _, err := client.Get("http://169.254.169.254/latest/meta-data"); err == nil {
		t.Fatal("metadata address must be blocked")
	}
}

func TestRedirectIsRechecked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer srv.Close()
	client := NewHTTPClient(Options{Timeout: time.Second, AllowPrivate: true, MaxRedirects: 3})
	if _, err := client.Get(srv.URL); err == nil {
		t.Fatal("redirect to metadata must fail")
	}
	noRedir := NewHTTPClient(Options{Timeout: time.Second, AllowPrivate: true})
	if _, err := noRedir.Get(srv.URL); err == nil {
		t.Fatal("redirects disabled by default")
	}
}
