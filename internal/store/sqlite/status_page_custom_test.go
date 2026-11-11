package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goup/internal/monitor"
)

func TestSanitizeStatusPageCustomCSS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "plain css", in: ".status-page{color:red;}", want: ".status-page{color:red;}"},
		{name: "strip style end", in: "body{color:red}</style><script>alert(1)</script>", want: "body{color:red}alert(1)"},
		{name: "strip style end spaced", in: "a{}</ Style >b{}", want: "a{}b{}"},
		{name: "strip html tags", in: ".x{color:red}<img src=x onerror=alert(1)>.y{color:blue}", want: ".x{color:red}.y{color:blue}"},
		{name: "strip script tags", in: "h1{color:red}<script>evil()</script>h2{color:blue}", want: "h1{color:red}evil()h2{color:blue}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeStatusPageCustomCSS(tc.in); got != tc.want {
				t.Fatalf("SanitizeStatusPageCustomCSS(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	oversized := strings.Repeat("a", statusPageCustomCSSMaxBytes+128)
	got := SanitizeStatusPageCustomCSS(oversized)
	if len(got) > statusPageCustomCSSMaxBytes {
		t.Fatalf("expected size cap at %d bytes, got %d", statusPageCustomCSSMaxBytes, len(got))
	}
	if strings.Contains(got, "<") || strings.Contains(got, ">") {
		t.Fatalf("sanitized CSS still contains angle brackets: %q", got)
	}
}

func TestNormalizeStatusPageCustomDomain(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"status.example.com", "status.example.com"},
		{"HTTPS://Status.Example.COM/path", "status.example.com"},
		{"status.example.com:443", "status.example.com"},
		{"http://status.example.com:8080/", "status.example.com"},
		{"not a domain", ""},
		{"localhost", ""},
		{".example.com", ""},
		{"status.example.com.", "status.example.com"},
	}
	for _, tc := range cases {
		if got := NormalizeStatusPageCustomDomain(tc.in); got != tc.want {
			t.Errorf("NormalizeStatusPageCustomDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStatusPageSettingsCustomCSSAndDomainPersist(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "tenant.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name: "Web", Kind: monitor.KindTCP, Target: "example.com:443",
		Interval: time.Minute, Timeout: 5 * time.Second, Enabled: true,
		ExecutorKind: "local", TLSMode: monitor.TLSModeNone, CertWarningDays: 7, ConfirmAfter: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = st.SaveStatusPageSettings(ctx, StatusPageSettings{
		Enabled:      true,
		Title:        "Acme",
		CustomCSS:    ".banner{color:red}</style><script>x()</script>",
		CustomDomain: "HTTPS://Status.Acme.Example/",
	}, []StatusPageMonitor{{MonitorID: id, DisplayName: "Web"}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := st.GetStatusPageSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.CustomDomain != "status.acme.example" {
		t.Fatalf("custom_domain = %q", got.CustomDomain)
	}
	if strings.Contains(strings.ToLower(got.CustomCSS), "</style>") || strings.Contains(strings.ToLower(got.CustomCSS), "<script") {
		t.Fatalf("custom_css not sanitized: %q", got.CustomCSS)
	}
	if !strings.Contains(got.CustomCSS, ".banner{color:red}") || !strings.Contains(got.CustomCSS, "x()") {
		t.Fatalf("unexpected custom_css: %q", got.CustomCSS)
	}
}
