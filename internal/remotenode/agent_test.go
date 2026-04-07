//go:build ignore
// +build ignore

package remotenode

import "testing"

func TestNormalizeControlPlaneURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: " https://example.com/node/bootstrap ", want: "https://example.com"},
		{in: "https://example.com/node/poll", want: "https://example.com"},
		{in: "https://example.com/node/report/", want: "https://example.com"},
		{in: "https://example.com/base/", want: "https://example.com/base"},
	}
	for _, tc := range cases {
		if got := normalizeControlPlaneURL(tc.in); got != tc.want {
			t.Fatalf("normalizeControlPlaneURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("REMOTE_NODE_CONTROL_PLANE_URL", "https://example.com/node/bootstrap")
	t.Setenv("REMOTE_NODE_ID", "node-1")
	t.Setenv("REMOTE_NODE_BOOTSTRAP_KEY", "secret")
	t.Setenv("REMOTE_NODE_POLL_SECONDS", "15")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ControlPlaneURL != "https://example.com" {
		t.Fatalf("ControlPlaneURL = %q, want %q", cfg.ControlPlaneURL, "https://example.com")
	}
	if cfg.InitialPollSeconds != 15 {
		t.Fatalf("InitialPollSeconds = %d, want 15", cfg.InitialPollSeconds)
	}
}

func TestLoadConfigFromEnvMissingRequired(t *testing.T) {
	t.Setenv("REMOTE_NODE_CONTROL_PLANE_URL", "")
	t.Setenv("REMOTE_NODE_ID", "")
	t.Setenv("REMOTE_NODE_BOOTSTRAP_KEY", "")

	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected error for missing required env vars")
	}
}








}	}		t.Fatalf("expected error for missing required env vars")	if _, err := LoadConfigFromEnv(); err == nil {	t.Setenv("REMOTE_NODE_BOOTSTRAP_KEY", "")	t.Setenv("REMOTE_NODE_ID", "")	t.Setenv("REMOTE_NODE_CONTROL_PLANE_URL", "")func TestLoadConfigFromEnvMissingRequired(t *testing.T) {}	}		t.Fatalf("InitialPollSeconds = %d, want 15", cfg.InitialPollSeconds)	if cfg.InitialPollSeconds != 15 {	}		t.Fatalf("ControlPlaneURL = %q, want %q", cfg.ControlPlaneURL, "https://example.com")	if cfg.ControlPlaneURL != "https://example.com" {	}		t.Fatalf("unexpected error: %v", err)	if err != nil {	cfg, err := LoadConfigFromEnv()	t.Setenv("REMOTE_NODE_POLL_SECONDS", "15")	t.Setenv("REMOTE_NODE_BOOTSTRAP_KEY", "secret")	t.Setenv("REMOTE_NODE_ID", "node-1")	t.Setenv("REMOTE_NODE_CONTROL_PLANE_URL", "https://example.com/node/bootstrap")func TestLoadConfigFromEnv(t *testing.T) {}	}		}			t.Fatalf("normalizeControlPlaneURL(%q) = %q, want %q", tc.in, got, tc.want)		if got := normalizeControlPlaneURL(tc.in); got != tc.want {	for _, tc := range cases {	}		{in: "https://example.com/base/", want: "https://example.com/base"},		{in: "https://example.com/node/report/", want: "https://example.com"},		{in: "https://example.com/node/poll", want: "https://example.com"},