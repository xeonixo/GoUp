package remotenode

import "testing"

func TestNormalizeControlPlaneURLHelpers(t *testing.T) {
	if got := normalizeControlPlaneURL("https://example.com/node/bootstrap"); got != "https://example.com" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeControlPlaneURL("https://example.com/base/"); got != "https://example.com/base" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadConfigFromEnvHelpers(t *testing.T) {
	t.Setenv("REMOTE_NODE_CONTROL_PLANE_URL", "https://example.com/node/poll")
	t.Setenv("REMOTE_NODE_ID", "n1")
	t.Setenv("REMOTE_NODE_BOOTSTRAP_KEY", "k1")
	t.Setenv("REMOTE_NODE_POLL_SECONDS", "9")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ControlPlaneURL != "https://example.com" {
		t.Fatalf("got %q", cfg.ControlPlaneURL)
	}
	if cfg.InitialPollSeconds != 9 {
		t.Fatalf("got %d", cfg.InitialPollSeconds)
	}
}
