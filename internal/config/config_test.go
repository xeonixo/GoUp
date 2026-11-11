package config

import (
	"os"
	"testing"
)

func validConfig() Config {
	return Config{
		Addr:                 ":8080",
		BaseURL:              "https://example.com",
		SessionKey:           "session-key-1234567890-abcdefghijkl",
		SSOSecretKey:         "sso-secret-key-123456-abcdefghijklmn",
		ControlPlaneAdminKey: "admin-cookie-key-123456-abcdefghijklm",
	}
}

func TestSecureCookies(t *testing.T) {
	if !(Config{BaseURL: "https://example.com"}).SecureCookies() {
		t.Fatalf("expected secure cookies for https")
	}
	if (Config{BaseURL: "http://example.com"}).SecureCookies() {
		t.Fatalf("expected insecure cookies for http")
	}
}

func TestValidateOIDCPartialFails(t *testing.T) {
	cfg := validConfig()
	cfg.Auth = AuthConfig{
		Mode: AuthModeOIDC,
		OIDC: OIDCConfig{
			IssuerURL: "https://issuer.example.com",
			ClientID:  "client",
		},
	}
	if err := validate(cfg); err == nil {
		t.Fatalf("expected error for partial global OIDC config")
	}
}

func TestValidateOIDCTenantOnlyAllowed(t *testing.T) {
	cfg := validConfig()
	cfg.Auth = AuthConfig{
		Mode: AuthModeOIDC,
		OIDC: OIDCConfig{},
	}
	if err := validate(cfg); err != nil {
		t.Fatalf("expected tenant-only OIDC to be valid, got: %v", err)
	}
}

func TestValidateRequiresSecurityKeys(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{
			name: "session key",
			mut:  func(cfg *Config) { cfg.SessionKey = "" },
		},
		{
			name: "sso secret key",
			mut:  func(cfg *Config) { cfg.SSOSecretKey = "" },
		},
		{
			name: "control plane admin key",
			mut:  func(cfg *Config) { cfg.ControlPlaneAdminKey = "" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mut(&cfg)
			if err := validate(cfg); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestValidateRequiresLongSecurityKeys(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{
			name: "session key",
			mut:  func(cfg *Config) { cfg.SessionKey = "short" },
		},
		{
			name: "sso secret key",
			mut:  func(cfg *Config) { cfg.SSOSecretKey = "short" },
		},
		{
			name: "control plane admin key",
			mut:  func(cfg *Config) { cfg.ControlPlaneAdminKey = "short" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mut(&cfg)
			if err := validate(cfg); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestValidateRejectsPlaceholderKeys(t *testing.T) {
	cfg := validConfig()
	cfg.SessionKey = "replace-with-64-hex-characters-aaaaaaaaaaaaaaaa"
	if err := validate(cfg); err == nil {
		t.Fatalf("expected placeholder key to be rejected")
	}
}

func TestValidateRejectsIdenticalKeys(t *testing.T) {
	cfg := validConfig()
	cfg.SSOSecretKey = cfg.SessionKey
	if err := validate(cfg); err == nil {
		t.Fatalf("expected identical keys to be rejected")
	}
	cfg = validConfig()
	cfg.ControlPlaneAdminKey = cfg.SessionKey
	if err := validate(cfg); err == nil {
		t.Fatalf("expected identical keys to be rejected")
	}
}

func TestValidateRejects31CharKey(t *testing.T) {
	cfg := validConfig()
	cfg.SessionKey = "0123456789012345678901234567890"
	if err := validate(cfg); err == nil {
		t.Fatalf("expected 31 char key to be rejected")
	}
	cfg.SessionKey = "01234567890123456789012345678901"
	cfg.Auth.Mode = AuthModeLocal
	if err := validate(cfg); err != nil {
		t.Fatalf("32 char key must pass: %v", err)
	}
}

func TestLoadReadsSSOSecretKeyPrevious(t *testing.T) {
	t.Setenv("GOUP_ADDR", ":8080")
	t.Setenv("GOUP_BASE_URL", "http://localhost:8080")
	t.Setenv("GOUP_DATA_DIR", t.TempDir())
	t.Setenv("GOUP_SESSION_KEY", "session-key-1234567890-abcdefghijkl")
	t.Setenv("GOUP_SSO_SECRET_KEY", "sso-secret-key-123456-abcdefghijklmn")
	t.Setenv("GOUP_CONTROL_PLANE_ADMIN_KEY", "admin-cookie-key-123456-abcdefghijklm")
	t.Setenv("GOUP_SSO_SECRET_KEY_PREVIOUS", "previous-sso-secret-key-abcdefghijkl")
	t.Setenv("GOUP_AUTH_MODE", "disabled")
	_ = os.Unsetenv("GOUP_CONTROL_DB_PATH")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SSOSecretKeyPrevious != "previous-sso-secret-key-abcdefghijkl" {
		t.Fatalf("SSOSecretKeyPrevious = %q", cfg.SSOSecretKeyPrevious)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies("10.0.0.0/8, 192.168.1.5 ,::1")
	if err != nil || len(got) != 3 {
		t.Fatalf("got %v err %v", got, err)
	}
	if _, err := ParseTrustedProxies("nonsense"); err == nil {
		t.Fatalf("expected error")
	}
	if got, err := ParseTrustedProxies(""); err != nil || len(got) != 0 {
		t.Fatalf("empty must be ok")
	}
}
