package config

import "testing"

func validConfig() Config {
	return Config{
		Addr:                 ":8080",
		BaseURL:              "https://example.com",
		SessionKey:           "session-key-1234567890",
		SSOSecretKey:         "sso-secret-key-123456",
		ControlPlaneAdminKey: "admin-cookie-key-123456",
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
