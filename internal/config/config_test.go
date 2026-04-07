package config

import "testing"

func TestSecureCookies(t *testing.T) {
	if !(Config{BaseURL: "https://example.com"}).SecureCookies() {
		t.Fatalf("expected secure cookies for https")
	}
	if (Config{BaseURL: "http://example.com"}).SecureCookies() {
		t.Fatalf("expected insecure cookies for http")
	}
}

func TestValidateOIDCPartialFails(t *testing.T) {
	cfg := Config{
		Addr:    ":8080",
		BaseURL: "https://example.com",
		Auth: AuthConfig{
			Mode: AuthModeOIDC,
			OIDC: OIDCConfig{
				IssuerURL: "https://issuer.example.com",
				ClientID:  "client",
			},
		},
	}
	if err := validate(cfg); err == nil {
		t.Fatalf("expected error for partial global OIDC config")
	}
}

func TestValidateOIDCTenantOnlyAllowed(t *testing.T) {
	cfg := Config{
		Addr:    ":8080",
		BaseURL: "https://example.com",
		Auth: AuthConfig{
			Mode: AuthModeOIDC,
			OIDC: OIDCConfig{},
		},
	}
	if err := validate(cfg); err != nil {
		t.Fatalf("expected tenant-only OIDC to be valid, got: %v", err)
	}
}
