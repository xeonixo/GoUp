package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type AuthMode string

const (
	AuthModeDisabled AuthMode = "disabled"
	AuthModeLocal    AuthMode = "local"
	AuthModeOIDC     AuthMode = "oidc"
)

type Config struct {
	Addr                 string
	BaseURL              string
	DataDir              string
	ControlPlaneDBPath   string
	LogLevel             string
	SessionKey           string
	SSOSecretKey         string
	ControlPlaneAdminKey string
	MonitorWorkers       int
	Auth                 AuthConfig

	// TrustedProxies lists networks whose X-Forwarded-For / X-Real-IP /
	// X-Forwarded-Proto headers are honored (GOUP_TRUSTED_PROXIES).
	TrustedProxies []netip.Prefix
	// SetupToken is the optional operator supplied admin setup token
	// (GOUP_SETUP_TOKEN). When empty a random one is generated at startup.
	SetupToken string
	// MonitorAllowPrivate lets HTTP(S) monitors target private networks
	// (GOUP_MONITOR_ALLOW_PRIVATE, default true). Cloud metadata addresses are
	// always blocked.
	MonitorAllowPrivate bool
	// AllowPrivateIntegrations permits private destinations for the Matrix
	// homeserver and OIDC issuer URLs (GOUP_ALLOW_PRIVATE_INTEGRATIONS).
	AllowPrivateIntegrations bool
}

type AuthConfig struct {
	Mode AuthMode
	OIDC OIDCConfig
}

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func Load() (Config, error) {
	cfg := Config{
		Addr:                 envOrDefault("GOUP_ADDR", ":8080"),
		BaseURL:              strings.TrimRight(envOrDefault("GOUP_BASE_URL", "http://localhost:8080"), "/"),
		DataDir:              envOrDefault("GOUP_DATA_DIR", "./data"),
		ControlPlaneDBPath:   os.Getenv("GOUP_CONTROL_DB_PATH"),
		LogLevel:             envOrDefault("GOUP_LOG_LEVEL", "info"),
		SessionKey:           strings.TrimSpace(os.Getenv("GOUP_SESSION_KEY")),
		SSOSecretKey:         strings.TrimSpace(os.Getenv("GOUP_SSO_SECRET_KEY")),
		ControlPlaneAdminKey: strings.TrimSpace(os.Getenv("GOUP_CONTROL_PLANE_ADMIN_KEY")),
		MonitorWorkers:       envIntOrDefault("GOUP_MONITOR_WORKERS", 4),
		SetupToken:           strings.TrimSpace(os.Getenv("GOUP_SETUP_TOKEN")),

		MonitorAllowPrivate:      envBoolOrDefault("GOUP_MONITOR_ALLOW_PRIVATE", true),
		AllowPrivateIntegrations: envBoolOrDefault("GOUP_ALLOW_PRIVATE_INTEGRATIONS", false),
		Auth: AuthConfig{
			Mode: AuthMode(envOrDefault("GOUP_AUTH_MODE", string(AuthModeDisabled))),
			OIDC: OIDCConfig{
				IssuerURL:    strings.TrimRight(os.Getenv("GOUP_OIDC_ISSUER_URL"), "/"),
				ClientID:     os.Getenv("GOUP_OIDC_CLIENT_ID"),
				ClientSecret: os.Getenv("GOUP_OIDC_CLIENT_SECRET"),
				RedirectURL:  strings.TrimRight(os.Getenv("GOUP_OIDC_REDIRECT_URL"), "/"),
			},
		},
	}

	proxies, err := ParseTrustedProxies(os.Getenv("GOUP_TRUSTED_PROXIES"))
	if err != nil {
		return Config{}, err
	}
	cfg.TrustedProxies = proxies

	if cfg.ControlPlaneDBPath == "" {
		cfg.ControlPlaneDBPath = filepath.Join(cfg.DataDir, "controlplane.db")
	}
	if cfg.Auth.OIDC.RedirectURL == "" {
		cfg.Auth.OIDC.RedirectURL = cfg.BaseURL + "/auth/callback"
	}
	if err := validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) SecureCookies() bool {
	return strings.HasPrefix(strings.ToLower(c.BaseURL), "https://")
}

func validate(cfg Config) error {
	if cfg.Addr == "" {
		return errors.New("GOUP_ADDR must not be empty")
	}
	if cfg.BaseURL == "" {
		return errors.New("GOUP_BASE_URL must not be empty")
	}
	if err := validateRequiredKey("GOUP_SESSION_KEY", cfg.SessionKey); err != nil {
		return err
	}
	if err := validateRequiredKey("GOUP_SSO_SECRET_KEY", cfg.SSOSecretKey); err != nil {
		return err
	}
	if err := validateRequiredKey("GOUP_CONTROL_PLANE_ADMIN_KEY", cfg.ControlPlaneAdminKey); err != nil {
		return err
	}
	keys := []struct{ name, value string }{
		{"GOUP_SESSION_KEY", cfg.SessionKey},
		{"GOUP_SSO_SECRET_KEY", cfg.SSOSecretKey},
		{"GOUP_CONTROL_PLANE_ADMIN_KEY", cfg.ControlPlaneAdminKey},
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if strings.TrimSpace(keys[i].value) == strings.TrimSpace(keys[j].value) {
				return fmt.Errorf("%s and %s must not be identical; generate each key independently with: openssl rand -hex 32", keys[i].name, keys[j].name)
			}
		}
	}
	if cfg.MonitorWorkers < 0 {
		return errors.New("GOUP_MONITOR_WORKERS must not be negative")
	}

	switch cfg.Auth.Mode {
	case AuthModeDisabled:
		return nil
	case AuthModeLocal:
		return nil
	case AuthModeOIDC:
		issuer := strings.TrimSpace(cfg.Auth.OIDC.IssuerURL)
		clientID := strings.TrimSpace(cfg.Auth.OIDC.ClientID)
		clientSecret := strings.TrimSpace(cfg.Auth.OIDC.ClientSecret)

		// Tenant-based OIDC is allowed without a global default provider.
		if issuer == "" && clientID == "" && clientSecret == "" {
			return nil
		}

		if issuer == "" || clientID == "" || clientSecret == "" {
			return fmt.Errorf("OIDC mode with global provider requires issuer URL, client ID and client secret")
		}
		return nil
	default:
		return fmt.Errorf("unsupported GOUP_AUTH_MODE %q", cfg.Auth.Mode)
	}
}

func validateRequiredKey(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if strings.HasPrefix(strings.ToLower(value), "replace-with") {
		return fmt.Errorf("%s still contains the example placeholder; generate a real key with: openssl rand -hex 32", name)
	}
	if len(value) < MinKeyLength {
		return fmt.Errorf("%s must be at least %d characters (generate one with: openssl rand -hex 32)", name, MinKeyLength)
	}
	return nil
}

// MinKeyLength is the minimum length of the three security keys.
const MinKeyLength = 32

// ParseTrustedProxies parses a comma separated list of CIDRs or single IPs.
func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("GOUP_TRUSTED_PROXIES: invalid CIDR %q", part)
			}
			out = append(out, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("GOUP_TRUSTED_PROXIES: invalid address %q", part)
		}
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

func envBoolOrDefault(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envIntOrDefault(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
