package config

import (
	"errors"
	"fmt"
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
	if len(value) < 16 {
		return fmt.Errorf("%s must be at least 16 characters", name)
	}
	return nil
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
