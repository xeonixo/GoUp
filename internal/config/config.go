package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type AuthMode string

const (
	AuthModeDisabled AuthMode = "disabled"
	AuthModeLocal    AuthMode = "local"
	AuthModeOIDC     AuthMode = "oidc"
)

type Config struct {
	Addr               string
	BaseURL            string
	DataDir            string
	DBPath             string
	ControlPlaneDBPath string
	LogLevel           string
	SessionKey         string
	SSOSecretKey       string
	Auth               AuthConfig
	Matrix             MatrixConfig
	Notify             NotifyConfig
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

type MatrixConfig struct {
	HomeserverURL string
	AccessToken   string
	RoomID        string
}

type NotifyConfig struct {
	EmailRecipients    []string
	EmailSubjectPrefix string
}

func Load() (Config, error) {
	cfg := Config{
		Addr:               envOrDefault("GOUP_ADDR", ":8080"),
		BaseURL:            strings.TrimRight(envOrDefault("GOUP_BASE_URL", "http://localhost:8080"), "/"),
		DataDir:            envOrDefault("GOUP_DATA_DIR", "./data"),
		DBPath:             os.Getenv("GOUP_DB_PATH"),
		ControlPlaneDBPath: os.Getenv("GOUP_CONTROL_DB_PATH"),
		LogLevel:           envOrDefault("GOUP_LOG_LEVEL", "info"),
		SessionKey:         os.Getenv("GOUP_SESSION_KEY"),
		SSOSecretKey:       os.Getenv("GOUP_SSO_SECRET_KEY"),
		Auth: AuthConfig{
			Mode: AuthMode(envOrDefault("GOUP_AUTH_MODE", string(AuthModeDisabled))),
			OIDC: OIDCConfig{
				IssuerURL:    strings.TrimRight(os.Getenv("GOUP_OIDC_ISSUER_URL"), "/"),
				ClientID:     os.Getenv("GOUP_OIDC_CLIENT_ID"),
				ClientSecret: os.Getenv("GOUP_OIDC_CLIENT_SECRET"),
				RedirectURL:  strings.TrimRight(os.Getenv("GOUP_OIDC_REDIRECT_URL"), "/"),
			},
		},
		Matrix: MatrixConfig{
			HomeserverURL: strings.TrimRight(os.Getenv("GOUP_MATRIX_HOMESERVER_URL"), "/"),
			AccessToken:   os.Getenv("GOUP_MATRIX_ACCESS_TOKEN"),
			RoomID:        os.Getenv("GOUP_MATRIX_ROOM_ID"),
		},
		Notify: NotifyConfig{
			EmailRecipients:    parseCSVEnv("GOUP_NOTIFY_EMAIL_TO"),
			EmailSubjectPrefix: strings.TrimSpace(os.Getenv("GOUP_NOTIFY_EMAIL_SUBJECT_PREFIX")),
		},
	}

	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(cfg.DataDir, "goup.db")
	}
	if cfg.ControlPlaneDBPath == "" {
		cfg.ControlPlaneDBPath = filepath.Join(cfg.DataDir, "controlplane.db")
	}
	if cfg.Auth.OIDC.RedirectURL == "" {
		cfg.Auth.OIDC.RedirectURL = cfg.BaseURL + "/auth/callback"
	}
	if cfg.SessionKey == "" {
		cfg.SessionKey = "dev-session-key-change-me"
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
	if len(cfg.SessionKey) < 16 {
		return errors.New("GOUP_SESSION_KEY must be at least 16 characters")
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

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parseCSVEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	items := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		normalized := strings.ToLower(value)
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		items = append(items, value)
	}
	if len(items) == 0 {
		return nil
	}
	return items
}
