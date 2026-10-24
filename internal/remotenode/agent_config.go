package remotenode

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ControlPlaneURL    string
	NodeID             string
	BootstrapKey       string
	InitialPollSeconds int
}

func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		ControlPlaneURL:    normalizeControlPlaneURL(os.Getenv("REMOTE_NODE_CONTROL_PLANE_URL")),
		NodeID:             strings.TrimSpace(os.Getenv("REMOTE_NODE_ID")),
		BootstrapKey:       strings.TrimSpace(os.Getenv("REMOTE_NODE_BOOTSTRAP_KEY")),
		InitialPollSeconds: 20,
	}
	if cfg.ControlPlaneURL == "" || cfg.NodeID == "" || cfg.BootstrapKey == "" {
		return Config{}, errors.New("REMOTE_NODE_CONTROL_PLANE_URL, REMOTE_NODE_ID und REMOTE_NODE_BOOTSTRAP_KEY müssen gesetzt sein")
	}
	allowInsecure := envTrue(os.Getenv("GOUP_REMOTE_NODE_ALLOW_INSECURE"))
	if err := validateControlPlaneURLSecurity(cfg.ControlPlaneURL, allowInsecure); err != nil {
		return Config{}, err
	}
	if raw := strings.TrimSpace(os.Getenv("REMOTE_NODE_POLL_SECONDS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			cfg.InitialPollSeconds = value
		}
	}
	return cfg, nil
}

func envTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// validateControlPlaneURLSecurity requires https unless the control plane is on
// the local machine or GOUP_REMOTE_NODE_ALLOW_INSECURE=true is set. The
// bootstrap key and access token are sent in request bodies/headers.
func validateControlPlaneURLSecurity(raw string, allowInsecure bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("REMOTE_NODE_CONTROL_PLANE_URL is not a valid URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		host := strings.ToLower(parsed.Hostname())
		if allowInsecure || host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return errors.New("REMOTE_NODE_CONTROL_PLANE_URL must use https (set GOUP_REMOTE_NODE_ALLOW_INSECURE=true to override for trusted networks)")
	default:
		return errors.New("REMOTE_NODE_CONTROL_PLANE_URL must use https")
	}
}

func normalizeControlPlaneURL(raw string) string {
	value := strings.TrimRight(strings.TrimSpace(raw), "/")
	for _, suffix := range []string{"/node/bootstrap", "/node/poll", "/node/report"} {
		if strings.HasSuffix(value, suffix) {
			value = strings.TrimSuffix(value, suffix)
			break
		}
	}
	return value
}
