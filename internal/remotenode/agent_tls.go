package remotenode

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// BuildClientTLSConfig builds an optional tls.Config for outbound HTTPS to the
// control plane. certFile/keyFile supply the client certificate (mTLS);
// caFile optionally replaces the system trust store for server verification.
// When no TLS files are set, it returns (nil, nil).
func BuildClientTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	caFile = strings.TrimSpace(caFile)
	if certFile == "" && keyFile == "" && caFile == "" {
		return nil, nil
	}
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("REMOTE_NODE_TLS_CERT_FILE and REMOTE_NODE_TLS_KEY_FILE must be set together")
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load remote-node client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read REMOTE_NODE_TLS_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("REMOTE_NODE_TLS_CA_FILE: no PEM certificates found")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func newHTTPClient(cfg Config) (*http.Client, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	tlsCfg, err := BuildClientTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		client.Transport = &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: tlsCfg,
		}
	}
	return client, nil
}
