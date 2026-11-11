package httpserver

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// BuildRemoteNodeMTLSServerTLSConfig loads a PEM client CA and returns a
// tls.Config suitable for http.Server.TLSConfig. When caFile is empty, it
// returns (nil, nil) so callers can leave plain HTTP unchanged.
//
// ClientAuth is always VerifyClientCertIfGiven so browser UI traffic keeps
// working without a client certificate. When require is true, handlers must
// still enforce a verified client cert on /node/* (see requireRemoteNodeMTLS).
func BuildRemoteNodeMTLSServerTLSConfig(caFile string, require bool) (*tls.Config, error) {
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		if require {
			return nil, fmt.Errorf("GOUP_REMOTE_NODE_MTLS_REQUIRE=true requires GOUP_REMOTE_NODE_MTLS_CA_FILE")
		}
		return nil, nil
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read GOUP_REMOTE_NODE_MTLS_CA_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("GOUP_REMOTE_NODE_MTLS_CA_FILE: no PEM certificates found")
	}
	// Request client certificates and verify any that are presented. Path-scoped
	// enforcement for /node/* is handled in middleware when require is true.
	_ = require
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}, nil
}

func isRemoteNodeMTLSPath(path string) bool {
	switch path {
	case "/node/bootstrap", "/node/poll", "/node/report":
		return true
	default:
		return false
	}
}

func hasVerifiedClientCertificate(r *http.Request) bool {
	if r == nil || r.TLS == nil {
		return false
	}
	return len(r.TLS.VerifiedChains) > 0
}

// requireRemoteNodeMTLS rejects /node/bootstrap|poll|report when mTLS is
// required and the request has no verified client certificate. Token auth
// remains unchanged and is checked by the handlers.
func (s *Server) requireRemoteNodeMTLS(next http.Handler) http.Handler {
	if !s.cfg.RemoteNodeMTLSRequire {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isRemoteNodeMTLSPath(r.URL.Path) && !hasVerifiedClientCertificate(r) {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
