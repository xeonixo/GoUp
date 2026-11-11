package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"goup/internal/config"
)

func TestBuildRemoteNodeMTLSServerTLSConfigEmpty(t *testing.T) {
	cfg, err := BuildRemoteNodeMTLSServerTLSConfig("", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config when CA file unset")
	}
}

func TestBuildRemoteNodeMTLSServerTLSConfigRequireNeedsCA(t *testing.T) {
	if _, err := BuildRemoteNodeMTLSServerTLSConfig("", true); err == nil {
		t.Fatalf("expected error when require=true without CA")
	}
}

func TestBuildRemoteNodeMTLSServerTLSConfigLoadsCA(t *testing.T) {
	dir := t.TempDir()
	caCert, _, caPEM := mustTestCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := BuildRemoteNodeMTLSServerTLSConfig(caPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected TLS config")
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatalf("ClientCAs must be set")
	}
	if !cfg.ClientCAs.Equal(certPoolWith(t, caCert)) {
		t.Fatalf("ClientCAs pool does not match loaded CA")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v, want TLS 1.2", cfg.MinVersion)
	}

	cfgReq, err := BuildRemoteNodeMTLSServerTLSConfig(caPath, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgReq.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("require mode still uses VerifyClientCertIfGiven for path-scoped enforcement, got %v", cfgReq.ClientAuth)
	}
}

func TestBuildRemoteNodeMTLSServerTLSConfigInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(path, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRemoteNodeMTLSServerTLSConfig(path, false); err == nil {
		t.Fatalf("expected error for invalid PEM")
	}
}

func TestRequireRemoteNodeMTLSMiddleware(t *testing.T) {
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	})

	s := &Server{cfg: config.Config{RemoteNodeMTLSRequire: true}}
	h := s.requireRemoteNodeMTLS(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/node/poll", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing client cert: got %d, want 401", rec.Code)
	}
	if called != 0 {
		t.Fatalf("handler must not run without client cert")
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || called != 1 {
		t.Fatalf("non-node paths must pass through, code=%d called=%d", rec.Code, called)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/node/bootstrap", nil)
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || called != 2 {
		t.Fatalf("verified client cert must pass, code=%d called=%d", rec.Code, called)
	}
}

func TestRequireRemoteNodeMTLSDisabled(t *testing.T) {
	called := 0
	s := &Server{cfg: config.Config{RemoteNodeMTLSRequire: false}}
	h := s.requireRemoteNodeMTLS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/node/report", nil))
	if called != 1 {
		t.Fatalf("disabled mTLS must not block /node/*")
	}
}

func certPoolWith(t *testing.T, cert *x509.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

func mustTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "goup-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, pemBytes
}
