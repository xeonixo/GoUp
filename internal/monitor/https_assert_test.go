package monitor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseHTTPRequestHeadersJSONAndMultiline(t *testing.T) {
	t.Parallel()

	fromJSON, err := ParseHTTPRequestHeaders(`{"X-Token":"abc","Content-Type":"application/json"}`)
	if err != nil {
		t.Fatalf("json headers: %v", err)
	}
	if fromJSON["X-Token"] != "abc" || fromJSON["Content-Type"] != "application/json" {
		t.Fatalf("json headers parsed = %#v", fromJSON)
	}

	fromLines, err := ParseHTTPRequestHeaders("X-Token: abc\nContent-Type=application/json\n")
	if err != nil {
		t.Fatalf("multiline headers: %v", err)
	}
	if fromLines["X-Token"] != "abc" || fromLines["Content-Type"] != "application/json" {
		t.Fatalf("multiline headers parsed = %#v", fromLines)
	}
}

func TestEvalSimpleJSONPath(t *testing.T) {
	t.Parallel()

	var root any
	if err := json.Unmarshal([]byte(`{"status":"ok","data":{"items":[{"id":7},{"id":8}]}}`), &root); err != nil {
		t.Fatal(err)
	}
	got, err := EvalSimpleJSONPath(root, "$.status")
	if err != nil || got != "ok" {
		t.Fatalf("$.status = %v (%v)", got, err)
	}
	got, err = EvalSimpleJSONPath(root, "$.data.items[0].id")
	if err != nil || !matchJSONPathExpected(got, "7") {
		t.Fatalf("$.data.items[0].id = %v (%v)", got, err)
	}
	if err := ValidateSimpleJSONPath("$.trailing."); err == nil {
		t.Fatal("expected invalid path error")
	}
}

func TestHTTPSCheckerMethodAndJSONPath(t *testing.T) {
	t.Parallel()

	var sawMethod string
	var sawAuth string
	var sawBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		sawBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","code":200}`))
	}))
	defer srv.Close()

	result := HTTPSChecker{}.Check(t.Context(), Monitor{
		ID:               1,
		Kind:             KindHTTPS,
		Target:           srv.URL,
		Timeout:          3 * time.Second,
		TLSMode:          TLSModeNone,
		HTTPMethod:       http.MethodPost,
		RequestHeaders:   "Authorization: Bearer secret\nContent-Type: application/json",
		RequestBody:      `{"ping":true}`,
		JSONPath:         "$.status",
		JSONPathExpected: "ok",
		CheckMode:        CheckModeHTTP,
	})
	if result.Status != StatusUp {
		t.Fatalf("status=%s message=%s", result.Status, result.Message)
	}
	if sawMethod != http.MethodPost {
		t.Fatalf("method = %q", sawMethod)
	}
	if sawAuth != "Bearer secret" {
		t.Fatalf("auth = %q", sawAuth)
	}
	if !strings.Contains(sawBody, `"ping":true`) {
		t.Fatalf("body = %q", sawBody)
	}

	fail := HTTPSChecker{}.Check(t.Context(), Monitor{
		ID:               2,
		Kind:             KindHTTPS,
		Target:           srv.URL,
		Timeout:          3 * time.Second,
		TLSMode:          TLSModeNone,
		JSONPath:         "$.status",
		JSONPathExpected: "down",
	})
	if fail.Status != StatusDown || !strings.Contains(fail.Message, "JSONPath") {
		t.Fatalf("expected JSONPath failure, got %s %q", fail.Status, fail.Message)
	}
}

func TestHTTPSCheckerTLSOnly(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := mustSelfSignedCert(t)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tcpLN, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLN := tls.NewListener(tcpLN, &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	defer tlsLN.Close()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"status":"down"}`, http.StatusInternalServerError)
		}),
	}
	go func() { _ = server.Serve(tlsLN) }()
	defer server.Close()

	target := "https://" + tcpLN.Addr().String() + "/health"
	expected := 200
	result := HTTPSChecker{}.Check(t.Context(), Monitor{
		ID:                 3,
		Kind:               KindHTTPS,
		Target:             target,
		Timeout:            3 * time.Second,
		TLSMode:            TLSModeSTARTTLS, // insecure verify for self-signed
		CheckMode:          CheckModeTLS,
		CertWarningDays:    7,
		ExpectedStatusCode: &expected,
		ExpectedText:       "never-checked",
		JSONPath:           "$.status",
		JSONPathExpected:   "ok",
	})
	if result.Status != StatusUp && result.Status != StatusDegraded {
		t.Fatalf("TLS-only should ignore HTTP 500, got %s %q", result.Status, result.Message)
	}
	if result.TLSValid == nil || !*result.TLSValid {
		t.Fatalf("expected TLS metadata, got %#v", result)
	}
	if !strings.Contains(result.Message, "TLS ok") && !strings.Contains(result.Message, "certificate expires") {
		t.Fatalf("unexpected TLS-only message: %q", result.Message)
	}

	plain := HTTPSChecker{}.Check(t.Context(), Monitor{
		ID:        4,
		Kind:      KindHTTPS,
		Target:    "http://127.0.0.1:9/",
		Timeout:   time.Second,
		TLSMode:   TLSModeNone,
		CheckMode: CheckModeTLS,
	})
	if plain.Status != StatusDown || !strings.Contains(plain.Message, "TLS-only") {
		t.Fatalf("plain HTTP TLS-only should fail, got %s %q", plain.Status, plain.Message)
	}
}

func mustSelfSignedCert(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
