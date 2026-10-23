package remotenode

import "testing"

func TestRequireSecureControlPlaneURL(t *testing.T) {
	if err := validateControlPlaneURLSecurity("https://example.com", false); err != nil {
		t.Fatalf("https must be accepted: %v", err)
	}
	if err := validateControlPlaneURLSecurity("http://localhost:8080", false); err != nil {
		t.Fatalf("localhost http must be accepted: %v", err)
	}
	if err := validateControlPlaneURLSecurity("http://127.0.0.1:8080", false); err != nil {
		t.Fatalf("127.0.0.1 http must be accepted: %v", err)
	}
	if err := validateControlPlaneURLSecurity("http://goup.example.com", false); err == nil {
		t.Fatalf("remote http must be rejected")
	}
	if err := validateControlPlaneURLSecurity("http://goup.example.com", true); err != nil {
		t.Fatalf("remote http must be accepted when explicitly allowed: %v", err)
	}
}
