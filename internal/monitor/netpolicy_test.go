package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPSCheckerBlocksMetadataAddress(t *testing.T) {
	dialer := newMonitorDialer(time.Second)
	if _, err := dialer.DialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("metadata dial must be blocked, got %v", err)
	}
}

func TestMonitorDialerPrivatePolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	// Default: private/loopback targets are reachable.
	conn, err := newMonitorDialer(time.Second).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("loopback must be reachable by default: %v", err)
	}
	conn.Close()

	SetAllowPrivateTargets(false)
	defer SetAllowPrivateTargets(true)
	if _, err := newMonitorDialer(time.Second).DialContext(context.Background(), "tcp", addr); err == nil {
		t.Fatalf("loopback must be blocked when GOUP_MONITOR_ALLOW_PRIVATE=false")
	}
}
