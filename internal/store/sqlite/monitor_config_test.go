package sqlite

import (
	"context"
	"goup/internal/monitor"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTPSAssertionConfigRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "https-assert.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	id, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name:             "API",
		Kind:             monitor.KindHTTPS,
		Target:           "https://example.com/health",
		Interval:         time.Minute,
		Timeout:          5 * time.Second,
		Enabled:          true,
		TLSMode:          monitor.TLSModeTLS,
		HTTPMethod:       "POST",
		RequestHeaders:   `{"X-Test":"1"}`,
		RequestBody:      `{"ping":true}`,
		JSONPath:         "$.status",
		JSONPathExpected: "ok",
		CheckMode:        monitor.CheckModeTLS,
		CertWarningDays:  7,
	})
	if err != nil {
		t.Fatal(err)
	}

	snap, err := st.GetMonitorSnapshot(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	m := snap.Monitor
	if m.HTTPMethod != "POST" || m.RequestHeaders != `{"X-Test":"1"}` || m.RequestBody != `{"ping":true}` {
		t.Fatalf("request fields = %#v", m)
	}
	if m.JSONPath != "$.status" || m.JSONPathExpected != "ok" || m.CheckMode != monitor.CheckModeTLS {
		t.Fatalf("assertion fields = %#v", m)
	}
}
