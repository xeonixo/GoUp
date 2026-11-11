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

func TestPrometheusAndGRPCConfigRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "prom-grpc.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	promID, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name:              "Prom",
		Kind:              "prom",
		Target:            "http://prometheus:9090",
		Interval:          time.Minute,
		Timeout:           5 * time.Second,
		Enabled:           true,
		TLSMode:           monitor.TLSModeNone,
		PromQuery:         `up{job="api"}`,
		PromExpectedValue: "1",
		PromComparison:    "gte",
	})
	if err != nil {
		t.Fatal(err)
	}
	promSnap, err := st.GetMonitorSnapshot(ctx, promID)
	if err != nil {
		t.Fatal(err)
	}
	if promSnap.Monitor.Kind != monitor.KindPrometheus {
		t.Fatalf("kind alias not normalized: %q", promSnap.Monitor.Kind)
	}
	if promSnap.Monitor.PromQuery != `up{job="api"}` || promSnap.Monitor.PromExpectedValue != "1" || promSnap.Monitor.PromComparison != monitor.PromComparisonGTE {
		t.Fatalf("prom config = %#v", promSnap.Monitor)
	}

	grpcID, err := st.CreateMonitor(ctx, CreateMonitorParams{
		Name:        "GRPC",
		Kind:        monitor.KindGRPC,
		Target:      "127.0.0.1:50051",
		Interval:    time.Minute,
		Timeout:     5 * time.Second,
		Enabled:     true,
		TLSMode:     monitor.TLSModeNone,
		GRPCService: "api.v1.Service",
	})
	if err != nil {
		t.Fatal(err)
	}
	grpcSnap, err := st.GetMonitorSnapshot(ctx, grpcID)
	if err != nil {
		t.Fatal(err)
	}
	if grpcSnap.Monitor.GRPCService != "api.v1.Service" {
		t.Fatalf("grpc service = %q", grpcSnap.Monitor.GRPCService)
	}
}
