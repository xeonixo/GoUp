package monitor

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func startTestGRPCHealthServer(t *testing.T, status healthpb.HealthCheckResponse_ServingStatus, service string) (addr string, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	hs := health.NewServer()
	hs.SetServingStatus("", status)
	if service != "" {
		hs.SetServingStatus(service, status)
	}
	healthpb.RegisterHealthServer(srv, hs)
	go func() { _ = srv.Serve(lis) }()
	return lis.Addr().String(), func() {
		srv.Stop()
		_ = lis.Close()
	}
}

func TestGRPCCheckerServing(t *testing.T) {
	addr, stop := startTestGRPCHealthServer(t, healthpb.HealthCheckResponse_SERVING, "api")
	defer stop()

	ok := (GRPCChecker{}).Check(context.Background(), Monitor{
		ID:          1,
		Kind:        KindGRPC,
		Target:      addr,
		Timeout:     2 * time.Second,
		TLSMode:     TLSModeNone,
		GRPCService: "api",
	})
	if ok.Status != StatusUp {
		t.Fatalf("expected up, got %s %q", ok.Status, ok.Message)
	}

	unknown := (GRPCChecker{}).Check(context.Background(), Monitor{
		Kind: KindGRPC, Target: addr, Timeout: 2 * time.Second, TLSMode: TLSModeNone, GRPCService: "other",
	})
	if unknown.Status != StatusDown {
		t.Fatalf("expected down for unknown service, got %s %q", unknown.Status, unknown.Message)
	}
	if !strings.Contains(unknown.Message, "SERVICE_UNKNOWN") && !strings.Contains(unknown.Message, "unknown service") {
		t.Fatalf("expected unknown-service error, got %q", unknown.Message)
	}
}

func TestGRPCCheckerNotServingAndBadTarget(t *testing.T) {
	addr, stop := startTestGRPCHealthServer(t, healthpb.HealthCheckResponse_NOT_SERVING, "")
	defer stop()

	down := (GRPCChecker{}).Check(context.Background(), Monitor{
		Kind: KindGRPC, Target: addr, Timeout: 2 * time.Second, TLSMode: TLSModeNone,
	})
	if down.Status != StatusDown || !strings.Contains(down.Message, "NOT_SERVING") {
		t.Fatalf("expected NOT_SERVING, got %s %q", down.Status, down.Message)
	}

	bad := (GRPCChecker{}).Check(context.Background(), Monitor{
		Kind: KindGRPC, Target: "not-a-host-port", Timeout: time.Second, TLSMode: TLSModeNone,
	})
	if bad.Status != StatusDown || !strings.Contains(bad.Message, "invalid grpc target") {
		t.Fatalf("expected invalid target, got %s %q", bad.Status, bad.Message)
	}
}
