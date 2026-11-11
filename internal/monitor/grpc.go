package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// GRPCChecker dials a gRPC endpoint and calls grpc.health.v1.Health/Check.
//
// Target: host:port
// TLSMode: none (plaintext), tls (verified), starttls/tls_insecure (TLS without verify)
// GRPCService: optional service name passed to Health/Check (empty = overall server health)
type GRPCChecker struct{}

func (c GRPCChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: startedAt.UTC(),
		Status:    StatusDown,
	}

	target := strings.TrimSpace(item.Target)
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		result.Message = fmt.Sprintf("invalid grpc target: %v", err)
		return result
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" || strings.TrimSpace(port) == "" {
		result.Message = "invalid grpc target: missing host or port"
		return result
	}
	dialTarget := net.JoinHostPort(host, port)

	securityMode, verifyCertificate, _ := ParseTCPTLSMode(item.TLSMode)
	dialer := newMonitorDialer(item.Timeout)

	opts := []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		}),
	}
	switch securityMode {
	case TLSModeNone:
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	default:
		tlsCfg := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			InsecureSkipVerify: !verifyCertificate,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	conn, err := grpc.NewClient(dialTarget, opts...)
	if err != nil {
		result.Latency = time.Since(startedAt)
		result.Message = fmt.Sprintf("grpc dial failed: %v", err)
		return result
	}
	defer conn.Close()

	client := healthpb.NewHealthClient(conn)
	req := &healthpb.HealthCheckRequest{Service: strings.TrimSpace(item.GRPCService)}
	resp, err := client.Check(ctx, req)
	result.Latency = time.Since(startedAt)
	if err != nil {
		result.Message = fmt.Sprintf("grpc health check failed: %v", err)
		return result
	}
	if resp == nil {
		result.Message = "grpc health check returned empty response"
		return result
	}

	switch resp.GetStatus() {
	case healthpb.HealthCheckResponse_SERVING:
		result.Status = StatusUp
		service := strings.TrimSpace(item.GRPCService)
		if service == "" {
			result.Message = fmt.Sprintf("grpc health SERVING in %s", formatLatency(result.Latency))
		} else {
			result.Message = fmt.Sprintf("grpc health SERVING for %s in %s", service, formatLatency(result.Latency))
		}
	case healthpb.HealthCheckResponse_NOT_SERVING:
		result.Message = "grpc health NOT_SERVING"
	case healthpb.HealthCheckResponse_SERVICE_UNKNOWN:
		result.Message = "grpc health SERVICE_UNKNOWN"
	default:
		result.Message = fmt.Sprintf("grpc health status %s", resp.GetStatus().String())
	}
	return result
}
