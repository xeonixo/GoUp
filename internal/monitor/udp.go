package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// UDPChecker sends a small probe to a UDP endpoint and evaluates whether an
// ICMP port-unreachable reply is received.
//
//   - If the host responds with ICMP "connection refused" / "port unreachable":
//     the endpoint is reported DOWN.
//   - If no rejection is received within the probe window (timeout or a data
//     response): the endpoint is reported UP.
//
// Note: UDP is connectionless, so a successful probe can never guarantee the
// remote service is actually running — only that the port is not actively closed.
//
// Target: host:port
type UDPChecker struct{}

const udpProbeWait = 2 * time.Second

func (c UDPChecker) Check(ctx context.Context, item Monitor) Result {
	start := time.Now()
	target := strings.TrimSpace(item.Target)
	timeout := item.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	conn, err := net.DialTimeout("udp", target, timeout)
	latency := time.Since(start)
	if err != nil {
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Latency:   latency,
			Message:   fmt.Sprintf("UDP dial failed: %v", err),
		}
	}
	defer conn.Close()

	// Send a one-byte probe to trigger an ICMP port-unreachable reply on
	// closed UDP ports (Linux/most kernels honour this).
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0}); err != nil {
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Latency:   time.Since(start),
			Message:   fmt.Sprintf("UDP write failed: %v", err),
		}
	}

	// Wait briefly for an ICMP rejection to bounce back.
	wait := udpProbeWait
	if timeout < wait {
		wait = timeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 512)
	_, readErr := conn.Read(buf)
	latency = time.Since(start)

	if readErr != nil {
		if isConnRefused(readErr) {
			return Result{
				MonitorID: item.ID,
				CheckedAt: time.Now().UTC(),
				Status:    StatusDown,
				Latency:   latency,
				Message:   "UDP port unreachable (ICMP connection refused)",
			}
		}
		// Deadline exceeded or another transient error: no ICMP rejection
		// received, treat the endpoint as reachable.
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusUp,
			Latency:   latency,
			Message:   "UDP endpoint reachable (no rejection received)",
		}
	}

	return Result{
		MonitorID: item.ID,
		CheckedAt: time.Now().UTC(),
		Status:    StatusUp,
		Latency:   latency,
		Message:   "UDP endpoint reachable (response received)",
	}
}

// isConnRefused returns true when err indicates an ICMP port-unreachable or
// TCP/UDP connection-refused condition.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "port unreachable")
}
