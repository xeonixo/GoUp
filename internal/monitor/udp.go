package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type UDPChecker struct{}

const udpProbeWait = 2 * time.Second

func (c UDPChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	checkedAt := startedAt.UTC()
	mode, family := ParseUDPMode(item.TLSMode)

	host, port, err := net.SplitHostPort(strings.TrimSpace(item.Target))
	if err != nil {
		return Result{
			MonitorID: item.ID,
			CheckedAt: checkedAt,
			Status:    StatusDown,
			Latency:   time.Since(startedAt),
			Message:   fmt.Sprintf("invalid udp target: %v", err),
		}
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return Result{
			MonitorID: item.ID,
			CheckedAt: checkedAt,
			Status:    StatusDown,
			Latency:   time.Since(startedAt),
			Message:   "invalid udp target: missing host",
		}
	}

	if IsExplicitUDPFamilyMode(item.TLSMode) && family == TCPAddressFamilyDual && net.ParseIP(host) == nil {
		baseTarget := net.JoinHostPort(host, port)
		v4Attempt := c.checkTarget(ctx, item, checkedAt, mode, "udp4", baseTarget)
		v6Attempt := c.checkTarget(ctx, item, checkedAt, mode, "udp6", baseTarget)

		v4Up := v4Attempt.Status == StatusUp || v4Attempt.Status == StatusDegraded
		v6Up := v6Attempt.Status == StatusUp || v6Attempt.Status == StatusDegraded
		v4Label := formatAttemptLabel("IPv4", v4Attempt)
		v6Label := formatAttemptLabel("IPv6", v6Attempt)

		result := Result{MonitorID: item.ID, CheckedAt: checkedAt, Status: StatusDown}
		switch {
		case v4Up && v6Up:
			result.Status = StatusUp
			if v4Attempt.Status == StatusDegraded || v6Attempt.Status == StatusDegraded {
				result.Status = StatusDegraded
			}
			result.Latency = (v4Attempt.Latency + v6Attempt.Latency) / 2
			state := "ok"
			if result.Status == StatusDegraded {
				state = "degraded"
			}
			result.Message = fmt.Sprintf("UDP %s %s · %s · %s", string(mode), state, v4Label, v6Label)
			return result
		case v4Up || v6Up:
			result.Status = StatusDegraded
			if v4Up {
				result.Latency = v4Attempt.Latency
			} else {
				result.Latency = v6Attempt.Latency
			}
			result.Message = fmt.Sprintf("UDP %s degraded · %s · %s", string(mode), v4Label, v6Label)
			return result
		default:
			result.Status = StatusDown
			result.Latency = time.Since(startedAt)
			result.Message = fmt.Sprintf("UDP %s failed · %s · %s", string(mode), v4Label, v6Label)
			return result
		}
	}

	network, err := udpDialNetwork(host, family)
	if err != nil {
		return Result{
			MonitorID: item.ID,
			CheckedAt: checkedAt,
			Status:    StatusDown,
			Latency:   time.Since(startedAt),
			Message:   fmt.Sprintf("invalid udp target: %v", err),
		}
	}

	target := net.JoinHostPort(host, port)
	return c.checkTarget(ctx, item, checkedAt, mode, network, target)
}

func (c UDPChecker) checkTarget(ctx context.Context, item Monitor, checkedAt time.Time, mode UDPProbeKind, network string, target string) Result {
	start := time.Now()
	timeout := item.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	conn, err := (newMonitorDialer(timeout)).DialContext(ctx, network, target)
	latency := time.Since(start)
	if err != nil {
		return Result{
			MonitorID: item.ID,
			CheckedAt: checkedAt,
			Status:    StatusDown,
			Latency:   latency,
			Message:   fmt.Sprintf("udp dial failed: %v", err),
		}
	}
	defer conn.Close()
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return Result{MonitorID: item.ID, CheckedAt: checkedAt, Status: StatusDown, Latency: time.Since(start), Message: "udp connection type mismatch"}
	}

	_ = udpConn.SetWriteDeadline(time.Now().Add(timeout))
	_ = udpConn.SetReadDeadline(time.Now().Add(timeout))

	switch mode {
	case UDPProbeKindDNS:
		return checkUDPDNS(item.ID, checkedAt, udpConn, start)
	case UDPProbeKindNTP:
		return checkUDPNTP(item.ID, checkedAt, udpConn, start)
	default:
		return checkUDPWireGuardLike(ctx, item.ID, checkedAt, udpConn, start, timeout, item.ExpectedText)
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

func udpDialNetwork(host string, family TCPAddressFamily) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(host))
	family = NormalizeTCPAddressFamily(string(family))

	if ip != nil {
		if ip.To4() != nil {
			if family == TCPAddressFamilyIPv6 {
				return "", fmt.Errorf("ip family is IPv6 but target is IPv4")
			}
			return "udp4", nil
		}
		if family == TCPAddressFamilyIPv4 {
			return "", fmt.Errorf("ip family is IPv4 but target is IPv6")
		}
		return "udp6", nil
	}

	switch family {
	case TCPAddressFamilyIPv4:
		return "udp4", nil
	case TCPAddressFamilyIPv6:
		return "udp6", nil
	default:
		return "udp", nil
	}
}
