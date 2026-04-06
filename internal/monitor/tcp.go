package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type TCPChecker struct{}

func (c TCPChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	checkedAt := startedAt.UTC()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: checkedAt,
		Status:    StatusDown,
	}

	securityMode, verifyCertificate, family := ParseTCPTLSMode(item.TLSMode)
	host, port, err := net.SplitHostPort(item.Target)
	if err != nil {
		result.Latency = time.Since(startedAt)
		result.Message = fmt.Sprintf("invalid tcp target: %v", err)
		return result
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		result.Latency = time.Since(startedAt)
		result.Message = "invalid tcp target: missing host"
		return result
	}

	if family == TCPAddressFamilyDual && net.ParseIP(host) == nil {
		baseTarget := net.JoinHostPort(host, port)
		v4Attempt := c.checkTarget(ctx, item, checkedAt, "tcp4", baseTarget, host, securityMode, verifyCertificate)
		v6Attempt := c.checkTarget(ctx, item, checkedAt, "tcp6", baseTarget, host, securityMode, verifyCertificate)

		v4Label := formatTCPAttemptLabel("IPv4", v4Attempt)
		v6Label := formatTCPAttemptLabel("IPv6", v6Attempt)

		v4Up := v4Attempt.Status == StatusUp || v4Attempt.Status == StatusDegraded
		v6Up := v6Attempt.Status == StatusUp || v6Attempt.Status == StatusDegraded

		switch {
		case v4Up && v6Up:
			result.Status = StatusUp
			if v4Attempt.Status == StatusDegraded || v6Attempt.Status == StatusDegraded {
				result.Status = StatusDegraded
			}
			result.Latency = (v4Attempt.Latency + v6Attempt.Latency) / 2
			adoptTCPAttemptMetadata(&result, v4Attempt)
			if result.TLSValid == nil {
				adoptTCPAttemptMetadata(&result, v6Attempt)
			}
			state := "ok"
			if result.Status == StatusDegraded {
				state = "degraded"
			}
			result.Message = "TCP dual stack " + state + " · " + v4Label + " · " + v6Label
			return result
		case v4Up || v6Up:
			result.Status = StatusDegraded
			if v4Up {
				result.Latency = v4Attempt.Latency
				adoptTCPAttemptMetadata(&result, v4Attempt)
			} else {
				result.Latency = v6Attempt.Latency
				adoptTCPAttemptMetadata(&result, v6Attempt)
			}
			result.Message = "TCP dual stack degraded · " + v4Label + " · " + v6Label
			return result
		default:
			result.Status = StatusDown
			result.Latency = time.Since(startedAt)
			result.Message = "TCP dual stack failed · " + v4Label + " · " + v6Label
			return result
		}
	}

	network, err := tcpDialNetwork(item.Target, family)
	if err != nil {
		result.Latency = time.Since(startedAt)
		result.Message = fmt.Sprintf("invalid tcp target: %v", err)
		return result
	}

	attempt := c.checkTarget(ctx, item, checkedAt, network, item.Target, host, securityMode, verifyCertificate)
	return attempt
}

func (c TCPChecker) checkTarget(ctx context.Context, item Monitor, checkedAt time.Time, network string, target string, serverName string, securityMode TLSMode, verifyCertificate bool) Result {
	attemptStartedAt := time.Now()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: checkedAt,
		Status:    StatusDown,
	}

	if securityMode == TLSModeNone {
		dialer := &net.Dialer{Timeout: item.Timeout}
		conn, err := dialer.DialContext(ctx, network, target)
		result.Latency = time.Since(attemptStartedAt)
		if err != nil {
			result.Message = fmt.Sprintf("tcp connect failed: %v", err)
			return result
		}
		_ = conn.Close()

		result.Status = StatusUp
		result.Message = fmt.Sprintf("TCP connect ok in %s", formatLatency(result.Latency))
		return result
	}

	dialer := &net.Dialer{Timeout: item.Timeout}
	conn, err := tls.DialWithDialer(dialer, network, target, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: !verifyCertificate, // false for tls mode; true for starttls/tls_insecure
	})
	result.Latency = time.Since(attemptStartedAt)
	if err != nil {
		result.Message = fmt.Sprintf("tcp tls handshake failed: %v", err)
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	applyTLSMetadata(&result, state)
	status, message := finalizeTLSResult(&result, fmt.Sprintf("TCP TLS handshake ok in %s", formatLatency(result.Latency)))
	if !verifyCertificate && len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		if leaf.CheckSignatureFrom(leaf) == nil && result.TLSDaysRemaining != nil {
			message = fmt.Sprintf("TCP TLS handshake ok in %s (self-signed cert, expires in %d days)", formatLatency(result.Latency), *result.TLSDaysRemaining)
		}
	}
	result.Status = status
	result.Message = message
	return result
}

func formatTCPAttemptLabel(label string, attempt Result) string {
	if attempt.Status == StatusUp || attempt.Status == StatusDegraded {
		if attempt.Status == StatusDegraded {
			return fmt.Sprintf("%s degraded (%s)", label, attempt.Message)
		}
		return fmt.Sprintf("%s %s", label, formatLatency(attempt.Latency))
	}
	if strings.TrimSpace(attempt.Message) == "" {
		return label + " down"
	}
	return fmt.Sprintf("%s down (%s)", label, attempt.Message)
}

func adoptTCPAttemptMetadata(target *Result, from Result) {
	if target == nil {
		return
	}
	target.TLSValid = from.TLSValid
	target.TLSNotAfter = from.TLSNotAfter
	target.TLSDaysRemaining = from.TLSDaysRemaining
}

func tcpDialNetwork(target string, family TCPAddressFamily) (string, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return "", fmt.Errorf("missing host")
	}

	ip := net.ParseIP(host)
	family = NormalizeTCPAddressFamily(string(family))

	if ip != nil {
		if ip.To4() != nil {
			if family == TCPAddressFamilyIPv6 {
				return "", fmt.Errorf("ip family is IPv6 but target is IPv4")
			}
			return "tcp4", nil
		}
		if family == TCPAddressFamilyIPv4 {
			return "", fmt.Errorf("ip family is IPv4 but target is IPv6")
		}
		return "tcp6", nil
	}

	switch family {
	case TCPAddressFamilyIPv4:
		return "tcp4", nil
	case TCPAddressFamilyIPv6:
		return "tcp6", nil
	default:
		return "tcp", nil
	}
}
