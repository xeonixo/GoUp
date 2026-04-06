package monitor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, target)
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

func checkUDPDNS(monitorID int64, checkedAt time.Time, conn *net.UDPConn, startedAt time.Time) Result {
	query, id := buildDNSProbeQuery()
	if _, err := conn.Write(query); err != nil {
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: time.Since(startedAt), Message: fmt.Sprintf("dns probe write failed: %v", err)}
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	latency := time.Since(startedAt)
	if err != nil {
		if isConnRefused(err) {
			return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: "dns port unreachable (ICMP connection refused)"}
		}
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: fmt.Sprintf("dns probe failed: %v", err)}
	}

	if n < 12 {
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: "dns response too short"}
	}
	respID := binary.BigEndian.Uint16(buf[0:2])
	if respID != id {
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: "dns response id mismatch"}
	}
	flags := binary.BigEndian.Uint16(buf[2:4])
	if flags&0x8000 == 0 {
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: "dns response missing QR flag"}
	}
	return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusUp, Latency: latency, Message: fmt.Sprintf("DNS response ok in %s", formatLatency(latency))}
}

func checkUDPNTP(monitorID int64, checkedAt time.Time, conn *net.UDPConn, startedAt time.Time) Result {
	request := make([]byte, 48)
	request[0] = 0x1b
	if _, err := conn.Write(request); err != nil {
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: time.Since(startedAt), Message: fmt.Sprintf("ntp probe write failed: %v", err)}
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	latency := time.Since(startedAt)
	if err != nil {
		if isConnRefused(err) {
			return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: "ntp port unreachable (ICMP connection refused)"}
		}
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: fmt.Sprintf("ntp probe failed: %v", err)}
	}
	if n < 48 {
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: "ntp response too short"}
	}
	mode := buf[0] & 0x07
	if mode != 4 && mode != 5 {
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: "ntp response mode invalid"}
	}
	return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusUp, Latency: latency, Message: fmt.Sprintf("NTP response ok in %s", formatLatency(latency))}
}

func checkUDPWireGuardLike(ctx context.Context, monitorID int64, checkedAt time.Time, conn *net.UDPConn, startedAt time.Time, timeout time.Duration, tunnelProbe string) Result {
	probe := []byte{0x01, 0x00, 0x00, 0x00}
	if _, err := conn.Write(probe); err != nil {
		return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: time.Since(startedAt), Message: fmt.Sprintf("wireguard probe write failed: %v", err)}
	}

	wait := udpProbeWait
	if timeout < wait {
		wait = timeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 512)
	_, readErr := conn.Read(buf)
	latency := time.Since(startedAt)
	baseMessage := "WireGuard endpoint reachable (no rejection received)"

	if readErr != nil {
		if isConnRefused(readErr) {
			return Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown, Latency: latency, Message: "wireguard port unreachable (ICMP connection refused)"}
		}
	} else {
		baseMessage = "WireGuard endpoint reachable (response received)"
	}

	result := Result{
		MonitorID: monitorID,
		CheckedAt: checkedAt,
		Status:    StatusDegraded,
		Latency:   latency,
		Message:   baseMessage,
	}

	tunnelProbe = strings.TrimSpace(tunnelProbe)
	if tunnelProbe == "" {
		result.Message = baseMessage + "; tunnel unverified (no tunnel probe configured)"
		return result
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	probeMessage, probeErr := runWireGuardTunnelProbe(probeCtx, tunnelProbe, timeout)
	if probeErr != nil {
		result.Status = StatusDown
		result.Message = fmt.Sprintf("%s; tunnel probe failed: %v", baseMessage, probeErr)
		return result
	}

	result.Status = StatusUp
	result.Message = fmt.Sprintf("%s; %s", baseMessage, probeMessage)
	return result
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

func buildDNSProbeQuery() ([]byte, uint16) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		binary.BigEndian.PutUint16(idBytes[:], uint16(time.Now().UnixNano()))
	}
	id := binary.BigEndian.Uint16(idBytes[:])

	buf := bytes.NewBuffer(make([]byte, 0, 32))
	_ = binary.Write(buf, binary.BigEndian, id)
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0100))
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	buf.WriteByte(7)
	buf.WriteString("example")
	buf.WriteByte(3)
	buf.WriteString("com")
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint16(1))

	return buf.Bytes(), id
}

func runWireGuardTunnelProbe(ctx context.Context, rawProbe string, timeout time.Duration) (string, error) {
	probe := strings.TrimSpace(rawProbe)
	if probe == "" {
		return "", nil
	}

	if !strings.Contains(probe, "://") {
		if _, _, err := net.SplitHostPort(probe); err == nil {
			probe = "tcp://" + probe
		} else {
			return "", fmt.Errorf("invalid tunnel probe format (use tcp://host:port or http(s)://...)")
		}
	}

	parsed, err := url.Parse(probe)
	if err != nil || parsed == nil {
		return "", fmt.Errorf("invalid tunnel probe: %w", err)
	}

	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "tcp":
		target := strings.TrimSpace(parsed.Host)
		if target == "" {
			return "", fmt.Errorf("invalid tcp tunnel probe target")
		}
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", target)
		if err != nil {
			return "", err
		}
		_ = conn.Close()
		return fmt.Sprintf("tunnel TCP probe ok (%s)", target), nil
	case "http", "https":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return "", err
		}
		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			return "", fmt.Errorf("tunnel HTTP probe unexpected status %d", resp.StatusCode)
		}
		return fmt.Sprintf("tunnel HTTP probe ok (%d)", resp.StatusCode), nil
	default:
		return "", fmt.Errorf("unsupported tunnel probe scheme %q", parsed.Scheme)
	}
}
