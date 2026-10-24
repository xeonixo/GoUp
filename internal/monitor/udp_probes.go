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
	// Question: ". IN NS". Every resolver knows (and usually caches) the root
	// name servers, so the probe tests the DNS service itself instead of
	// depending on one particular domain resolving.
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, uint16(2))
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
		conn, err := (newMonitorDialer(timeout)).DialContext(ctx, "tcp", target)
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
