package monitor

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/icmp"
)

type ICMPChecker struct{}

type icmpAddressFamily int

const (
	icmpAddressFamilyAuto icmpAddressFamily = iota
	icmpAddressFamilyIPv4
	icmpAddressFamilyIPv6
)

func (c ICMPChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	checkedAt := startedAt.UTC()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: checkedAt,
		Status:    StatusDown,
	}

	family := icmpAddressFamilyFromTLSMode(item.TLSMode)
	if family == icmpAddressFamilyAuto && !isLiteralICMPTarget(item.Target) {
		v4Attempt := c.checkResolvedTargets(ctx, item, checkedAt, icmpAddressFamilyIPv4)
		v6Attempt := c.checkResolvedTargets(ctx, item, checkedAt, icmpAddressFamilyIPv6)

		v4Label := "IPv4 down"
		if v4Attempt.Status == StatusUp {
			v4Label = "IPv4 " + formatLatency(v4Attempt.Latency)
		}
		v6Label := "IPv6 down"
		if v6Attempt.Status == StatusUp {
			v6Label = "IPv6 " + formatLatency(v6Attempt.Latency)
		}

		switch {
		case v4Attempt.Status == StatusUp && v6Attempt.Status == StatusUp:
			result.Status = StatusUp
			result.Latency = (v4Attempt.Latency + v6Attempt.Latency) / 2
			result.Message = "ICMP dual stack ok · " + v4Label + " · " + v6Label
		case v4Attempt.Status == StatusUp || v6Attempt.Status == StatusUp:
			result.Status = StatusDegraded
			if v4Attempt.Status == StatusUp {
				result.Latency = v4Attempt.Latency
			} else {
				result.Latency = v6Attempt.Latency
			}
			result.Message = "ICMP dual stack degraded · " + v4Label + " · " + v6Label
		default:
			result.Status = StatusDown
			result.Latency = time.Since(startedAt)
			result.Message = "ICMP dual stack failed · " + v4Label + " · " + v6Label
		}
		return result
	}

	targets, err := resolveICMPTargets(ctx, item.Target, family)
	if err != nil {
		result.Message = fmt.Sprintf("icmp resolve failed: %v", err)
		return result
	}

	var failures []string
	for _, target := range targets {
		attempt := c.checkTarget(ctx, item, checkedAt, target)
		if attempt.Status == StatusUp {
			return attempt
		}
		if attempt.Message != "" {
			failures = append(failures, fmt.Sprintf("%s (%s): %s", target.ip.String(), target.network, attempt.Message))
		}
	}

	if len(failures) > 0 {
		result.Message = "icmp check failed: " + strings.Join(failures, " | ")
	} else {
		result.Message = "icmp check failed"
	}
	result.Latency = time.Since(startedAt)
	return result
}

func (c ICMPChecker) checkResolvedTargets(ctx context.Context, item Monitor, checkedAt time.Time, family icmpAddressFamily) Result {
	result := Result{MonitorID: item.ID, CheckedAt: checkedAt, Status: StatusDown}
	targets, err := resolveICMPTargets(ctx, item.Target, family)
	if err != nil {
		result.Message = fmt.Sprintf("icmp resolve failed: %v", err)
		return result
	}
	for _, target := range targets {
		attempt := c.checkTarget(ctx, item, checkedAt, target)
		if attempt.Status == StatusUp {
			return attempt
		}
		result = attempt
	}
	return result
}

func (c ICMPChecker) checkTarget(ctx context.Context, item Monitor, checkedAt time.Time, target resolvedICMPTarget) Result {
	attemptStartedAt := time.Now()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: checkedAt,
		Status:    StatusDown,
	}

	conn, err := icmp.ListenPacket(target.network, "")
	if err != nil {
		result.Message = formatICMPError("icmp socket failed", err)
		return result
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(item.Timeout)); err != nil {
		result.Message = fmt.Sprintf("icmp deadline failed: %v", err)
		return result
	}

	body := &icmp.Echo{
		ID:   int(randomUint16()),
		Seq:  int(randomUint16()),
		Data: append([]byte("goup:"), randomNonce(8)...),
	}
	message := icmp.Message{Type: target.protocol.requestType, Code: 0, Body: body}
	payload, err := message.Marshal(nil)
	if err != nil {
		result.Message = fmt.Sprintf("icmp marshal failed: %v", err)
		return result
	}

	if _, err := conn.WriteTo(payload, &net.IPAddr{IP: target.ip}); err != nil {
		result.Latency = time.Since(attemptStartedAt)
		result.Message = formatICMPError("icmp send failed", err)
		return result
	}

	buffer := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		result.Latency = time.Since(attemptStartedAt)
		if err != nil {
			result.Message = formatICMPError("icmp read failed", err)
			return result
		}

		reply, err := icmp.ParseMessage(target.replyProtocol, buffer[:n])
		if err != nil {
			result.Message = fmt.Sprintf("icmp parse failed: %v", err)
			return result
		}

		echo, ok := reply.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if echo.ID != body.ID || echo.Seq != body.Seq {
			continue
		}
		if !equalProbeData(echo.Data, body.Data) {
			continue
		}
		if !sameHostIP(peer, target.ip) {
			continue
		}

		switch reply.Type {
		case target.protocol.replyType:
			result.Status = StatusUp
			result.Message = fmt.Sprintf("ICMP echo ok from %s in %s", target.ip.String(), formatLatency(result.Latency))
			return result
		default:
			result.Message = fmt.Sprintf("unexpected icmp reply type %v", reply.Type)
			return result
		}
	}
}

type icmpProtocol struct {
	requestType icmp.Type
	replyType   icmp.Type
}

func formatICMPError(prefix string, err error) string {
	if err == nil {
		return prefix
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "operation not permitted") || strings.Contains(message, "permission denied") {
		return fmt.Sprintf("%s: %v (raw socket permission missing; ensure NET_RAW/cap_net_raw)", prefix, err)
	}
	return fmt.Sprintf("%s: %v", prefix, err)
}

func sameHostIP(addr net.Addr, ip net.IP) bool {
	ipAddr, ok := addr.(*net.IPAddr)
	if !ok {
		return false
	}
	return ipAddr.IP.Equal(ip)
}

func randomUint16() uint16 {
	var buf [2]byte
	if _, err := crand.Read(buf[:]); err == nil {
		return binary.BigEndian.Uint16(buf[:])
	}
	return uint16(time.Now().UnixNano())
}

func randomNonce(length int) []byte {
	if length <= 0 {
		return nil
	}
	buf := make([]byte, length)
	if _, err := crand.Read(buf); err == nil {
		return buf
	}
	now := uint64(time.Now().UnixNano())
	for i := range buf {
		buf[i] = byte(now >> ((i % 8) * 8))
	}
	return buf
}

func equalProbeData(got []byte, want []byte) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
