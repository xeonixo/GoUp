package monitor

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ICMPChecker struct{}

func (c ICMPChecker) Check(ctx context.Context, item Monitor) Result {
	startedAt := time.Now()
	result := Result{
		MonitorID: item.ID,
		CheckedAt: startedAt.UTC(),
		Status:    StatusDown,
	}

	targets, err := resolveICMPTargets(ctx, item.Target)
	if err != nil {
		result.Message = fmt.Sprintf("icmp resolve failed: %v", err)
		return result
	}

	var failures []string
	for _, target := range targets {
		attempt := c.checkTarget(ctx, item, startedAt, target)
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

func (c ICMPChecker) checkTarget(ctx context.Context, item Monitor, startedAt time.Time, target resolvedICMPTarget) Result {
	result := Result{
		MonitorID: item.ID,
		CheckedAt: startedAt.UTC(),
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
		result.Message = formatICMPError("icmp send failed", err)
		return result
	}

	buffer := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		result.Latency = time.Since(startedAt)
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
			result.Message = fmt.Sprintf("ICMP echo ok from %s in %d ms", target.ip.String(), result.Latency.Milliseconds())
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

type resolvedICMPTarget struct {
	ip            net.IP
	network       string
	protocol      icmpProtocol
	replyProtocol int
}

func resolveICMPTargets(ctx context.Context, target string) ([]resolvedICMPTarget, error) {
	host, err := normalizeICMPTarget(target)
	if err != nil {
		return nil, err
	}

	resolver := net.DefaultResolver
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no ip addresses found")
	}

	v4 := make([]resolvedICMPTarget, 0, len(ips))
	v6 := make([]resolvedICMPTarget, 0, len(ips))

	for _, candidate := range ips {
		ip := candidate.IP
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, resolvedICMPTarget{
				ip:            ip4,
				network:       "ip4:icmp",
				protocol:      icmpProtocol{requestType: ipv4.ICMPTypeEcho, replyType: ipv4.ICMPTypeEchoReply},
				replyProtocol: 1,
			})
			continue
		}
		v6 = append(v6, resolvedICMPTarget{
			ip:            ip,
			network:       "ip6:ipv6-icmp",
			protocol:      icmpProtocol{requestType: ipv6.ICMPTypeEchoRequest, replyType: ipv6.ICMPTypeEchoReply},
			replyProtocol: 58,
		})
	}

	targets := append(v4, v6...)
	if len(targets) == 0 {
		return nil, errors.New("no usable ip addresses found")
	}

	return targets, nil
}

func normalizeICMPTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", errors.New("target is required")
	}

	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err == nil {
			host := strings.TrimSpace(parsed.Hostname())
			if host != "" {
				target = host
			}
		}
	}

	if host, _, err := net.SplitHostPort(target); err == nil {
		target = strings.TrimSpace(host)
	}

	target = strings.Trim(target, "[]")
	if target == "" {
		return "", errors.New("target is required")
	}

	ip := net.ParseIP(target)
	if ip == nil {
		return "", fmt.Errorf("icmp target must be a literal IPv4 or IPv6 address: %s", target)
	}

	return ip.String(), nil
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
