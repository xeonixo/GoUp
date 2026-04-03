package monitor

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
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

	ip, network, requestProtocol, replyProtocol, err := resolveICMPTarget(ctx, item.Target)
	if err != nil {
		result.Message = fmt.Sprintf("icmp resolve failed: %v", err)
		return result
	}

	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		result.Message = fmt.Sprintf("icmp socket failed: %v", err)
		return result
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(item.Timeout)); err != nil {
		result.Message = fmt.Sprintf("icmp deadline failed: %v", err)
		return result
	}

	body := &icmp.Echo{
		ID:   os.Getpid() & 0xffff,
		Seq:  rand.Intn(65535),
		Data: []byte("goup"),
	}
	message := icmp.Message{Type: requestProtocol.requestType, Code: 0, Body: body}
	payload, err := message.Marshal(nil)
	if err != nil {
		result.Message = fmt.Sprintf("icmp marshal failed: %v", err)
		return result
	}

	if _, err := conn.WriteTo(payload, &net.IPAddr{IP: ip}); err != nil {
		result.Message = fmt.Sprintf("icmp send failed: %v", err)
		return result
	}

	buffer := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		result.Latency = time.Since(startedAt)
		if err != nil {
			result.Message = fmt.Sprintf("icmp read failed: %v", err)
			return result
		}

		reply, err := icmp.ParseMessage(replyProtocol, buffer[:n])
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
		if !sameHostIP(peer, ip) {
			continue
		}

		switch reply.Type {
		case requestProtocol.replyType:
			result.Status = StatusUp
			result.Message = fmt.Sprintf("ICMP echo ok from %s in %d ms", ip.String(), result.Latency.Milliseconds())
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

func resolveICMPTarget(ctx context.Context, target string) (net.IP, string, icmpProtocol, int, error) {
	if target == "" {
		return nil, "", icmpProtocol{}, 0, errors.New("target is required")
	}

	resolver := net.DefaultResolver
	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		return nil, "", icmpProtocol{}, 0, err
	}
	if len(ips) == 0 {
		return nil, "", icmpProtocol{}, 0, errors.New("no ip addresses found")
	}

	ip := ips[0].IP
	if ip4 := ip.To4(); ip4 != nil {
		return ip4, "ip4:icmp", icmpProtocol{requestType: ipv4.ICMPTypeEcho, replyType: ipv4.ICMPTypeEchoReply}, 1, nil
	}
	return ip, "ip6:ipv6-icmp", icmpProtocol{requestType: ipv6.ICMPTypeEchoRequest, replyType: ipv6.ICMPTypeEchoReply}, 58, nil
}

func sameHostIP(addr net.Addr, ip net.IP) bool {
	ipAddr, ok := addr.(*net.IPAddr)
	if !ok {
		return true
	}
	return ipAddr.IP.Equal(ip)
}
