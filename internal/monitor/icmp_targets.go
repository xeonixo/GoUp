package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type resolvedICMPTarget struct {
	ip            net.IP
	network       string
	protocol      icmpProtocol
	replyProtocol int
}

func resolveICMPTargets(ctx context.Context, target string, family icmpAddressFamily) ([]resolvedICMPTarget, error) {
	host, err := normalizeICMPTarget(target)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			if family == icmpAddressFamilyIPv6 {
				return nil, errors.New("icmp family is IPv6 but target is IPv4")
			}
			return []resolvedICMPTarget{{
				ip:            ip4,
				network:       "ip4:icmp",
				protocol:      icmpProtocol{requestType: ipv4.ICMPTypeEcho, replyType: ipv4.ICMPTypeEchoReply},
				replyProtocol: 1,
			}}, nil
		}
		if family == icmpAddressFamilyIPv4 {
			return nil, errors.New("icmp family is IPv4 but target is IPv6")
		}
		return []resolvedICMPTarget{{
			ip:            ip,
			network:       "ip6:ipv6-icmp",
			protocol:      icmpProtocol{requestType: ipv6.ICMPTypeEchoRequest, replyType: ipv6.ICMPTypeEchoReply},
			replyProtocol: 58,
		}}, nil
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

	if family == icmpAddressFamilyIPv4 {
		if len(v4) == 0 {
			return nil, errors.New("no IPv4 addresses found")
		}
		return v4, nil
	}
	if family == icmpAddressFamilyIPv6 {
		if len(v6) == 0 {
			return nil, errors.New("no IPv6 addresses found")
		}
		return v6, nil
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

	if ip := net.ParseIP(target); ip != nil {
		return ip.String(), nil
	}

	if strings.ContainsAny(target, " /\\@") {
		return "", fmt.Errorf("icmp target must be a valid host or IPv4/IPv6 address: %s", target)
	}

	return target, nil
}

func icmpAddressFamilyFromTLSMode(mode TLSMode) icmpAddressFamily {
	switch mode {
	case TLSModeTLS:
		return icmpAddressFamilyIPv4
	case TLSModeSTARTTLS:
		return icmpAddressFamilyIPv6
	default:
		return icmpAddressFamilyAuto
	}
}

func isLiteralICMPTarget(target string) bool {
	value := strings.TrimSpace(target)
	value = strings.Trim(value, "[]")
	if value == "" {
		return false
	}
	return net.ParseIP(value) != nil
}
