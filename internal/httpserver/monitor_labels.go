package httpserver

import (
	"goup/internal/monitor"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func icmpDualStackLatencyLabel(message string) string {
	trimmed := strings.TrimSpace(message)
	if !strings.HasPrefix(trimmed, "ICMP dual stack") {
		return ""
	}
	parts := strings.Split(trimmed, " · ")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[1:], " · ")
}

func formatLatencyLabel(duration time.Duration) string {
	if duration <= 0 {
		return "0ms"
	}
	if duration < time.Millisecond {
		return "<1ms"
	}
	if duration < time.Second {
		return strconv.FormatInt(duration.Milliseconds(), 10) + "ms"
	}
	seconds := duration.Seconds()
	formatted := strconv.FormatFloat(seconds, 'f', 2, 64)
	formatted = strings.TrimRight(strings.TrimRight(formatted, "0"), ".")
	return formatted + "s"
}

func defaultTLSMode(kind monitor.Kind) monitor.TLSMode {
	switch kind {
	case monitor.KindHTTPS, monitor.KindIMAP:
		return monitor.TLSModeTLS
	case monitor.KindSMTP:
		return monitor.TLSModeSTARTTLS
	default:
		return monitor.TLSModeNone
	}
}

func normalizeTLSMode(kind monitor.Kind, requested monitor.TLSMode) monitor.TLSMode {
	switch kind {
	case monitor.KindHTTPS:
		return monitor.NormalizeHTTPSTLSSecurityMode(requested)
	case monitor.KindTCP:
		return monitor.NormalizeTCPTLSSecurityMode(requested)
	case monitor.KindICMP:
		if requested == monitor.TLSModeNone || requested == monitor.TLSModeTLS || requested == monitor.TLSModeSTARTTLS {
			return requested
		}
		return monitor.TLSModeNone
	case monitor.KindSMTP:
		if monitor.IsValidMailTLSMode(requested) {
			return requested
		}
		return monitor.TLSModeSTARTTLS
	case monitor.KindIMAP:
		if monitor.IsValidMailTLSMode(requested) {
			return requested
		}
		return monitor.TLSModeTLS
	case monitor.KindUDP:
		if monitor.IsValidUDPMode(requested) {
			return requested
		}
		return monitor.TLSModeNone
	case monitor.KindDNS, monitor.KindWhois:
		return monitor.TLSModeNone
	default:
		return requested
	}
}

func parseMonitorExecutorSelection(raw string) (executorKind string, executorRef string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "local") {
		return "local", ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "remote:") {
		ref := strings.TrimSpace(raw[len("remote:"):])
		if ref == "" {
			return "local", ""
		}
		return "remote", ref
	}
	return "local", ""
}

func monitorTargetLabel(item monitor.Monitor) string {
	if item.Kind == monitor.KindDNS {
		parsed := monitor.ParseDNSTarget(item.Target)
		parts := make([]string, 0, 3)
		if parsed.Host != "" {
			parts = append(parts, parsed.Host)
		}
		switch monitor.NormalizeDNSRecordType(string(parsed.RecordType)) {
		case monitor.DNSRecordTypeA:
			parts = append(parts, "A")
		case monitor.DNSRecordTypeAAAA:
			parts = append(parts, "AAAA")
		case monitor.DNSRecordTypeCNAME:
			parts = append(parts, "CNAME")
		case monitor.DNSRecordTypeMX:
			parts = append(parts, "MX")
		case monitor.DNSRecordTypeTXT:
			parts = append(parts, "TXT")
		case monitor.DNSRecordTypeNS:
			parts = append(parts, "NS")
		case monitor.DNSRecordTypeSRV:
			parts = append(parts, "SRV")
		case monitor.DNSRecordTypeCAA:
			parts = append(parts, "CAA")
		case monitor.DNSRecordTypeSOA:
			parts = append(parts, "SOA")
		default:
			parts = append(parts, "A+AAAA")
		}
		if parsed.Server != "" {
			parts = append(parts, "via "+parsed.Server)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " · ")
		}
		return item.Target
	}
	if item.Kind != monitor.KindTCP {
		return item.Target
	}
	host, port, err := net.SplitHostPort(item.Target)
	if err != nil {
		return item.Target
	}
	if host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

func monitorTLSModeLabel(item monitor.Monitor) string {
	switch item.Kind {
	case monitor.KindHTTPS:
		return ""
	case monitor.KindSMTP, monitor.KindIMAP:
		securityMode, verifyCertificate, family := monitor.ParseMailTLSMode(item.TLSMode)
		parts := make([]string, 0, 2)
		switch securityMode {
		case monitor.TLSModeNone:
			parts = append(parts, "Plaintext")
		case monitor.TLSModeSTARTTLS:
			if verifyCertificate {
				parts = append(parts, "STARTTLS")
			} else {
				parts = append(parts, "STARTTLS (selfsigned)")
			}
		default:
			if verifyCertificate {
				parts = append(parts, "TLS")
			} else {
				parts = append(parts, "TLS (selfsigned)")
			}
		}
		host := ""
		if parsedHost, _, err := net.SplitHostPort(strings.TrimSpace(item.Target)); err == nil {
			host = strings.TrimSpace(strings.Trim(parsedHost, "[]"))
		}
		if host != "" && !isLiteralIPAddress(host) {
			switch family {
			case monitor.TCPAddressFamilyIPv4:
				parts = append(parts, "IPv4")
			case monitor.TCPAddressFamilyIPv6:
				parts = append(parts, "IPv6")
			default:
				parts = append(parts, "Dual Stack")
			}
		}
		return strings.Join(parts, " · ")
	case monitor.KindTCP:
		securityMode, _, family := monitor.ParseTCPTLSMode(item.TLSMode)
		parts := make([]string, 0, 2)
		switch securityMode {
		case monitor.TLSModeTLS:
			parts = append(parts, "TLS")
		case monitor.TLSModeSTARTTLS:
			parts = append(parts, "TLS (selfsigned)")
		}
		switch family {
		case monitor.TCPAddressFamilyIPv4:
			parts = append(parts, "IPv4")
		case monitor.TCPAddressFamilyIPv6:
			parts = append(parts, "IPv6")
		}
		return strings.Join(parts, " · ")
	case monitor.KindICMP:
		switch item.TLSMode {
		case monitor.TLSModeTLS:
			return "IPv4"
		case monitor.TLSModeSTARTTLS:
			return "IPv6"
		case monitor.TLSModeNone:
			if !isLiteralIPAddress(item.Target) {
				return "Dual Stack"
			}
			return ""
		default:
			return ""
		}
	case monitor.KindUDP:
		probeKind, family := monitor.ParseUDPMode(item.TLSMode)
		kindLabel := "WireGuard"
		switch probeKind {
		case monitor.UDPProbeKindDNS:
			kindLabel = "DNS"
		case monitor.UDPProbeKindNTP:
			kindLabel = "NTP"
		}
		if monitor.IsExplicitUDPFamilyMode(item.TLSMode) {
			switch family {
			case monitor.TCPAddressFamilyIPv4:
				return kindLabel + " · IPv4"
			case monitor.TCPAddressFamilyIPv6:
				return kindLabel + " · IPv6"
			default:
				return kindLabel + " · Dual Stack"
			}
		}
		return kindLabel
	default:
		return ""
	}
}

func isTimeoutMessage(message string) bool {
	text := strings.ToLower(strings.TrimSpace(message))
	if text == "" {
		return false
	}
	return strings.Contains(text, "timeout") ||
		strings.Contains(text, "timed out") ||
		strings.Contains(text, "deadline exceeded") ||
		strings.Contains(text, "i/o timeout")
}

func normalizeHTTPMonitorTarget(raw string, mode monitor.TLSMode) string {
	target := strings.TrimSpace(raw)
	if target == "" {
		return target
	}
	if strings.Contains(target, "://") {
		return target
	}
	target = strings.TrimPrefix(target, "//")
	if mode == monitor.TLSModeNone {
		return "http://" + target
	}
	return "https://" + target
}

func isLiteralIPAddress(raw string) bool {
	target := strings.TrimSpace(raw)
	target = strings.Trim(target, "[]")
	if target == "" {
		return false
	}
	return net.ParseIP(target) != nil
}

func monitorHTTPKindLabel(target string, mode monitor.TLSMode) string {
	securityMode, _, family := monitor.ParseHTTPSTLSMode(mode)
	base := "HTTPS"
	switch securityMode {
	case monitor.TLSModeNone:
		base = "HTTP"
	case monitor.TLSModeSTARTTLS:
		base = "HTTPS (selfsigned)"
	}

	parsed, err := url.Parse(strings.TrimSpace(target))
	hasLiteralIPHost := false
	if err == nil && parsed != nil {
		hostname := strings.TrimSpace(parsed.Hostname())
		hasLiteralIPHost = isLiteralIPAddress(hostname)
	}

	switch family {
	case monitor.TCPAddressFamilyIPv4:
		return base + " · IPv4"
	case monitor.TCPAddressFamilyIPv6:
		return base + " · IPv6"
	case monitor.TCPAddressFamilyDual:
		if !hasLiteralIPHost {
			return base + " · Dual Stack"
		}
		return base
	default:
		return base
	}
}

func buildHTTPMonitorTarget(host string, port string, path string, mode monitor.TLSMode) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return normalizeHTTPMonitorTarget(path, mode)
	}
	port = strings.TrimSpace(port)
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	path = strings.TrimSpace(path)
	if path != "" && !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "?") {
		path = "/" + path
	}

	scheme := "https://"
	if mode == monitor.TLSModeNone {
		scheme = "http://"
	}
	return scheme + host + path
}

// ========== Tenant-Specific Login Handlers (Multi-Tenant SSO) ==========
