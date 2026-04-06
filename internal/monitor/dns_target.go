package monitor

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type DNSRecordType string

const (
	DNSRecordTypeMixed DNSRecordType = "mixed"
	DNSRecordTypeA     DNSRecordType = "a"
	DNSRecordTypeAAAA  DNSRecordType = "aaaa"
	DNSRecordTypeCNAME DNSRecordType = "cname"
	DNSRecordTypeMX    DNSRecordType = "mx"
	DNSRecordTypeTXT   DNSRecordType = "txt"
	DNSRecordTypeNS    DNSRecordType = "ns"
	DNSRecordTypeSRV   DNSRecordType = "srv"
	DNSRecordTypeCAA   DNSRecordType = "caa"
	DNSRecordTypeSOA   DNSRecordType = "soa"
)

type DNSTarget struct {
	Host       string
	RecordType DNSRecordType
	Server     string
}

func NormalizeDNSRecordType(value string) DNSRecordType {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(DNSRecordTypeA):
		return DNSRecordTypeA
	case string(DNSRecordTypeAAAA):
		return DNSRecordTypeAAAA
	case string(DNSRecordTypeCNAME):
		return DNSRecordTypeCNAME
	case string(DNSRecordTypeMX):
		return DNSRecordTypeMX
	case string(DNSRecordTypeTXT):
		return DNSRecordTypeTXT
	case string(DNSRecordTypeNS):
		return DNSRecordTypeNS
	case string(DNSRecordTypeSRV):
		return DNSRecordTypeSRV
	case string(DNSRecordTypeCAA):
		return DNSRecordTypeCAA
	case string(DNSRecordTypeSOA):
		return DNSRecordTypeSOA
	default:
		return DNSRecordTypeMixed
	}
}

func ParseDNSTarget(raw string) DNSTarget {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return DNSTarget{RecordType: DNSRecordTypeMixed}
	}
	parts := strings.SplitN(trimmed, "|", 3)
	if len(parts) == 1 {
		return DNSTarget{Host: trimmed, RecordType: DNSRecordTypeMixed}
	}
	result := DNSTarget{
		Host:       strings.TrimSpace(parts[0]),
		RecordType: NormalizeDNSRecordType(parts[1]),
	}
	if len(parts) >= 3 {
		result.Server = strings.TrimSpace(parts[2])
	}
	if result.Host == "" {
		result.Host = trimmed
		result.RecordType = DNSRecordTypeMixed
		result.Server = ""
	}
	return result
}

func ComposeDNSTarget(host string, recordType DNSRecordType, server string) string {
	normalizedHost := strings.TrimSpace(host)
	if normalizedHost == "" {
		return ""
	}
	normalizedRecordType := NormalizeDNSRecordType(string(recordType))
	normalizedServer, err := NormalizeDNSServer(server)
	if err != nil {
		normalizedServer = strings.TrimSpace(server)
	}
	if normalizedRecordType == DNSRecordTypeMixed && normalizedServer == "" {
		return normalizedHost
	}
	return normalizedHost + "|" + string(normalizedRecordType) + "|" + normalizedServer
}

func NormalizeDNSTarget(raw string) (string, error) {
	parsed := ParseDNSTarget(raw)
	if parsed.Host == "" {
		return "", fmt.Errorf("target must be a hostname for DNS monitors")
	}
	if strings.ContainsAny(parsed.Host, " /\\@|") {
		return "", fmt.Errorf("DNS target must be a plain hostname (e.g. example.com)")
	}
	normalizedServer, err := NormalizeDNSServer(parsed.Server)
	if err != nil {
		return "", err
	}
	return ComposeDNSTarget(parsed.Host, parsed.RecordType, normalizedServer), nil
}

func NormalizeDNSServer(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	host, port, err := splitOptionalHostPort(trimmed, "53")
	if err != nil {
		return "", fmt.Errorf("invalid DNS server: %w", err)
	}
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("invalid DNS server: missing host")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber <= 0 || portNumber > 65535 {
		return "", fmt.Errorf("invalid DNS server: invalid port")
	}
	return net.JoinHostPort(host, port), nil
}

func splitOptionalHostPort(raw string, defaultPort string) (string, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", defaultPort, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		if strings.HasSuffix(trimmed, "]") {
			return strings.Trim(strings.TrimSpace(trimmed), "[]"), defaultPort, nil
		}
		host, port, err := net.SplitHostPort(trimmed)
		if err != nil {
			return "", "", err
		}
		return strings.Trim(host, "[]"), strings.TrimSpace(port), nil
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return trimmed, defaultPort, nil
	}
	if strings.Count(trimmed, ":") == 1 {
		host, port, err := net.SplitHostPort(trimmed)
		if err != nil {
			return "", "", err
		}
		return strings.TrimSpace(host), strings.TrimSpace(port), nil
	}
	return trimmed, defaultPort, nil
}
