package monitor

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// SDNSTarget is the name to resolve and the encrypted resolver that answers it.
//
// Stored form: name|recordType|endpoint|sni
// The endpoint keeps its path, so a DoH client id stays in place:
// https://dns.example/dns-query/<client-id>
type SDNSTarget struct {
	Name       string
	RecordType DNSRecordType
	Endpoint   string
	// SNI is an optional TLS server name. It is used when Endpoint is an IP
	// whose certificate is issued to a hostname.
	SNI string
}

// ParseSDNSTarget splits a stored secure-DNS target. It does not validate it.
func ParseSDNSTarget(raw string) SDNSTarget {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return SDNSTarget{RecordType: DNSRecordTypeMixed}
	}
	parts := strings.Split(trimmed, "|")
	target := SDNSTarget{
		Name:       strings.TrimSpace(parts[0]),
		RecordType: DNSRecordTypeMixed,
	}
	if len(parts) == 1 {
		return target
	}
	target.RecordType = NormalizeDNSRecordType(parts[1])
	if len(parts) >= 3 {
		target.Endpoint = strings.TrimSpace(parts[2])
	}
	if len(parts) >= 4 {
		target.SNI = strings.TrimSpace(strings.Join(parts[3:], "|"))
	}
	return target
}

// ComposeSDNSTarget builds the stored target. Empty SNI omits the last field.
func ComposeSDNSTarget(name string, recordType DNSRecordType, endpoint, sni string) string {
	name = strings.TrimSpace(name)
	endpoint = strings.TrimSpace(endpoint)
	sni = strings.TrimSpace(sni)
	recordType = NormalizeDNSRecordType(string(recordType))
	base := name + "|" + string(recordType) + "|" + endpoint
	if sni == "" {
		return base
	}
	return base + "|" + sni
}

// NormalizeSDNSTarget validates and canonicalizes a secure-DNS target for transport.
func NormalizeSDNSTarget(raw string, transport SDNSTransport) (string, error) {
	parsed := ParseSDNSTarget(raw)
	name, err := normalizeSDNSQueryName(parsed.Name)
	if err != nil {
		return "", err
	}
	endpoint, err := normalizeSDNSEndpoint(transport, parsed.Endpoint)
	if err != nil {
		return "", err
	}
	sni, err := normalizeSDNSSNI(parsed.SNI)
	if err != nil {
		return "", err
	}
	return ComposeSDNSTarget(name, parsed.RecordType, endpoint, sni), nil
}

// SDNSEndpointHost returns the host the checker dials (no port, no brackets).
func SDNSEndpointHost(transport SDNSTransport, endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if NormalizeSDNSTransport(string(transport)).UsesHTTP() {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return ""
		}
		return parsed.Hostname()
	}
	host, _, err := splitOptionalHostPort(stripSDNSScheme(endpoint), sdnsDefaultPort(transport))
	if err != nil {
		return ""
	}
	return strings.Trim(strings.TrimSpace(host), "[]")
}

func normalizeSDNSQueryName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	name = strings.TrimSuffix(name, ".")
	if name == "" || strings.ContainsAny(name, " /\\@|") || strings.Contains(name, "://") {
		return "", fmt.Errorf("secure DNS query name must be a hostname (e.g. example.com)")
	}
	if !isASCIIString(name) {
		ascii, err := idna.Lookup.ToASCII(name)
		if err != nil || ascii == "" {
			return "", fmt.Errorf("secure DNS query name must be a hostname (e.g. example.com)")
		}
		name = ascii
	}
	return name, nil
}

func normalizeSDNSSNI(raw string) (string, error) {
	sni := strings.TrimSpace(raw)
	sni = strings.TrimSuffix(sni, ".")
	if sni == "" {
		return "", nil
	}
	if strings.ContainsAny(sni, " /\\@|:") || net.ParseIP(sni) != nil {
		return "", fmt.Errorf("TLS server name must be a hostname")
	}
	if !isASCIIString(sni) {
		ascii, err := idna.Lookup.ToASCII(sni)
		if err != nil || ascii == "" {
			return "", fmt.Errorf("TLS server name must be a hostname")
		}
		sni = ascii
	}
	return sni, nil
}

func normalizeSDNSEndpoint(transport SDNSTransport, raw string) (string, error) {
	transport = NormalizeSDNSTransport(string(transport))
	if transport.UsesHTTP() {
		return normalizeSDNSHTTPEndpoint(raw)
	}
	return normalizeSDNSHostPort(raw, sdnsDefaultPort(transport))
}

func normalizeSDNSHTTPEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || parsed.Host == "" || !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("DoH endpoint must be an https URL (e.g. https://dns.example/dns-query/client-id)")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("DoH endpoint must not contain credentials")
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return "", fmt.Errorf("DoH endpoint must include a host")
	}
	if port := parsed.Port(); port != "" {
		if _, err := normalizeSDNSHostPort(parsed.Host, "443"); err != nil {
			return "", fmt.Errorf("DoH endpoint port is invalid")
		}
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/dns-query"
	}
	query := parsed.Query()
	query.Del("dns")
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}

func normalizeSDNSHostPort(raw string, defaultPort string) (string, error) {
	trimmed := stripSDNSScheme(strings.TrimSpace(raw))
	if trimmed == "" || strings.Contains(trimmed, "://") {
		return "", fmt.Errorf("resolver must be a host or host:port")
	}
	host, port, err := splitOptionalHostPort(trimmed, defaultPort)
	if err != nil {
		return "", fmt.Errorf("invalid resolver address: %w", err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("invalid resolver address: missing host")
	}
	if _, err := normalizeSDNSPort(port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

func normalizeSDNSPort(port string) (string, error) {
	port = strings.TrimSpace(port)
	if port == "" {
		return "", fmt.Errorf("invalid resolver address: missing port")
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("invalid resolver address: invalid port")
		}
	}
	n := 0
	for _, r := range port {
		n = n*10 + int(r-'0')
		if n > 65535 {
			return "", fmt.Errorf("invalid resolver address: invalid port")
		}
	}
	if n <= 0 {
		return "", fmt.Errorf("invalid resolver address: invalid port")
	}
	return port, nil
}

func sdnsDefaultPort(transport SDNSTransport) string {
	switch NormalizeSDNSTransport(string(transport)) {
	case SDNSTransportDoT, SDNSTransportDoQ:
		return "853"
	default:
		return "443"
	}
}

func stripSDNSScheme(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	for _, prefix := range []string{"tls://", "dot://", "quic://", "doq://"} {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(raw[len(prefix):])
		}
	}
	return strings.TrimSpace(raw)
}

func isASCIIString(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}
