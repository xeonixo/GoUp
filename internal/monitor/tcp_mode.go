package monitor

import "strings"

type TCPAddressFamily string

const (
	TCPAddressFamilyDual TCPAddressFamily = "dual"
	TCPAddressFamilyIPv4 TCPAddressFamily = "ipv4"
	TCPAddressFamilyIPv6 TCPAddressFamily = "ipv6"
)

func NormalizeTCPAddressFamily(raw string) TCPAddressFamily {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(TCPAddressFamilyIPv4):
		return TCPAddressFamilyIPv4
	case string(TCPAddressFamilyIPv6):
		return TCPAddressFamilyIPv6
	default:
		return TCPAddressFamilyDual
	}
}

func NormalizeTCPTLSSecurityMode(mode TLSMode) TLSMode {
	securityMode, _, _ := ParseTCPTLSMode(mode)
	return securityMode
}

// ParseTCPTLSMode parses a TCP monitor TLS mode string and returns the
// canonical security mode, whether certificate verification is enabled, and
// the address family to use.
//
// Supported modes:
//   - "none" (default): plain TCP, no TLS
//   - "tls": TLS with full certificate verification
//   - "tls_insecure": TLS without certificate verification (explicit)
//   - "starttls": TLS without certificate verification (backward-compatible alias for tls_insecure)
//   - "starttls_insecure": TLS without certificate verification (explicit)
//
// The _ipv4 / _ipv6 suffixes control address-family selection.
func ParseTCPTLSMode(mode TLSMode) (TLSMode, bool, TCPAddressFamily) {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	if raw == "" {
		return TLSModeNone, false, TCPAddressFamilyDual
	}

	family := TCPAddressFamilyDual
	base := raw

	switch {
	case strings.HasSuffix(raw, "_ipv4"):
		family = TCPAddressFamilyIPv4
		base = strings.TrimSuffix(raw, "_ipv4")
	case strings.HasSuffix(raw, "_ipv6"):
		family = TCPAddressFamilyIPv6
		base = strings.TrimSuffix(raw, "_ipv6")
	}

	switch TLSMode(base) {
	case TLSModeNone:
		return TLSModeNone, false, family
	case TLSModeTLS:
		return TLSModeTLS, true, family
	case TLSModeSTARTTLS:
		// Backward-compatible: "starttls" for TCP monitors means TLS without
		// certificate verification (e.g. self-signed certs). Prefer tls_insecure
		// or starttls_insecure for new monitors.
		return TLSModeSTARTTLS, false, family
	case TLSModeTLSInsecure:
		// Explicit insecure TLS mode.
		return TLSModeTLS, false, family
	case TLSModeSTARTTLSInsecure:
		// Explicit insecure STARTTLS mode.
		return TLSModeSTARTTLS, false, family
	default:
		return TLSModeNone, false, TCPAddressFamilyDual
	}
}

func ComposeTCPTLSMode(securityMode TLSMode, family TCPAddressFamily) TLSMode {
	securityMode = NormalizeTCPTLSSecurityMode(securityMode)
	family = NormalizeTCPAddressFamily(string(family))
	if family == TCPAddressFamilyDual {
		return securityMode
	}
	return TLSMode(string(securityMode) + "_" + string(family))
}

func IsValidTCPTLSMode(mode TLSMode) bool {
	securityMode, _, _ := ParseTCPTLSMode(mode)
	return securityMode == TLSModeNone || securityMode == TLSModeTLS || securityMode == TLSModeSTARTTLS
}
