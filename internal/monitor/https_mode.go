package monitor

import "strings"

func NormalizeHTTPSTLSSecurityMode(mode TLSMode) TLSMode {
	securityMode, _, _ := ParseHTTPSTLSMode(mode)
	return securityMode
}

// ParseHTTPSTLSMode parses an HTTPS monitor TLS mode string and returns the
// canonical security mode, whether certificate verification is enabled, and
// the address family to use.
//
// Supported modes:
//   - "tls" (default): TLS with full certificate verification
//   - "tls_insecure": TLS without certificate verification (explicit)
//   - "starttls": TLS without certificate verification (backward-compatible alias for tls_insecure)
//   - "none": plain HTTP, no TLS
//
// The _ipv4 / _ipv6 / _dual suffixes control address-family selection.
func ParseHTTPSTLSMode(mode TLSMode) (TLSMode, bool, TCPAddressFamily) {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	if raw == "" {
		return TLSModeTLS, true, TCPAddressFamilyDual
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
	case strings.HasSuffix(raw, "_dual"):
		family = TCPAddressFamilyDual
		base = strings.TrimSuffix(raw, "_dual")
	}

	switch TLSMode(base) {
	case TLSModeNone:
		return TLSModeNone, false, family
	case TLSModeTLS:
		return TLSModeTLS, true, family
	case TLSModeSTARTTLS:
		// Backward-compatible: "starttls" for HTTPS monitors means TLS without
		// certificate verification (e.g. self-signed certs). Prefer tls_insecure
		// for new monitors.
		return TLSModeSTARTTLS, false, family
	case TLSModeTLSInsecure:
		// Explicit insecure mode: TLS without certificate verification.
		return TLSModeTLS, false, family
	default:
		return TLSModeTLS, true, TCPAddressFamilyDual
	}
}

func ComposeHTTPSTLSMode(securityMode TLSMode, family TCPAddressFamily) TLSMode {
	securityMode = NormalizeHTTPSTLSSecurityMode(securityMode)
	family = NormalizeTCPAddressFamily(string(family))
	if family == TCPAddressFamilyDual {
		return TLSMode(string(securityMode) + "_dual")
	}
	return TLSMode(string(securityMode) + "_" + string(family))
}

func IsValidHTTPSTLSMode(mode TLSMode) bool {
	securityMode, _, _ := ParseHTTPSTLSMode(mode)
	return securityMode == TLSModeNone || securityMode == TLSModeTLS || securityMode == TLSModeSTARTTLS
}

func IsExplicitHTTPSInsecureMode(mode TLSMode) bool {
	securityMode, _, _ := ParseHTTPSTLSMode(mode)
	base := strings.ToLower(strings.TrimSpace(string(mode)))
	for _, suffix := range []string{"_ipv4", "_ipv6", "_dual"} {
		base = strings.TrimSuffix(base, suffix)
	}
	// tls_insecure is the explicit form; starttls is the legacy alias.
	return securityMode != TLSModeNone && (TLSMode(base) == TLSModeTLSInsecure || TLSMode(base) == TLSModeSTARTTLS)
}

func IsExplicitHTTPSFamilyMode(mode TLSMode) bool {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	return strings.HasSuffix(raw, "_ipv4") || strings.HasSuffix(raw, "_ipv6") || strings.HasSuffix(raw, "_dual")
}
