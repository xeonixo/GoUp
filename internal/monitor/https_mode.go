package monitor

import "strings"

func NormalizeHTTPSTLSSecurityMode(mode TLSMode) TLSMode {
	securityMode, _ := ParseHTTPSTLSMode(mode)
	return securityMode
}

func ParseHTTPSTLSMode(mode TLSMode) (TLSMode, TCPAddressFamily) {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	if raw == "" {
		return TLSModeTLS, TCPAddressFamilyDual
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
	case TLSModeNone, TLSModeTLS, TLSModeSTARTTLS:
		return TLSMode(base), family
	default:
		return TLSModeTLS, TCPAddressFamilyDual
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
	securityMode, _ := ParseHTTPSTLSMode(mode)
	return securityMode == TLSModeNone || securityMode == TLSModeTLS || securityMode == TLSModeSTARTTLS
}

func IsExplicitHTTPSFamilyMode(mode TLSMode) bool {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	return strings.HasSuffix(raw, "_ipv4") || strings.HasSuffix(raw, "_ipv6") || strings.HasSuffix(raw, "_dual")
}
