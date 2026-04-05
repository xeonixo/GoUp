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
	securityMode, _ := ParseTCPTLSMode(mode)
	return securityMode
}

func ParseTCPTLSMode(mode TLSMode) (TLSMode, TCPAddressFamily) {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	if raw == "" {
		return TLSModeNone, TCPAddressFamilyDual
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
	case TLSModeNone, TLSModeTLS, TLSModeSTARTTLS:
		return TLSMode(base), family
	default:
		return TLSModeNone, TCPAddressFamilyDual
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
	securityMode, _ := ParseTCPTLSMode(mode)
	return securityMode == TLSModeNone || securityMode == TLSModeTLS || securityMode == TLSModeSTARTTLS
}
