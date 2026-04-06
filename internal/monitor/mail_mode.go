package monitor

import "strings"

func NormalizeMailTLSSecurityMode(mode TLSMode) TLSMode {
	securityMode, _, _ := ParseMailTLSMode(mode)
	return securityMode
}

func ParseMailTLSMode(mode TLSMode) (TLSMode, bool, TCPAddressFamily) {
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
		return TLSModeSTARTTLS, true, family
	case TLSModeTLSInsecure:
		return TLSModeTLS, false, family
	case TLSModeSTARTTLSInsecure:
		return TLSModeSTARTTLS, false, family
	default:
		return TLSModeNone, false, TCPAddressFamilyDual
	}
}

func ComposeMailTLSMode(securityMode TLSMode, verifyCertificate bool, family TCPAddressFamily) TLSMode {
	securityMode = NormalizeMailTLSSecurityMode(securityMode)
	family = NormalizeTCPAddressFamily(string(family))

	base := TLSModeNone
	switch securityMode {
	case TLSModeTLS:
		if verifyCertificate {
			base = TLSModeTLS
		} else {
			base = TLSModeTLSInsecure
		}
	case TLSModeSTARTTLS:
		if verifyCertificate {
			base = TLSModeSTARTTLS
		} else {
			base = TLSModeSTARTTLSInsecure
		}
	default:
		base = TLSModeNone
	}

	if family == TCPAddressFamilyDual {
		return base
	}
	return TLSMode(string(base) + "_" + string(family))
}

func IsValidMailTLSMode(mode TLSMode) bool {
	securityMode, _, _ := ParseMailTLSMode(mode)
	return securityMode == TLSModeNone || securityMode == TLSModeTLS || securityMode == TLSModeSTARTTLS
}
