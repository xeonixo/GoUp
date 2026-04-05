package monitor

import "strings"

type UDPProbeKind string

const (
	UDPProbeKindDNS       UDPProbeKind = "dns"
	UDPProbeKindNTP       UDPProbeKind = "ntp"
	UDPProbeKindWireGuard UDPProbeKind = "wireguard"
)

func NormalizeUDPProbeKind(raw string) UDPProbeKind {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(UDPProbeKindDNS):
		return UDPProbeKindDNS
	case string(UDPProbeKindNTP):
		return UDPProbeKindNTP
	default:
		return UDPProbeKindDNS
	}
}

func ParseUDPMode(mode TLSMode) (UDPProbeKind, TCPAddressFamily) {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	if raw == "" || raw == string(TLSModeNone) {
		return UDPProbeKindWireGuard, TCPAddressFamilyDual
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

	return NormalizeUDPProbeKind(base), family
}

func ComposeUDPMode(kind UDPProbeKind, family TCPAddressFamily) TLSMode {
	kind = NormalizeUDPProbeKind(string(kind))
	family = NormalizeTCPAddressFamily(string(family))
	return TLSMode(string(kind) + "_" + string(family))
}

func IsValidUDPMode(mode TLSMode) bool {
	kind, _ := ParseUDPMode(mode)
	return kind == UDPProbeKindDNS || kind == UDPProbeKindNTP || kind == UDPProbeKindWireGuard
}

func IsExplicitUDPFamilyMode(mode TLSMode) bool {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	return strings.HasSuffix(raw, "_ipv4") || strings.HasSuffix(raw, "_ipv6") || strings.HasSuffix(raw, "_dual")
}
