package monitor

import "strings"

// SDNSTransport is the encrypted DNS transport of a secure-DNS monitor.
type SDNSTransport string

const (
	// SDNSTransportDoH is DNS over HTTPS (RFC 8484) on HTTP/1.1 or HTTP/2.
	SDNSTransportDoH SDNSTransport = "doh"
	// SDNSTransportDoT is DNS over TLS (RFC 7858), default port 853.
	SDNSTransportDoT SDNSTransport = "dot"
	// SDNSTransportDoQ is DNS over QUIC (RFC 9250), default port 853, ALPN "doq".
	SDNSTransportDoQ SDNSTransport = "doq"
	// SDNSTransportDoH3 is DNS over HTTP/3 (RFC 8484 on HTTP/3).
	SDNSTransportDoH3 SDNSTransport = "doh3"
)

// SDNSMethod is the HTTP request style for DoH and DoH3.
// POST sends the DNS wire message as the body. GET puts the same bytes,
// base64url-encoded without padding, in the dns query parameter (RFC 8484).
type SDNSMethod string

const (
	SDNSMethodPOST SDNSMethod = "post"
	SDNSMethodGET  SDNSMethod = "get"
)

type sdnsSettings struct {
	Transport SDNSTransport
	Method    SDNSMethod
	Verify    bool
	Family    TCPAddressFamily
}

// UsesUDP reports whether the transport dials UDP (QUIC) rather than TCP.
func (t SDNSTransport) UsesUDP() bool {
	return t == SDNSTransportDoQ || t == SDNSTransportDoH3
}

// UsesHTTP reports whether the transport speaks the RFC 8484 HTTP binding.
func (t SDNSTransport) UsesHTTP() bool {
	return t == SDNSTransportDoH || t == SDNSTransportDoH3
}

// Label is the short name used in check messages and the dashboard.
func (t SDNSTransport) Label() string {
	switch NormalizeSDNSTransport(string(t)) {
	case SDNSTransportDoT:
		return "DoT"
	case SDNSTransportDoQ:
		return "DoQ"
	case SDNSTransportDoH3:
		return "DoH3"
	default:
		return "DoH"
	}
}

// NormalizeSDNSTransport maps user input onto a known transport. Unknown values become DoH.
func NormalizeSDNSTransport(raw string) SDNSTransport {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(SDNSTransportDoT):
		return SDNSTransportDoT
	case string(SDNSTransportDoQ):
		return SDNSTransportDoQ
	case string(SDNSTransportDoH3), "http3", "h3":
		return SDNSTransportDoH3
	default:
		return SDNSTransportDoH
	}
}

// NormalizeSDNSMethod maps user input onto GET or POST. Anything other than GET is POST.
func NormalizeSDNSMethod(raw string) SDNSMethod {
	if strings.EqualFold(strings.TrimSpace(raw), string(SDNSMethodGET)) {
		return SDNSMethodGET
	}
	return SDNSMethodPOST
}

// ParseSDNSMode decodes the tls_mode column of a secure-DNS monitor.
//
// Shape: transport, optional _get, optional _insecure, optional _ipv4/_ipv6/_dual.
// POST, certificate verification, and dual-stack are the defaults and are omitted
// from the stored value. Examples: "doh", "doh_get_ipv6", "dot_insecure", "doq_ipv4".
func ParseSDNSMode(mode TLSMode) sdnsSettings {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	settings := sdnsSettings{
		Transport: SDNSTransportDoH,
		Method:    SDNSMethodPOST,
		Verify:    true,
		Family:    TCPAddressFamilyDual,
	}
	if raw == "" {
		return settings
	}

	switch {
	case strings.HasSuffix(raw, "_ipv4"):
		settings.Family = TCPAddressFamilyIPv4
		raw = strings.TrimSuffix(raw, "_ipv4")
	case strings.HasSuffix(raw, "_ipv6"):
		settings.Family = TCPAddressFamilyIPv6
		raw = strings.TrimSuffix(raw, "_ipv6")
	case strings.HasSuffix(raw, "_dual"):
		settings.Family = TCPAddressFamilyDual
		raw = strings.TrimSuffix(raw, "_dual")
	}

	if strings.HasSuffix(raw, "_insecure") {
		settings.Verify = false
		raw = strings.TrimSuffix(raw, "_insecure")
	}
	if strings.HasSuffix(raw, "_get") {
		settings.Method = SDNSMethodGET
		raw = strings.TrimSuffix(raw, "_get")
	} else if strings.HasSuffix(raw, "_post") {
		settings.Method = SDNSMethodPOST
		raw = strings.TrimSuffix(raw, "_post")
	}

	switch SDNSTransport(raw) {
	case SDNSTransportDoH, SDNSTransportDoT, SDNSTransportDoQ, SDNSTransportDoH3:
		settings.Transport = SDNSTransport(raw)
	default:
		return sdnsSettings{Transport: SDNSTransportDoH, Method: SDNSMethodPOST, Verify: true, Family: TCPAddressFamilyDual}
	}
	if !settings.Transport.UsesHTTP() {
		settings.Method = SDNSMethodPOST
	}
	return settings
}

// ComposeSDNSMode encodes transport, HTTP method, certificate verification, and address family.
func ComposeSDNSMode(transport SDNSTransport, method SDNSMethod, verify bool, family TCPAddressFamily) TLSMode {
	transport = NormalizeSDNSTransport(string(transport))
	family = NormalizeTCPAddressFamily(string(family))
	base := string(transport)
	if transport.UsesHTTP() && NormalizeSDNSMethod(string(method)) == SDNSMethodGET {
		base += "_get"
	}
	if !verify {
		base += "_insecure"
	}
	if family != TCPAddressFamilyDual {
		base += "_" + string(family)
	}
	return TLSMode(base)
}

// SDNSTransportOf returns the transport encoded in mode.
func SDNSTransportOf(mode TLSMode) SDNSTransport {
	return ParseSDNSMode(mode).Transport
}

// IsValidSDNSMode reports whether mode is a known secure-DNS mode.
// An empty mode is not valid; the form always stores an explicit transport.
func IsValidSDNSMode(mode TLSMode) bool {
	raw := strings.ToLower(strings.TrimSpace(string(mode)))
	if raw == "" {
		return false
	}
	switch {
	case strings.HasSuffix(raw, "_ipv4"):
		raw = strings.TrimSuffix(raw, "_ipv4")
	case strings.HasSuffix(raw, "_ipv6"):
		raw = strings.TrimSuffix(raw, "_ipv6")
	case strings.HasSuffix(raw, "_dual"):
		raw = strings.TrimSuffix(raw, "_dual")
	}
	if strings.HasSuffix(raw, "_insecure") {
		raw = strings.TrimSuffix(raw, "_insecure")
	}
	if strings.HasSuffix(raw, "_get") {
		raw = strings.TrimSuffix(raw, "_get")
	} else if strings.HasSuffix(raw, "_post") {
		raw = strings.TrimSuffix(raw, "_post")
	}
	switch SDNSTransport(raw) {
	case SDNSTransportDoH, SDNSTransportDoT, SDNSTransportDoQ, SDNSTransportDoH3:
		return true
	default:
		return false
	}
}
