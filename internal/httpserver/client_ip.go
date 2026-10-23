package httpserver

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// remoteAddrIP returns the parsed peer address of the TCP connection.
func remoteAddrIP(r *http.Request) (netip.Addr, bool) {
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func (s *Server) isTrustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range s.cfg.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// fromTrustedProxy reports whether the direct peer is a configured proxy.
func (s *Server) fromTrustedProxy(r *http.Request) bool {
	if len(s.cfg.TrustedProxies) == 0 {
		return false
	}
	addr, ok := remoteAddrIP(r)
	return ok && s.isTrustedProxy(addr)
}

// clientIP returns the client address. X-Forwarded-For / X-Real-IP are only
// honored when the direct peer is in GOUP_TRUSTED_PROXIES; the rightmost
// untrusted hop of X-Forwarded-For is used, so client-supplied leading entries
// cannot spoof the address.
func (s *Server) clientIP(r *http.Request) string {
	remote, ok := remoteAddrIP(r)
	if !ok {
		raw := strings.TrimSpace(r.RemoteAddr)
		if raw == "" {
			return "unknown"
		}
		return raw
	}
	if !s.isTrustedProxy(remote) {
		return remote.String()
	}

	if values := r.Header.Values("X-Forwarded-For"); len(values) > 0 {
		var hops []string
		for _, v := range values {
			for _, part := range strings.Split(v, ",") {
				if part = strings.TrimSpace(part); part != "" {
					hops = append(hops, part)
				}
			}
		}
		for i := len(hops) - 1; i >= 0; i-- {
			addr, err := netip.ParseAddr(strings.Trim(hops[i], "[]"))
			if err != nil {
				// Malformed hop: stop trusting the chain beyond this point.
				break
			}
			addr = addr.Unmap()
			if s.isTrustedProxy(addr) {
				continue
			}
			return addr.String()
		}
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		if addr, err := netip.ParseAddr(real); err == nil {
			return addr.Unmap().String()
		}
	}
	return remote.String()
}

// rateLimitIP is clientIP normalized for use as a rate-limit key: IPv6
// addresses collapse to their /64 so that a client cannot rotate through a
// whole prefix to dodge lockouts.
func (s *Server) rateLimitIP(r *http.Request) string {
	return normalizeRateLimitIP(s.clientIP(r))
}

func normalizeRateLimitIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}

// requestIsHTTPS reports whether the client-facing connection uses TLS,
// either because the base URL is https, TLS terminates here, or a trusted
// proxy says so via X-Forwarded-Proto.
func (s *Server) requestIsHTTPS(r *http.Request) bool {
	if s.cfg.SecureCookies() {
		return true
	}
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if s.fromTrustedProxy(r) {
		proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
		return strings.EqualFold(proto, "https")
	}
	return false
}
