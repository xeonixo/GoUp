// Package netguard provides SSRF protection helpers: IP classification, a
// net.Dialer that validates the resolved peer address at connect time, and an
// http.Client constructor that re-checks every redirect hop.
package netguard

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// ErrBlockedAddress is returned when a destination address is not allowed.
var ErrBlockedAddress = errors.New("target address is blocked")

// EnvAllowPrivateIntegrations opts in to private destinations for integrations
// (Matrix homeserver, OIDC issuer).
const EnvAllowPrivateIntegrations = "GOUP_ALLOW_PRIVATE_INTEGRATIONS"

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// alwaysBlocked holds cloud metadata endpoints that are never reachable, even
// when private networks are allowed.
var alwaysBlocked = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("100.100.100.200"),
}

// IsPublicIP reports whether addr is a globally routable unicast address.
func IsPublicIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// AlwaysBlocked reports whether addr is a cloud metadata address (or
// otherwise invalid / unspecified) that must never be contacted.
func AlwaysBlocked(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return true
	}
	for _, blocked := range alwaysBlocked {
		if addr == blocked {
			return true
		}
	}
	return false
}

// Allowed applies the policy: metadata addresses are always rejected, private
// addresses only when allowPrivate is set.
func Allowed(addr netip.Addr, allowPrivate bool) bool {
	addr = addr.Unmap()
	if AlwaysBlocked(addr) {
		return false
	}
	if allowPrivate {
		return !addr.IsUnspecified() && !addr.IsMulticast()
	}
	return IsPublicIP(addr)
}

// AllowPrivateIntegrationsFromEnv reads GOUP_ALLOW_PRIVATE_INTEGRATIONS.
func AllowPrivateIntegrationsFromEnv() bool {
	return envTrue(os.Getenv(EnvAllowPrivateIntegrations))
}

func envTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ControlFunc returns a net.Dialer.Control hook which rejects connections to
// addresses that violate the policy. It runs after DNS resolution on the
// concrete peer address, which defeats DNS rebinding.
func ControlFunc(allowPrivate bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return ErrBlockedAddress
		}
		if !Allowed(addr, allowPrivate) {
			return ErrBlockedAddress
		}
		return nil
	}
}

// NewDialer returns a net.Dialer guarded by the policy.
func NewDialer(timeout time.Duration, allowPrivate bool) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: ControlFunc(allowPrivate)}
}

// ValidateURL checks scheme/host of a user supplied URL. Literal IPs are
// checked immediately; hostnames are checked at dial time.
func ValidateURL(raw string, allowPrivate bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, errors.New("url must use https")
	}
	if parsed.User != nil {
		return nil, errors.New("url must not contain credentials")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return nil, errors.New("url host is required")
	}
	if addr, err := netip.ParseAddr(host); err == nil && !Allowed(addr, allowPrivate) {
		return nil, ErrBlockedAddress
	}
	if !allowPrivate {
		lower := strings.ToLower(host)
		if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
			return nil, ErrBlockedAddress
		}
	}
	return parsed, nil
}

// Options configures NewHTTPClient.
type Options struct {
	Timeout      time.Duration
	AllowPrivate bool
	// MaxRedirects is the number of redirects followed. 0 disables redirects
	// (the first response is returned as an error).
	MaxRedirects int
	// UseEnvProxy honors HTTP(S)_PROXY. The proxy address itself is subject to
	// the same policy.
	UseEnvProxy bool
	// KeepAlives enables connection reuse.
	KeepAlives bool
}

// NewHTTPClient builds an HTTP client whose connections are validated at dial
// time and whose redirects are re-validated (https only, no credentials).
func NewHTTPClient(opts Options) *http.Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := &http.Transport{
		DisableKeepAlives:   !opts.KeepAlives,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext:         NewDialer(timeout, opts.AllowPrivate).DialContext,
	}
	if opts.UseEnvProxy {
		transport.Proxy = http.ProxyFromEnvironment
	}
	maxRedirects := opts.MaxRedirects
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if maxRedirects <= 0 {
				return errors.New("redirects are not allowed")
			}
			if len(via) > maxRedirects {
				return errors.New("too many redirects")
			}
			if _, err := ValidateURL(req.URL.String(), opts.AllowPrivate); err != nil {
				return fmt.Errorf("redirect target rejected: %w", err)
			}
			return nil
		},
	}
}
