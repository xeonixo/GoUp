package monitor

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"goup/internal/netguard"
)

// allowPrivateTargets controls whether monitors may reach private/loopback
// networks (GOUP_MONITOR_ALLOW_PRIVATE, default true: homelab monitoring of
// internal hosts is the main use case). Cloud metadata endpoints are blocked
// regardless of this setting.
var allowPrivateTargets atomic.Bool

func init() {
	allowPrivateTargets.Store(true)
}

// SetAllowPrivateTargets configures the monitor network policy. It is called
// once at startup with the value of GOUP_MONITOR_ALLOW_PRIVATE.
func SetAllowPrivateTargets(allow bool) {
	allowPrivateTargets.Store(allow)
}

// newMonitorDialer returns a dialer that enforces the monitor network policy
// on the resolved peer address (so DNS rebinding and redirects are covered).
func newMonitorDialer(timeout time.Duration) *net.Dialer {
	return netguard.NewDialer(timeout, allowPrivateTargets.Load())
}

// monitorAllowsIP reports whether a resolved peer address may be contacted.
func monitorAllowsIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return netguard.Allowed(addr.Unmap(), allowPrivateTargets.Load())
}
