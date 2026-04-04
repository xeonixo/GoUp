package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSChecker resolves a hostname using the system resolver and optionally checks
// that a specific value appears in the results.
//
// Target:       hostname to resolve (e.g. "example.com")
// ExpectedText: optional IP address that must appear among the resolved addresses
//               (case-insensitive substring match). Leave empty to just verify
//               the hostname resolves at all.
type DNSChecker struct{}

func (c DNSChecker) Check(ctx context.Context, item Monitor) Result {
	start := time.Now()
	target := strings.TrimSpace(item.Target)
	expected := strings.ToLower(strings.TrimSpace(item.ExpectedText))
	timeout := item.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(resolveCtx, target)
	latency := time.Since(start)
	if err != nil {
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Latency:   latency,
			Message:   fmt.Sprintf("DNS lookup failed: %v", err),
		}
	}

	if len(addrs) == 0 {
		return Result{
			MonitorID: item.ID,
			CheckedAt: time.Now().UTC(),
			Status:    StatusDown,
			Latency:   latency,
			Message:   "DNS lookup returned no records",
		}
	}

	if expected != "" {
		found := false
		for _, addr := range addrs {
			if strings.Contains(strings.ToLower(addr), expected) {
				found = true
				break
			}
		}
		if !found {
			return Result{
				MonitorID: item.ID,
				CheckedAt: time.Now().UTC(),
				Status:    StatusDown,
				Latency:   latency,
				Message:   fmt.Sprintf("DNS resolved but expected %q not found in: %s", item.ExpectedText, strings.Join(addrs, ", ")),
			}
		}
	}

	return Result{
		MonitorID: item.ID,
		CheckedAt: time.Now().UTC(),
		Status:    StatusUp,
		Latency:   latency,
		Message:   fmt.Sprintf("Resolved: %s", strings.Join(addrs, ", ")),
	}
}
