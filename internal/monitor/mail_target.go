package monitor

import (
	"net"
	"strings"
	"time"
)

func mailTargetUsesHostname(target string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return false
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	return host != "" && net.ParseIP(host) == nil
}

func aggregateMailDualStackResult(monitorID int64, checkedAt time.Time, startedAt time.Time, protocol string, v4Attempt Result, v6Attempt Result) Result {
	result := Result{MonitorID: monitorID, CheckedAt: checkedAt, Status: StatusDown}
	v4Label := formatAttemptLabel("IPv4", v4Attempt)
	v6Label := formatAttemptLabel("IPv6", v6Attempt)
	v4Up := v4Attempt.Status == StatusUp || v4Attempt.Status == StatusDegraded
	v6Up := v6Attempt.Status == StatusUp || v6Attempt.Status == StatusDegraded

	switch {
	case v4Up && v6Up:
		result.Status = StatusUp
		if v4Attempt.Status == StatusDegraded || v6Attempt.Status == StatusDegraded {
			result.Status = StatusDegraded
		}
		result.Latency = (v4Attempt.Latency + v6Attempt.Latency) / 2
		adoptTCPAttemptMetadata(&result, v4Attempt)
		if result.TLSValid == nil {
			adoptTCPAttemptMetadata(&result, v6Attempt)
		}
		state := "ok"
		if result.Status == StatusDegraded {
			state = "degraded"
		}
		result.Message = protocol + " dual stack " + state + " · " + v4Label + " · " + v6Label
	case v4Up || v6Up:
		result.Status = StatusDegraded
		if v4Up {
			result.Latency = v4Attempt.Latency
			adoptTCPAttemptMetadata(&result, v4Attempt)
		} else {
			result.Latency = v6Attempt.Latency
			adoptTCPAttemptMetadata(&result, v6Attempt)
		}
		result.Message = protocol + " dual stack degraded · " + v4Label + " · " + v6Label
	default:
		result.Status = StatusDown
		result.Latency = time.Since(startedAt)
		result.Message = protocol + " dual stack failed · " + v4Label + " · " + v6Label
	}
	return result
}
