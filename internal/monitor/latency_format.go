package monitor

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func formatAttemptLabel(label string, attempt Result) string {
	if attempt.Status == StatusUp || attempt.Status == StatusDegraded {
		if attempt.Status == StatusDegraded {
			return fmt.Sprintf("%s degraded (%s)", label, attempt.Message)
		}
		return fmt.Sprintf("%s %s", label, formatLatency(attempt.Latency))
	}
	if strings.TrimSpace(attempt.Message) == "" {
		return label + " down"
	}
	return fmt.Sprintf("%s down (%s)", label, attempt.Message)
}

func formatLatency(duration time.Duration) string {
	if duration <= 0 {
		return "0ms"
	}
	if duration < time.Millisecond {
		return "<1ms"
	}
	if duration < time.Second {
		return strconv.FormatInt(duration.Milliseconds(), 10) + "ms"
	}
	seconds := duration.Seconds()
	formatted := strconv.FormatFloat(seconds, 'f', 2, 64)
	formatted = strings.TrimRight(strings.TrimRight(formatted, "0"), ".")
	return formatted + "s"
}
