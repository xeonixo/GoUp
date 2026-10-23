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

// FormatOutageDuration renders an outage length compactly, e.g. "2 h 15 min" or "3 d 4 h".
func FormatOutageDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	switch {
	case d < time.Minute:
		return "< 1 min"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		h, m := int(d.Hours()), int(d.Minutes())%60
		if m == 0 {
			return fmt.Sprintf("%d h", h)
		}
		return fmt.Sprintf("%d h %d min", h, m)
	}
	days, hours := int(d.Hours())/24, int(d.Hours())%24
	if hours == 0 {
		return fmt.Sprintf("%d d", days)
	}
	return fmt.Sprintf("%d d %d h", days, hours)
}
