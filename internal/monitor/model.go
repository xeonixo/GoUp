package monitor

import "time"

type Kind string

type TLSMode string

type Status string

const (
	KindHTTPS Kind = "https"
	KindTCP   Kind = "tcp"
	KindICMP  Kind = "icmp"
	KindSMTP  Kind = "smtp"
	KindIMAP  Kind = "imap"
	KindDNS   Kind = "dns"
	KindUDP   Kind = "udp"
	KindWhois Kind = "whois"
	// KindHeartbeat is a push monitor: an external job calls a secret URL; silence means down.
	KindHeartbeat Kind = "heartbeat"
)

const (
	TLSModeNone             TLSMode = "none"
	TLSModeTLS              TLSMode = "tls"
	TLSModeSTARTTLS         TLSMode = "starttls"
	TLSModeTLSInsecure      TLSMode = "tls_insecure"
	TLSModeSTARTTLSInsecure TLSMode = "starttls_insecure"
)

const (
	StatusUp       Status = "up"
	StatusDown     Status = "down"
	StatusDegraded Status = "degraded"
	StatusUnknown  Status = "unknown"
)

type Monitor struct {
	ID                 int64
	Name               string
	Group              string
	SortOrder          int
	ExecutorKind       string
	ExecutorRef        string
	Kind               Kind
	Target             string
	Interval           time.Duration
	Timeout            time.Duration
	Enabled            bool
	TLSMode            TLSMode
	ExpectedStatusCode *int
	ExpectedText       string
	NotifyOnRecovery   bool
	RetryCount         int
	RetryInterval      time.Duration
	// MutedUntil suppresses notifications (checks keep running) until this time.
	MutedUntil *time.Time
	// CertWarningDays marks a monitor degraded when its certificate expires within this many days.
	CertWarningDays int
	// ConfirmAfter is the number of consecutive failed checks needed before a down/degraded
	// transition is announced; 0 or 1 announces immediately. Recovery is always immediate.
	ConfirmAfter int
	// RemindEveryMinutes repeats the down alert at this interval while the monitor stays down;
	// 0 disables reminders. See ValidRemindEveryMinutes for the allowed values.
	RemindEveryMinutes int
	// LastAlertAt is when the current outage was last announced (down alert or reminder); it is
	// cleared as soon as the monitor is no longer down. Reminders are measured from it.
	LastAlertAt *time.Time
	// MuteStartStatus is the status the monitor had when its notifications were muted. It is a
	// pending catch-up marker: once the mute is over the runner compares it with the current
	// status, sends at most one summary notification and clears it.
	MuteStartStatus Status
	// HeartbeatToken is the secret in the ping URL of a heartbeat monitor (empty for other kinds).
	HeartbeatToken string
	// LastHeartbeatAt is when the latest ping arrived; nil until the first one.
	LastHeartbeatAt *time.Time
	// LastHeartbeatFailed marks that the latest ping was a /fail call (the job reported an error).
	LastHeartbeatFailed bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ValidRemindEveryMinutes lists the reminder intervals the UI offers (0 = off).
var ValidRemindEveryMinutes = []int{0, 15, 30, 60, 120, 240, 720, 1440}

// ValidRemindEvery reports whether minutes is an allowed reminder interval.
func ValidRemindEvery(minutes int) bool {
	for _, allowed := range ValidRemindEveryMinutes {
		if minutes == allowed {
			return true
		}
	}
	return false
}

// RemindInterval returns the reminder interval, or 0 when reminders are off.
func (m Monitor) RemindInterval() time.Duration {
	if m.RemindEveryMinutes <= 0 {
		return 0
	}
	return time.Duration(m.RemindEveryMinutes) * time.Minute
}

// DefaultCertWarningDays is used when a monitor has no certificate warning threshold of its own.
const DefaultCertWarningDays = 7

// IsMuted reports whether notifications for this monitor are currently suppressed.
func (m Monitor) IsMuted(now time.Time) bool {
	return m.MutedUntil != nil && now.Before(*m.MutedUntil)
}

// EffectiveCertWarningDays returns the monitor's threshold or the default.
func (m Monitor) EffectiveCertWarningDays() int {
	if m.CertWarningDays <= 0 {
		return DefaultCertWarningDays
	}
	return m.CertWarningDays
}

type Result struct {
	ID               int64
	MonitorID        int64
	CheckedAt        time.Time
	Status           Status
	Latency          time.Duration
	Message          string
	HTTPStatusCode   *int
	TLSValid         *bool
	TLSNotAfter      *time.Time
	TLSDaysRemaining *int
	// InMaintenance marks a result recorded inside a maintenance window; it is excluded from
	// uptime and never triggers notifications.
	InMaintenance bool
}

type Snapshot struct {
	Monitor    Monitor
	LastResult *Result
}

// MaxHeartbeatCheckInterval bounds how often the runner evaluates a heartbeat monitor, so an
// overdue ping is noticed within about a minute even when the expected period is a day.
const MaxHeartbeatCheckInterval = time.Minute

// ScheduleInterval is the interval at which the runner evaluates the monitor. It equals
// Interval except for heartbeat monitors, whose Interval is the expected ping period.
func (m Monitor) ScheduleInterval() time.Duration {
	if m.Kind == KindHeartbeat && (m.Interval <= 0 || m.Interval > MaxHeartbeatCheckInterval) {
		return MaxHeartbeatCheckInterval
	}
	return m.Interval
}

func (s Snapshot) IsDue(now time.Time) bool {
	if !s.Monitor.Enabled {
		return false
	}
	if s.Monitor.ExecutorKind == "remote" {
		return false
	}
	if s.LastResult == nil {
		return true
	}
	return !s.LastResult.CheckedAt.Add(s.Monitor.ScheduleInterval()).After(now)
}
