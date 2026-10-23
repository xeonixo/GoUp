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
	// MuteStartStatus is the status the monitor had when its notifications were muted. It is a
	// pending catch-up marker: once the mute is over the runner compares it with the current
	// status, sends at most one summary notification and clears it.
	MuteStartStatus Status
	CreatedAt       time.Time
	UpdatedAt       time.Time
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
}

type Snapshot struct {
	Monitor    Monitor
	LastResult *Result
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
	return !s.LastResult.CheckedAt.Add(s.Monitor.Interval).After(now)
}
