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
	TLSModeNone     TLSMode = "none"
	TLSModeTLS      TLSMode = "tls"
	TLSModeSTARTTLS TLSMode = "starttls"
)

const (
	StatusUp       Status = "up"
	StatusDown     Status = "down"
	StatusDegraded Status = "degraded"
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
	CreatedAt          time.Time
	UpdatedAt          time.Time
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
