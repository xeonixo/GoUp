package remotenode

import (
	"time"
)

type bootstrapRequest struct {
	NodeID       string `json:"node_id"`
	BootstrapKey string `json:"bootstrap_key"`
}

type bootstrapResponse struct {
	OK                  bool   `json:"ok"`
	AccessToken         string `json:"access_token"`
	AccessTokenExpires  string `json:"access_token_expires"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
}

type pollResponse struct {
	OK                  bool                  `json:"ok"`
	AccessToken         string                `json:"access_token"`
	AccessTokenExpires  string                `json:"access_token_expires"`
	PollIntervalSeconds int                   `json:"poll_interval_seconds"`
	AssignedMonitors    []assignedMonitorSpec `json:"assigned_monitors"`
}

type assignedMonitorSpec struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	Target             string `json:"target"`
	IntervalSeconds    int    `json:"interval_seconds"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	TLSMode            string `json:"tls_mode"`
	ExpectedStatusCode *int   `json:"expected_status_code,omitempty"`
	ExpectedText       string `json:"expected_text,omitempty"`
}

type reportRequest struct {
	Results []reportResult `json:"results"`
}

type reportResult struct {
	MonitorID        int64   `json:"monitor_id"`
	CheckedAt        string  `json:"checked_at"`
	Status           string  `json:"status"`
	LatencyMS        int64   `json:"latency_ms"`
	Message          string  `json:"message"`
	HTTPStatusCode   *int    `json:"http_status_code,omitempty"`
	TLSValid         *bool   `json:"tls_valid,omitempty"`
	TLSNotAfter      *string `json:"tls_not_after,omitempty"`
	TLSDaysRemaining *int    `json:"tls_days_remaining,omitempty"`
}

type remoteScheduleState struct {
	interval time.Duration
	nextDue  time.Time
	inFlight bool
}
