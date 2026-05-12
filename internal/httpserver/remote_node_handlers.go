package httpserver

import (
	"time"
)

const (
	remoteNodeAccessTokenTTL       = 5 * time.Minute
	remoteNodeDefaultPollIntervalS = 20
	remoteNodeBootstrapBodyLimit   = 4 * 1024
	remoteNodePollBodyLimit        = 4 * 1024
	remoteNodeReportBodyLimit      = 512 * 1024
	remoteNodeReportMaxResults     = 100
	remoteNodeReportMaxMessageLen  = 1000
	remoteNodeReportMaxPastSkew    = 24 * time.Hour
	remoteNodeReportMaxFutureSkew  = 10 * time.Minute
)

type remoteNodeBootstrapRequest struct {
	NodeID       string `json:"node_id"`
	BootstrapKey string `json:"bootstrap_key"`
}

type remoteNodePollRequest struct {
	AgentVersion string `json:"agent_version,omitempty"`
}

type remoteNodeMonitorPayload struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	Target             string `json:"target"`
	IntervalSeconds    int    `json:"interval_seconds"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	TLSMode            string `json:"tls_mode"`
	ExpectedStatusCode *int   `json:"expected_status_code,omitempty"`
	ExpectedText       string `json:"expected_text,omitempty"`
	NotifyOnRecovery   bool   `json:"notify_on_recovery"`
}

type remoteNodeReportRequest struct {
	Results []remoteNodeResultPayload `json:"results"`
}

type remoteNodeResultPayload struct {
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
