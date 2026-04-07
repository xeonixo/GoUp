package monitor

import (
	"testing"
	"time"
)

func TestParseHTTPSTLSMode(t *testing.T) {
	mode, verify, family := ParseHTTPSTLSMode(TLSMode("tls_insecure_ipv6"))
	if mode != TLSModeTLS {
		t.Fatalf("mode = %q, want %q", mode, TLSModeTLS)
	}
	if verify {
		t.Fatalf("verify = true, want false")
	}
	if family != TCPAddressFamilyIPv6 {
		t.Fatalf("family = %q, want %q", family, TCPAddressFamilyIPv6)
	}
}

func TestComposeMailTLSMode(t *testing.T) {
	got := ComposeMailTLSMode(TLSModeSTARTTLS, false, TCPAddressFamilyIPv4)
	want := TLSMode("starttls_insecure_ipv4")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseUDPModeDefaults(t *testing.T) {
	kind, family := ParseUDPMode(TLSMode(""))
	if kind != UDPProbeKindWireGuard {
		t.Fatalf("kind = %q, want %q", kind, UDPProbeKindWireGuard)
	}
	if family != TCPAddressFamilyDual {
		t.Fatalf("family = %q, want %q", family, TCPAddressFamilyDual)
	}
}

func TestFormatLatency(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		out  string
	}{
		{name: "zero", in: 0, out: "0ms"},
		{name: "sub-millisecond", in: 500 * time.Microsecond, out: "<1ms"},
		{name: "milliseconds", in: 125 * time.Millisecond, out: "125ms"},
		{name: "seconds", in: 1500 * time.Millisecond, out: "1.5s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatLatency(tc.in); got != tc.out {
				t.Fatalf("formatLatency(%s) = %q, want %q", tc.in, got, tc.out)
			}
		})
	}
}

func TestBuildTransition(t *testing.T) {
	now := time.Now().UTC()
	snapshot := Snapshot{
		Monitor: Monitor{ID: 7, Name: "api", NotifyOnRecovery: true},
		LastResult: &Result{
			Status:    StatusDown,
			CheckedAt: now.Add(-time.Minute),
		},
	}
	current := Result{Status: StatusUp, CheckedAt: now, Message: "ok"}
	transition, ok := buildTransition(snapshot, current)
	if !ok {
		t.Fatalf("expected transition")
	}
	if transition.Previous != StatusDown || transition.Current != StatusUp {
		t.Fatalf("unexpected transition: %+v", transition)
	}
}

func TestBuildTransitionRecoveryDisabled(t *testing.T) {
	now := time.Now().UTC()
	snapshot := Snapshot{
		Monitor: Monitor{ID: 7, NotifyOnRecovery: false},
		LastResult: &Result{
			Status:    StatusDown,
			CheckedAt: now.Add(-time.Minute),
		},
	}
	current := Result{Status: StatusUp, CheckedAt: now, Message: "ok"}
	if _, ok := buildTransition(snapshot, current); ok {
		t.Fatalf("expected no transition when recovery notifications are disabled")
	}
}

func TestNormalizeDNSServer(t *testing.T) {
	got, err := NormalizeDNSServer("8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "8.8.8.8:53" {
		t.Fatalf("got %q, want %q", got, "8.8.8.8:53")
	}
}

func TestNormalizeDNSServerInvalidPort(t *testing.T) {
	if _, err := NormalizeDNSServer("8.8.8.8:99999"); err == nil {
		t.Fatalf("expected invalid port error")
	}
}

func TestFinalizeTLSResult(t *testing.T) {
	result := Result{}
	days := 3
	result.TLSDaysRemaining = &days
	status, msg := finalizeTLSResult(&result, "ok")
	if status != StatusDegraded {
		t.Fatalf("status = %q, want %q", status, StatusDegraded)
	}
	if msg == "ok" {
		t.Fatalf("expected degraded message details")
	}
}
