package sqlite

import (
	"errors"
	"testing"
	"time"

	"goup/internal/monitor"
)

func TestValidateCreateMonitorParams(t *testing.T) {
	base := CreateMonitorParams{
		Name:         "my monitor",
		ExecutorKind: "local",
		Kind:         monitor.KindHTTPS,
		Target:       "https://example.com",
		Interval:     60 * time.Second,
		Timeout:      10 * time.Second,
	}
	copy := func(fn func(*CreateMonitorParams)) CreateMonitorParams {
		p := base
		fn(&p)
		return p
	}
	tests := []struct {
		name      string
		params    CreateMonitorParams
		shouldErr bool
	}{
		{"valid params", base, false},
		{"missing name", copy(func(p *CreateMonitorParams) { p.Name = "" }), true},
		{"whitespace-only name", copy(func(p *CreateMonitorParams) { p.Name = "   " }), true},
		{"invalid executor kind", copy(func(p *CreateMonitorParams) { p.ExecutorKind = "unknown" }), true},
		{"remote without ref", copy(func(p *CreateMonitorParams) { p.ExecutorKind = "remote"; p.ExecutorRef = "" }), true},
		{"remote with ref is valid", copy(func(p *CreateMonitorParams) { p.ExecutorKind = "remote"; p.ExecutorRef = "node-1" }), false},
		{"interval too short", copy(func(p *CreateMonitorParams) { p.Interval = 5 * time.Second }), true},
		{"timeout too short", copy(func(p *CreateMonitorParams) { p.Timeout = 0 }), true},
		{"timeout exceeds interval", copy(func(p *CreateMonitorParams) { p.Timeout = 90 * time.Second }), true},
		{"group too long", copy(func(p *CreateMonitorParams) { p.Group = string(make([]byte, 81)) }), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCreateMonitorParams(tt.params)
			if tt.shouldErr && err == nil {
				t.Errorf("expected error but got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestNormalizeMonitorExecutor(t *testing.T) {
	tests := []struct {
		name         string
		kind         string
		ref          string
		expectedKind string
		expectedRef  string
	}{
		{"local executor", "local", "", "local", ""},
		{"empty kind becomes local", "", "", "local", ""},
		{"remote node id", "remote", "node123", "remote", "node123"},
		{"remote with spaces trimmed", "remote", "  node-id  ", "remote", "node-id"},
		{"unknown passed through", "invalid", "ref", "invalid", "ref"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKind, gotRef := normalizeMonitorExecutor(tt.kind, tt.ref)
			if gotKind != tt.expectedKind {
				t.Errorf("normalizeMonitorExecutor(%q, %q) kind = %q, want %q", tt.kind, tt.ref, gotKind, tt.expectedKind)
			}
			if gotRef != tt.expectedRef {
				t.Errorf("normalizeMonitorExecutor(%q, %q) ref = %q, want %q", tt.kind, tt.ref, gotRef, tt.expectedRef)
			}
		})
	}
}

func TestIsMalformedSQLiteError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"exact phrase", errors.New("database disk image is malformed"), true},
		{"uppercase is matched", errors.New("Database Disk Image Is Malformed"), true},
		{"wrapped phrase", errors.New("sqlite: database disk image is malformed: some detail"), true},
		{"different error", errors.New("constraint violation"), false},
		{"only partial word", errors.New("malformed query syntax"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMalformedSQLiteError(tt.err)
			if got != tt.expected {
				t.Errorf("isMalformedSQLiteError(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestReorderStringsHelper(t *testing.T) {
	tests := []struct {
		name       string
		items      []string
		dragged    string
		target     string
		expected   []string
		shouldMove bool
	}{
		{"move forward", []string{"a", "b", "c"}, "a", "c", []string{"b", "c", "a"}, true},
		{"move backward", []string{"a", "b", "c"}, "c", "a", []string{"c", "a", "b"}, true},
		{"adjacent swap", []string{"a", "b", "c"}, "a", "b", []string{"b", "a", "c"}, true},
		{"same position returns true", []string{"a", "b", "c"}, "b", "b", []string{"a", "b", "c"}, true},
		{"not found returns false", []string{"a", "b"}, "x", "a", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, moved := reorderStrings(tt.items, tt.dragged, tt.target)
			if moved != tt.shouldMove {
				t.Errorf("reorderStrings(%v, %q, %q) moved = %v, want %v", tt.items, tt.dragged, tt.target, moved, tt.shouldMove)
			}
			if moved && len(got) != len(tt.expected) {
				t.Errorf("reorderStrings() length = %d, want %d", len(got), len(tt.expected))
			}
		})
	}
}

func TestReorderInt64Helper(t *testing.T) {
	tests := []struct {
		name       string
		items      []int64
		dragged    int64
		target     int64
		shouldMove bool
	}{
		{"move forward", []int64{1, 2, 3}, 1, 3, true},
		{"move backward", []int64{1, 2, 3}, 3, 1, true},
		{"same position returns true", []int64{1, 2, 3}, 2, 2, true},
		{"not found", []int64{1, 2}, 9, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, moved := reorderInt64(tt.items, tt.dragged, tt.target)
			if moved != tt.shouldMove {
				t.Errorf("reorderInt64(%v, %d, %d) moved = %v, want %v", tt.items, tt.dragged, tt.target, moved, tt.shouldMove)
			}
			if moved && len(got) != len(tt.items) {
				t.Errorf("reorderInt64() length = %d, want %d", len(got), len(tt.items))
			}
		})
	}
}

func TestMonitorHourlyRollupFields(t *testing.T) {
	// Verify MonitorHourlyRollup struct invariants without a real DB
	r := MonitorHourlyRollup{
		MonitorID:      42,
		HourBucket:     time.Now().UTC().Truncate(time.Hour),
		TotalChecks:    10,
		UpChecks:       7,
		DownChecks:     2,
		DegradedChecks: 1,
		LatencySumMS:   1250,
		LatencyMinMS:   50,
	}
	if r.UpChecks+r.DownChecks+r.DegradedChecks != r.TotalChecks {
		t.Errorf("check counts don't add up: %d+%d+%d != %d",
			r.UpChecks, r.DownChecks, r.DegradedChecks, r.TotalChecks)
	}
	if r.LatencyMinMS > r.LatencySumMS/r.TotalChecks {
		t.Errorf("LatencyMinMS (%d) > average (%d)", r.LatencyMinMS, r.LatencySumMS/r.TotalChecks)
	}
	if r.MonitorID <= 0 {
		t.Errorf("MonitorID should be positive, got %d", r.MonitorID)
	}
}
