package monitor

import "testing"

func TestNormalizeICMPTarget(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "hostname", input: "example.com", want: "example.com"},
		{name: "ipv4", input: "1.1.1.1", want: "1.1.1.1"},
		{name: "invalid ipv4 literal treated as hostname", input: "999.999.999.999", want: "999.999.999.999"},
		{name: "url host extracted", input: "https://example.com/health", want: "example.com"},
		{name: "host port normalized", input: "example.com:443", want: "example.com"},
		{name: "bracket ipv6", input: "[2001:db8::1]", want: "2001:db8::1"},
		{name: "empty", input: "  ", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeICMPTarget(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got target %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
