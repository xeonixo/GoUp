package monitor

import (
	"testing"
)

func TestParseDNSTargetPipe(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		expectedHost   string
		expectedRecord string
	}{
		{"pipe-separated", "example.com|a|8.8.8.8", "example.com", "a"},
		{"no pipes defaults to mixed", "example.com", "example.com", "mixed"},
		{"empty string", "", "", "mixed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDNSTarget(tt.raw)
			if got.Host != tt.expectedHost {
				t.Errorf("ParseDNSTarget(%q).Host = %q, want %q", tt.raw, got.Host, tt.expectedHost)
			}
			if string(got.RecordType) != tt.expectedRecord {
				t.Errorf("ParseDNSTarget(%q).RecordType = %v, want %q", tt.raw, got.RecordType, tt.expectedRecord)
			}
		})
	}
}

func TestNormalizeDNSRecordTypeLowercase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"uppercase A", "A", "a"},
		{"uppercase MX", "MX", "mx"},
		{"uppercase CNAME", "CNAME", "cname"},
		{"already lowercase", "txt", "txt"},
		{"invalid defaults", "INVALID", "mixed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDNSRecordType(tt.input)
			if string(got) != tt.expected {
				t.Errorf("NormalizeDNSRecordType(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNormalizeTCPAddressFamilyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"ipv4 unchanged", "ipv4", "ipv4"},
		{"ipv6 unchanged", "ipv6", "ipv6"},
		{"uppercase normalized", "IPV4", "ipv4"},
		{"invalid defaults to dual", "invalid", "dual"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeTCPAddressFamily(tt.input)
			if string(got) != tt.expected {
				t.Errorf("NormalizeTCPAddressFamily(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNormalizeMailTLSSecurityMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"none preserved", "none", "none"},
		{"tls preserved", "tls", "tls"},
		{"starttls preserved", "starttls", "starttls"},
		{"tls_insecure normalizes to tls", "tls_insecure", "tls"},
		{"starttls_insecure normalizes to starttls", "starttls_insecure", "starttls"},
		{"invalid defaults to none", "invalid", "none"},
		{"empty defaults to none", "", "none"},
		{"uppercase normalized", "TLS", "tls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeMailTLSSecurityMode(TLSMode(tt.input))
			if string(got) != tt.expected {
				t.Errorf("NormalizeMailTLSSecurityMode(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsValidMailTLSMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"none is valid", "none", true},
		{"tls is valid", "tls", true},
		{"starttls is valid", "starttls", true},
		{"tls_insecure is valid (normalizes to tls)", "tls_insecure", true},
		{"starttls_insecure is valid", "starttls_insecure", true},
		// unknown inputs normalize to none, which is a valid mode
		{"invalid normalizes to none", "invalid", true},
		{"empty normalizes to none", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidMailTLSMode(TLSMode(tt.input))
			if got != tt.expected {
				t.Errorf("IsValidMailTLSMode(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsValidTCPTLSMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"none is valid", "none", true},
		{"tls is valid", "tls", true},
		{"starttls is valid (backward compat)", "starttls", true},
		{"tls_insecure is valid", "tls_insecure", true},
		// unknown inputs normalize to none, which is a valid mode
		{"invalid normalizes to none", "invalid", true},
		{"empty normalizes to none", "", true},
		// family suffixes still produce valid modes
		{"tls_ipv4 is valid", "tls_ipv4", true},
		{"none_ipv6 is valid", "none_ipv6", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidTCPTLSMode(TLSMode(tt.input))
			if got != tt.expected {
				t.Errorf("IsValidTCPTLSMode(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsValidUDPMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"dns is valid", "dns", true},
		{"ntp is valid", "ntp", true},
		{"dns_ipv4 is valid", "dns_ipv4", true},
		{"ntp_ipv6 is valid", "ntp_ipv6", true},
		// unknown input normalizes to dns (the default), which is valid
		{"unknown normalizes to dns", "unknown", true},
		// empty/none returns wireguard which is also valid
		{"empty returns wireguard", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidUDPMode(TLSMode(tt.input))
			if got != tt.expected {
				t.Errorf("IsValidUDPMode(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
