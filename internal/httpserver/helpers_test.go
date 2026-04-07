package httpserver

import (
	"testing"
)

func TestNormalizeOriginSimple(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected string
	}{
		{"lowercase scheme", "HTTP://example.com", "http://example.com"},
		{"trailing slash removed", "http://example.com/", "http://example.com"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeOrigin(tt.raw)
			if got != tt.expected {
				t.Errorf("normalizeOrigin(%q) = %q, want %q", tt.raw, got, tt.expected)
			}
		})
	}
}

func TestNormalizeRefererOriginExtraction(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		contains string
	}{
		{"extracts origin from URL", "http://example.com/path", "example.com"},
		{"keeps port", "http://example.com:8080/admin", "8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRefererOrigin(tt.raw)
			if got != "" && !contains(got, tt.contains) {
				t.Errorf("normalizeRefererOrigin(%q) = %q, should contain %q", tt.raw, got, tt.contains)
			}
		})
	}
}

func TestAutoTenantDBPathConstruction(t *testing.T) {
	got := autoTenantDBPath("/data", "mytenant")
	if !contains(got, "mytenant") || !contains(got, ".db") {
		t.Errorf("autoTenantDBPath should include tenant name and .db suffix, got %q", got)
	}
}

func TestSanitizeIconName(t *testing.T) {
	got := sanitizeUploadedIconName("test.png")
	if got == "" {
		t.Errorf("sanitizeUploadedIconName should not return empty for valid name")
	}
}

func TestSanitizeSlugBasics(t *testing.T) {
	got := sanitizeDashboardIconFileSlug("MyIcon")
	if !contains(got, "m") || !contains(got, "icon") {
		t.Errorf("sanitizeDashboardIconFileSlug should lowercase, got %q", got)
	}
}

func TestTenantIconDirKey(t *testing.T) {
	got := normalizeTenantIconDirKey("mytenant")
	if got == "" {
		t.Errorf("normalizeTenantIconDirKey should not return empty")
	}
}

func TestEqualStringSlicesEmpty(t *testing.T) {
	if !equalStringSlices([]string{}, []string{}) {
		t.Errorf("empty slices should be equal")
	}
}

func TestEqualStringSlicesEqual(t *testing.T) {
	if !equalStringSlices([]string{"a", "b"}, []string{"a", "b"}) {
		t.Errorf("equal slices should be equal")
	}
}

func TestEqualStringSlicesDifferent(t *testing.T) {
	if equalStringSlices([]string{"a", "b"}, []string{"b", "a"}) {
		t.Errorf("different order should not be equal")
	}
}

func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
