package app

import (
	"testing"
)

func TestParseLogLevelFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int // slog.Level
	}{
		{"debug", "debug", -4}, // slog.LevelDebug
		{"info", "info", 0},    // slog.LevelInfo
		{"warn", "warn", 4},    // slog.LevelWarn
		{"error", "error", 8},  // slog.LevelError
		{"unknown defaults to info", "unknown", 0},
		{"empty defaults to info", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLogLevel(tt.input)
			if int(got) != tt.expected {
				t.Errorf("parseLogLevel(%q) = %d, want %d", tt.input, int(got), tt.expected)
			}
		})
	}
}
