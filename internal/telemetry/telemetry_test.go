package telemetry

import (
	"log/slog"
	"os"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected slog.Level
	}{
		{"debug lowercase", "debug", slog.LevelDebug},
		{"debug uppercase with spaces", "  DEBUG  ", slog.LevelDebug},
		{"warn lowercase", "warn", slog.LevelWarn},
		{"warning lowercase", "warning", slog.LevelWarn},
		{"error lowercase", "error", slog.LevelError},
		{"info lowercase", "info", slog.LevelInfo},
		{"empty string", "", slog.LevelInfo},
		{"unknown level", "verbose", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLogLevel(tt.input)
			if got != tt.expected {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestInitLogger(t *testing.T) {
	_ = os.Setenv("LOG_LEVEL", "debug")
	defer func() { _ = os.Unsetenv("LOG_LEVEL") }()

	InitLogger("test_service")
	logger := slog.Default()
	if !logger.Enabled(nil, slog.LevelDebug) {
		t.Errorf("expected default logger to be enabled for LevelDebug")
	}
}
