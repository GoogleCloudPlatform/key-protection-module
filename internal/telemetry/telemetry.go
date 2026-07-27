// Package telemetry provides structured logging utilities for KPM.
package telemetry

import (
	"log/slog"
	"os"
	"strings"
)

// InitLogger initializes and sets the default slog logger to output structured JSON to stdout.
func InitLogger(serviceName string) {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(os.Getenv("LOG_LEVEL")),
	}).WithAttrs([]slog.Attr{
		slog.String("service.name", serviceName),
	})
	slog.SetDefault(slog.New(handler))
}

func parseLogLevel(levelStr string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
