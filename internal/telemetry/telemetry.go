// Package telemetry provides OpenTelemetry instrumentation for WSD.
package telemetry

import (
	"context"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// Init initializes the OTLP Exporter and configures the default logger.
// Returns a shutdown function to flush pending telemetry data.
func Init(_ context.Context, _ string, serviceName string) (func(context.Context) error, error) {
	// Initialize OTLP Exporter here using the provided endpoint
	// 1. Setup Resource (service name, instance ID, etc.)
	// 2. Setup OTLP Trace Exporter and set global TracerProvider
	// 3. Setup OTLP Log Exporter and set global LoggerProvider (use BatchProcessors!)

	// Setup W3C Trace Context propagation
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
	))

	// Bind slog to OpenTelemetry
	// Consider a Tee handler here if you still want stdout logs
	handler := otelslog.NewHandler(serviceName)
	slog.SetDefault(slog.New(handler))

	// Return a shutdown function that calls Shutdown() on your TracerProvider and LoggerProvider
	return func(_ context.Context) error {
		// e.g., tracerProvider.Shutdown(shutdownCtx)
		// e.g., loggerProvider.Shutdown(shutdownCtx)
		return nil
	}, nil
}

// WrapHTTPHandler provides an instrumented HTTP handler.
func WrapHTTPHandler(handler http.Handler, name string) http.Handler {
	return otelhttp.NewHandler(handler, name)
}
