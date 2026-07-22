// Package telemetry provides OpenTelemetry instrumentation for WSD.
package telemetry

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// traceHandler wraps a slog.Handler to inject OpenTelemetry trace and span IDs.
type traceHandler struct {
	slog.Handler
}

// Handle adds trace_id and span_id to the log record if a valid span exists in the context.
func (t *traceHandler) Handle(ctx context.Context, r slog.Record) error {
	spanContext := trace.SpanFromContext(ctx).SpanContext()
	if spanContext.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", spanContext.TraceID().String()),
			slog.String("span_id", spanContext.SpanID().String()),
		)
	}
	return t.Handler.Handle(ctx, r)
}

// Init initializes the OTLP Exporter and configures the default logger.
// Returns a shutdown function to flush pending telemetry data.
func Init(_ context.Context, _ string, _ string) (func(context.Context) error, error) {
	// Initialize OTLP Exporter here using the provided endpoint
	// 1. Setup Resource (service name, instance ID, etc.)
	// 2. Setup OTLP Trace Exporter and set global TracerProvider

	// Setup W3C Trace Context propagation
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
	))

	// Configure slog to output structured JSON to standard output with trace context
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	slog.SetDefault(slog.New(&traceHandler{Handler: jsonHandler}))

	// Return a shutdown function that calls Shutdown() on your TracerProvider
	return func(_ context.Context) error {
		// e.g., tracerProvider.Shutdown(shutdownCtx)
		return nil
	}, nil
}

// WrapHTTPHandler provides an instrumented HTTP handler.
func WrapHTTPHandler(handler http.Handler, name string) http.Handler {
	return otelhttp.NewHandler(handler, name)
}
