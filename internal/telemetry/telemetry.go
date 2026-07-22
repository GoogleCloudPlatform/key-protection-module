// Package telemetry provides OpenTelemetry instrumentation for WSD.
package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

type teeHandler struct {
	h1, h2 slog.Handler
}

func (t *teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return t.h1.Enabled(ctx, level) || t.h2.Enabled(ctx, level)
}

func (t *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	if t.h1.Enabled(ctx, r.Level) {
		if err := t.h1.Handle(ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	if t.h2.Enabled(ctx, r.Level) {
		if err := t.h2.Handle(ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &teeHandler{
		h1: t.h1.WithAttrs(attrs),
		h2: t.h2.WithAttrs(attrs),
	}
}

func (t *teeHandler) WithGroup(name string) slog.Handler {
	return &teeHandler{
		h1: t.h1.WithGroup(name),
		h2: t.h2.WithGroup(name),
	}
}

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

	// Bind slog to OpenTelemetry and combine it with the default stdout JSON logger
	otelHandler := otelslog.NewHandler(serviceName)
	stdoutHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(&teeHandler{h1: stdoutHandler, h2: otelHandler}))

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
