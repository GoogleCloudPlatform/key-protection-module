package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestTraceHandler_InjectsTraceAndSpanID(t *testing.T) {
	var buf bytes.Buffer
	jsonHandler := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(&traceHandler{Handler: jsonHandler})

	traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	logger.InfoContext(ctx, "test message", "foo", "bar")

	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to unmarshal JSON log output: %v\nRaw: %s", err, buf.String())
	}

	if logEntry["msg"] != "test message" {
		t.Errorf("Expected msg 'test message', got '%v'", logEntry["msg"])
	}
	if logEntry["foo"] != "bar" {
		t.Errorf("Expected foo 'bar', got '%v'", logEntry["foo"])
	}

	gotTraceID, ok := logEntry["trace_id"].(string)
	if !ok || gotTraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("Expected trace_id '4bf92f3577b34da6a3ce929d0e0e4736', got '%v'", logEntry["trace_id"])
	}

	gotSpanID, ok := logEntry["span_id"].(string)
	if !ok || gotSpanID != "00f067aa0ba902b7" {
		t.Errorf("Expected span_id '00f067aa0ba902b7', got '%v'", logEntry["span_id"])
	}
}

func TestTraceHandler_NoSpan(t *testing.T) {
	var buf bytes.Buffer
	jsonHandler := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(&traceHandler{Handler: jsonHandler})

	logger.InfoContext(context.Background(), "test without span")

	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to unmarshal JSON log output: %v\nRaw: %s", err, buf.String())
	}

	if _, exists := logEntry["trace_id"]; exists {
		t.Errorf("Did not expect trace_id when no span in context, got '%v'", logEntry["trace_id"])
	}
	if _, exists := logEntry["span_id"]; exists {
		t.Errorf("Did not expect span_id when no span in context, got '%v'", logEntry["span_id"])
	}
}

func TestInit(t *testing.T) {
	shutdown, err := Init(context.Background(), "localhost:4317", "TestService")
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("Expected non-nil shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown returned error: %v", err)
	}
}
