package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const testCorrelationID = "4bf92f3577b34da6a3ce929d0e0e4736"

func TestCorrelationIDValidation(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want bool
	}{
		{id: testCorrelationID, want: true},
		{id: "", want: false},
		{id: "00000000000000000000000000000000", want: false},
		{id: "4BF92F3577B34DA6A3CE929D0E0E4736", want: false},
		{id: "4bf92f35", want: false},
		{id: "4bf92f3577b34da6a3ce929d0e0e473x", want: false},
	} {
		if got := IsValidCorrelationID(tc.id); got != tc.want {
			t.Errorf("IsValidCorrelationID(%q) = %t, want %t", tc.id, got, tc.want)
		}
	}

	if got := NewCorrelationID(); !IsValidCorrelationID(got) {
		t.Fatalf("NewCorrelationID() = %q, want a valid ID", got)
	}
}

func TestCorrelateHTTPPreservesValidID(t *testing.T) {
	var logOutput bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logOutput, nil)))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })

	var handlerID string
	handler := CorrelateHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerID = CorrelationID(r.Context())
		http.Error(w, "failed", http.StatusInternalServerError)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", nil)
	req.Header.Set(CorrelationIDHeader, testCorrelationID)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if handlerID != testCorrelationID {
		t.Fatalf("handler correlation ID = %q, want %q", handlerID, testCorrelationID)
	}
	if got := recorder.Header().Get(CorrelationIDHeader); got != testCorrelationID {
		t.Fatalf("response correlation ID = %q, want %q", got, testCorrelationID)
	}
	if got := logOutput.String(); !strings.Contains(got, `"correlation_id":"`+testCorrelationID+`"`) {
		t.Fatalf("failure log is missing correlation ID: %s", got)
	}
}

func TestCorrelateHTTPDoesNotLogClientErrors(t *testing.T) {
	var logOutput bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logOutput, nil)))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })

	handler := CorrelateHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))

	if logOutput.Len() != 0 {
		t.Fatalf("client error generated a log: %s", logOutput.String())
	}
}

func TestCorrelationUnaryServerInterceptorPropagatesID(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		CorrelationIDMetadataKey, testCorrelationID,
	))
	var handlerID string

	_, err := CorrelationUnaryServerInterceptor(
		ctx,
		struct{}{},
		&grpc.UnaryServerInfo{FullMethod: "/test.Service/Call"},
		func(ctx context.Context, _ interface{}) (interface{}, error) {
			handlerID = CorrelationID(ctx)
			return nil, status.Error(codes.Internal, "failed")
		},
	)

	if status.Code(err) != codes.Internal {
		t.Fatalf("interceptor error = %v, want Internal", err)
	}
	if handlerID != testCorrelationID {
		t.Fatalf("handler correlation ID = %q, want %q", handlerID, testCorrelationID)
	}
}

func TestWithOutgoingCorrelationID(t *testing.T) {
	ctx := WithOutgoingCorrelationID(WithCorrelationID(context.Background(), testCorrelationID))
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("outgoing metadata is missing")
	}
	if got := md.Get(CorrelationIDMetadataKey); len(got) != 1 || got[0] != testCorrelationID {
		t.Fatalf("outgoing correlation ID = %v, want %q", got, testCorrelationID)
	}
}
