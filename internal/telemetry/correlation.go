// Package telemetry provides request correlation helpers for KPM logs.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// CorrelationIDHeader is the HTTP header used to accept and return a request correlation ID.
	CorrelationIDHeader = "X-KPM-Correlation-ID"
	// CorrelationIDMetadataKey carries the correlation ID between WSD and KPS over gRPC.
	CorrelationIDMetadataKey = "x-kpm-correlation-id"
	correlationIDLength      = 32
)

type correlationIDKey struct{}

var fallbackIDCounter atomic.Uint64

// NewCorrelationID returns a bounded, lowercase 128-bit identifier.
func NewCorrelationID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		binary.BigEndian.PutUint64(id[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(id[8:], fallbackIDCounter.Add(1))
	}
	if id == [16]byte{} {
		id[15] = 1
	}
	return hex.EncodeToString(id[:])
}

// IsValidCorrelationID reports whether id is the bounded format accepted across KPM.
func IsValidCorrelationID(id string) bool {
	if len(id) != correlationIDLength {
		return false
	}
	nonZero := false
	for _, c := range id {
		if c >= '1' && c <= '9' {
			nonZero = true
			continue
		}
		if c == '0' {
			continue
		}
		if c >= 'a' && c <= 'f' {
			nonZero = true
			continue
		}
		return false
	}
	return nonZero
}

// WithCorrelationID returns a child context carrying id. Invalid IDs are ignored.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if !IsValidCorrelationID(id) {
		return ctx
	}
	return context.WithValue(ctx, correlationIDKey{}, id)
}

// CorrelationID returns the correlation ID stored in ctx, or an empty string.
func CorrelationID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(correlationIDKey{}).(string)
	if !IsValidCorrelationID(id) {
		return ""
	}
	return id
}

// EnsureCorrelationID preserves a valid ID in ctx or adds a new one.
func EnsureCorrelationID(ctx context.Context) context.Context {
	if id := CorrelationID(ctx); id != "" {
		return ctx
	}
	return WithCorrelationID(ctx, NewCorrelationID())
}

// Logger returns the default logger enriched with the context's correlation ID.
func Logger(ctx context.Context) *slog.Logger {
	if id := CorrelationID(ctx); id != "" {
		return slog.Default().With("correlation_id", id)
	}
	return slog.Default()
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.statusCode != 0 {
		return
	}
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if r.statusCode == 0 {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(body)
}

// CorrelateHTTP assigns one ID to the request, response, Go failure log, and KCC calls.
func CorrelateHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(CorrelationIDHeader)
		if !IsValidCorrelationID(id) {
			id = NewCorrelationID()
		}
		ctx := WithCorrelationID(r.Context(), id)
		w.Header().Set(CorrelationIDHeader, id)

		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r.WithContext(ctx))
		if recorder.statusCode >= http.StatusInternalServerError {
			Logger(ctx).LogAttrs(ctx, slog.LevelError, "request failed",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", recorder.statusCode),
			)
		}
	})
}

// WithOutgoingCorrelationID adds ctx's ID to outgoing WSD-to-KPS gRPC metadata.
func WithOutgoingCorrelationID(ctx context.Context) context.Context {
	id := CorrelationID(ctx)
	if id == "" {
		return ctx
	}
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set(CorrelationIDMetadataKey, id)
	return metadata.NewOutgoingContext(ctx, md)
}

// CorrelationUnaryServerInterceptor restores or generates an ID and logs server-side RPC failures.
func CorrelationUnaryServerInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	id := CorrelationID(ctx)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for _, candidate := range md.Get(CorrelationIDMetadataKey) {
			if IsValidCorrelationID(candidate) {
				id = candidate
				break
			}
		}
	}
	if id == "" {
		id = NewCorrelationID()
	}
	ctx = WithCorrelationID(ctx, id)

	resp, err := handler(ctx, req)
	if err != nil {
		code := status.Code(err)
		switch code {
		case codes.Internal, codes.Unknown, codes.DataLoss, codes.Unavailable:
			Logger(ctx).LogAttrs(ctx, slog.LevelError, "RPC failed",
				slog.String("method", info.FullMethod),
				slog.String("code", code.String()),
			)
		}
	}
	return resp, err
}
