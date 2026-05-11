package keyprotectionservice

import (
	"context"
	"errors"
	"fmt"
	"testing"

	kpspb "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGrpcCodeFromError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"not_found", keymanager.Status_STATUS_NOT_FOUND.ToStatus(), codes.NotFound},
		{"invalid_argument", keymanager.Status_STATUS_INVALID_ARGUMENT.ToStatus(), codes.InvalidArgument},
		{"unsupported_algorithm", keymanager.Status_STATUS_UNSUPPORTED_ALGORITHM.ToStatus(), codes.InvalidArgument},
		{"invalid_key", keymanager.Status_STATUS_INVALID_KEY.ToStatus(), codes.InvalidArgument},
		{"permission_denied", keymanager.Status_STATUS_PERMISSION_DENIED.ToStatus(), codes.PermissionDenied},
		{"unauthenticated", keymanager.Status_STATUS_UNAUTHENTICATED.ToStatus(), codes.Unauthenticated},
		{"already_exists", keymanager.Status_STATUS_ALREADY_EXISTS.ToStatus(), codes.AlreadyExists},
		{"crypto_error", keymanager.Status_STATUS_CRYPTO_ERROR.ToStatus(), codes.Internal},
		{"plain_error", errors.New("boom"), codes.Internal},
		{"wrapped_not_found", fmt.Errorf("context: %w", keymanager.Status_STATUS_NOT_FOUND.ToStatus()), codes.NotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := grpcCodeFromError(tc.err); got != tc.want {
				t.Errorf("grpcCodeFromError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func testValidation(t *testing.T, req interface{}, handler grpc.UnaryHandler) {
	t.Helper()
	_, err := ValidationInterceptor(context.Background(), req, &grpc.UnaryServerInfo{}, handler)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected code InvalidArgument, got %v", st.Code())
	}
}

func TestDecapAndSealValidation(t *testing.T) {
	server := &grpcServer{
		svc: &mockKPS{},
	}

	req := &kpspb.DecapAndSealRequest{}

	testValidation(t, req, func(ctx context.Context, r interface{}) (interface{}, error) {
		return server.DecapAndSeal(ctx, r.(*kpspb.DecapAndSealRequest))
	})
}

func TestDestroyKEMKeyValidation(t *testing.T) {
	server := &grpcServer{
		svc: &mockKPS{},
	}

	req := &kpspb.DestroyKEMKeyRequest{}

	testValidation(t, req, func(ctx context.Context, r interface{}) (interface{}, error) {
		return server.DestroyKEMKey(ctx, r.(*kpspb.DestroyKEMKeyRequest))
	})
}

func TestGetKEMKeyValidation(t *testing.T) {
	server := &grpcServer{
		svc: &mockKPS{},
	}

	req := &kpspb.GetKEMKeyRequest{}

	testValidation(t, req, func(ctx context.Context, r interface{}) (interface{}, error) {
		return server.GetKEMKey(ctx, r.(*kpspb.GetKEMKeyRequest))
	})
}
