package keyprotectionservice

import (
	"errors"
	"fmt"
	"testing"

	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"google.golang.org/grpc/codes"
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
