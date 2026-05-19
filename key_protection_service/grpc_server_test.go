package keyprotectionservice

import (
	"context"
	"errors"
	"fmt"
	"testing"

	kpskcc "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/key_custody_core"
	kpspb "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/uuid"
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

func TestNewGrpcServer(t *testing.T) {
	mock := &mockKPS{}
	srv := NewGrpcServer(mock, "test-boot-token")
	if srv == nil {
		t.Fatal("expected server, got nil")
	}
}

func TestGenerateKEMKeypair(t *testing.T) {
	id := uuid.New()
	pubKey := []byte("pub-key")

	tests := []struct {
		name                 string
		req                  *kpspb.GenerateKEMKeypairRequest
		generateKEMKeypairFn func(ctx context.Context, algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
		wantCode             codes.Code
		wantHandle           string
		wantKemAlgo          keymanager.KemAlgorithm
	}{
		{
			name: "success",
			req: &kpspb.GenerateKEMKeypairRequest{
				Algo:          &keymanager.HpkeAlgorithm{Kem: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256},
				BindingPubKey: &keymanager.HpkePublicKey{PublicKey: []byte("binding")},
				LifespanSecs:  3600,
			},
			generateKEMKeypairFn: func(_ context.Context, _ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
				return id, pubKey, nil
			},
			wantCode:    codes.OK,
			wantHandle:  id.String(),
			wantKemAlgo: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
		},
		{
			name: "svc error",
			req: &kpspb.GenerateKEMKeypairRequest{
				Algo:          &keymanager.HpkeAlgorithm{Kem: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256},
				BindingPubKey: &keymanager.HpkePublicKey{PublicKey: []byte("binding")},
				LifespanSecs:  3600,
			},
			generateKEMKeypairFn: func(_ context.Context, _ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
				return uuid.Nil, nil, keymanager.Status_STATUS_INVALID_ARGUMENT.ToStatus()
			},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockKPS{
				generateKEMKeypairFn: tc.generateKEMKeypairFn,
			}
			server := &grpcServer{svc: mock}

			resp, err := server.GenerateKEMKeypair(context.Background(), tc.req)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("expected code %v, got %v (err: %v)", tc.wantCode, status.Code(err), err)
			}

			if err == nil {
				if resp.KeyHandle.GetHandle() != tc.wantHandle {
					t.Errorf("expected id %s, got %s", tc.wantHandle, resp.KeyHandle.GetHandle())
				}
				if resp.KemPubKey.GetAlgorithm() != tc.wantKemAlgo {
					t.Errorf("expected alg %v, got %v", tc.wantKemAlgo, resp.KemPubKey.GetAlgorithm())
				}
			}
		})
	}
}

func TestDecapAndSeal(t *testing.T) {
	id := uuid.New()

	tests := []struct {
		name           string
		req            *kpspb.DecapAndSealRequest
		decapAndSealFn func(ctx context.Context, id uuid.UUID, ct, aad []byte) ([]byte, []byte, error)
		wantCode       codes.Code
		wantSealEnc    string
	}{
		{
			name: "success",
			req: &kpspb.DecapAndSealRequest{
				KeyHandle:  &keymanager.KeyHandle{Handle: id.String()},
				Ciphertext: &keymanager.KemCiphertext{Ciphertext: []byte("ct")},
				Aad:        []byte("aad"),
			},
			decapAndSealFn: func(_ context.Context, _ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
				return []byte("seal-enc"), []byte("sealed-ct"), nil
			},
			wantCode:    codes.OK,
			wantSealEnc: "seal-enc",
		},
		{
			name: "invalid uuid",
			req: &kpspb.DecapAndSealRequest{
				KeyHandle:  &keymanager.KeyHandle{Handle: "invalid"},
				Ciphertext: &keymanager.KemCiphertext{Ciphertext: []byte("ct")},
				Aad:        []byte("aad"),
			},
			decapAndSealFn: func(_ context.Context, _ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
				return nil, nil, nil
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "svc error",
			req: &kpspb.DecapAndSealRequest{
				KeyHandle:  &keymanager.KeyHandle{Handle: id.String()},
				Ciphertext: &keymanager.KemCiphertext{Ciphertext: []byte("ct")},
				Aad:        []byte("aad"),
			},
			decapAndSealFn: func(_ context.Context, _ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
				return nil, nil, keymanager.Status_STATUS_NOT_FOUND.ToStatus()
			},
			wantCode: codes.NotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockKPS{
				decapAndSealFn: tc.decapAndSealFn,
			}
			server := &grpcServer{svc: mock}

			resp, err := server.DecapAndSeal(context.Background(), tc.req)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("expected code %v, got %v (err: %v)", tc.wantCode, status.Code(err), err)
			}
			if err == nil && string(resp.SealEnc) != tc.wantSealEnc {
				t.Errorf("expected seal-enc %s, got %s", tc.wantSealEnc, resp.SealEnc)
			}
		})
	}
}

func TestEnumerateKEMKeys(t *testing.T) {
	id := uuid.New()

	tests := []struct {
		name               string
		req                *kpspb.EnumerateKEMKeysRequest
		enumerateKEMKeysFn func(ctx context.Context, limit, offset int32) ([]kpskcc.KEMKeyInfo, bool, error)
		wantCode           codes.Code
		wantHasMore        bool
		wantCount          int
		wantHandle         string
	}{
		{
			name: "success",
			req: &kpspb.EnumerateKEMKeysRequest{
				Limit:  10,
				Offset: 0,
			},
			enumerateKEMKeysFn: func(_ context.Context, _, _ int32) ([]kpskcc.KEMKeyInfo, bool, error) {
				return []kpskcc.KEMKeyInfo{
					{
						ID:                    id,
						Algorithm:             &keymanager.HpkeAlgorithm{Kem: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256},
						KEMPubKey:             []byte("pub"),
						RemainingLifespanSecs: 100,
					},
				}, true, nil
			},
			wantCode:    codes.OK,
			wantHasMore: true,
			wantCount:   1,
			wantHandle:  id.String(),
		},
		{
			name: "svc error",
			req: &kpspb.EnumerateKEMKeysRequest{
				Limit:  10,
				Offset: 0,
			},
			enumerateKEMKeysFn: func(_ context.Context, _, _ int32) ([]kpskcc.KEMKeyInfo, bool, error) {
				return nil, false, keymanager.Status_STATUS_PERMISSION_DENIED.ToStatus()
			},
			wantCode: codes.PermissionDenied,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockKPS{
				enumerateKEMKeysFn: tc.enumerateKEMKeysFn,
			}
			server := &grpcServer{svc: mock}

			resp, err := server.EnumerateKEMKeys(context.Background(), tc.req)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("expected code %v, got %v (err: %v)", tc.wantCode, status.Code(err), err)
			}
			if err == nil {
				if resp.HasMore != tc.wantHasMore {
					t.Errorf("expected HasMore %v, got %v", tc.wantHasMore, resp.HasMore)
				}
				if len(resp.Keys) != tc.wantCount {
					t.Fatalf("expected %d keys, got %d", tc.wantCount, len(resp.Keys))
				}
				if tc.wantCount > 0 && resp.Keys[0].KeyHandle.GetHandle() != tc.wantHandle {
					t.Errorf("expected id %s, got %s", tc.wantHandle, resp.Keys[0].KeyHandle.GetHandle())
				}
			}
		})
	}
}

func TestDestroyKEMKey(t *testing.T) {
	id := uuid.New()

	tests := []struct {
		name            string
		req             *kpspb.DestroyKEMKeyRequest
		destroyKEMKeyFn func(ctx context.Context, id uuid.UUID) error
		wantCode        codes.Code
	}{
		{
			name: "success",
			req: &kpspb.DestroyKEMKeyRequest{
				KeyHandle: &keymanager.KeyHandle{Handle: id.String()},
			},
			destroyKEMKeyFn: func(_ context.Context, _ uuid.UUID) error {
				return nil
			},
			wantCode: codes.OK,
		},
		{
			name: "invalid uuid",
			req: &kpspb.DestroyKEMKeyRequest{
				KeyHandle: &keymanager.KeyHandle{Handle: "invalid"},
			},
			destroyKEMKeyFn: func(_ context.Context, _ uuid.UUID) error {
				return nil
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "svc error",
			req: &kpspb.DestroyKEMKeyRequest{
				KeyHandle: &keymanager.KeyHandle{Handle: id.String()},
			},
			destroyKEMKeyFn: func(_ context.Context, _ uuid.UUID) error {
				return keymanager.Status_STATUS_NOT_FOUND.ToStatus()
			},
			wantCode: codes.NotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockKPS{
				destroyKEMKeyFn: tc.destroyKEMKeyFn,
			}
			server := &grpcServer{svc: mock}

			_, err := server.DestroyKEMKey(context.Background(), tc.req)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("expected code %v, got %v (err: %v)", tc.wantCode, status.Code(err), err)
			}
		})
	}
}

func TestGetKEMKey(t *testing.T) {
	id := uuid.New()

	tests := []struct {
		name        string
		req         *kpspb.GetKEMKeyRequest
		GetKEMKeyFn func(ctx context.Context, id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error)
		wantCode    codes.Code
		wantPubKey  string
	}{
		{
			name: "success",
			req: &kpspb.GetKEMKeyRequest{
				KeyHandle: &keymanager.KeyHandle{Handle: id.String()},
			},
			GetKEMKeyFn: func(_ context.Context, _ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
				return []byte("kem-pub"), []byte("binding-pub"), &keymanager.HpkeAlgorithm{Kem: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256}, 100, nil
			},
			wantCode:   codes.OK,
			wantPubKey: "kem-pub",
		},
		{
			name: "invalid uuid",
			req: &kpspb.GetKEMKeyRequest{
				KeyHandle: &keymanager.KeyHandle{Handle: "invalid"},
			},
			GetKEMKeyFn: func(_ context.Context, _ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
				return nil, nil, nil, 0, nil
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "svc error",
			req: &kpspb.GetKEMKeyRequest{
				KeyHandle: &keymanager.KeyHandle{Handle: id.String()},
			},
			GetKEMKeyFn: func(_ context.Context, _ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
				return nil, nil, nil, 0, keymanager.Status_STATUS_NOT_FOUND.ToStatus()
			},
			wantCode: codes.NotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockKPS{
				GetKEMKeyFn: tc.GetKEMKeyFn,
			}
			server := &grpcServer{svc: mock}

			resp, err := server.GetKEMKey(context.Background(), tc.req)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("expected code %v, got %v (err: %v)", tc.wantCode, status.Code(err), err)
			}
			if err == nil && string(resp.KemPubKey.PublicKey) != tc.wantPubKey {
				t.Errorf("expected %s, got %s", tc.wantPubKey, resp.KemPubKey.PublicKey)
			}
		})
	}
}

func TestHeartbeat(t *testing.T) {
	server := &grpcServer{bootToken: "test-token"}
	resp, err := server.Heartbeat(context.Background(), &kpspb.HeartbeatRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.KpsBootToken != "test-token" {
		t.Errorf("expected test-token, got %s", resp.KpsBootToken)
	}
}

func TestValidationInterceptor_NotProtoMessage(t *testing.T) {
	req := "not a proto message"
	_, err := ValidationInterceptor(context.Background(), req, &grpc.UnaryServerInfo{}, func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, nil
	})
	if status.Code(err) != codes.Internal {
		t.Errorf("expected Internal, got %v", status.Code(err))
	}
}
