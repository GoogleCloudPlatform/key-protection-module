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
	mock := &mockKPS{
		generateKEMKeypairFn: func(_ context.Context, _ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
			return id, pubKey, nil
		},
	}
	server := &grpcServer{svc: mock}

	req := &kpspb.GenerateKEMKeypairRequest{
		Algo:          &keymanager.HpkeAlgorithm{Kem: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256},
		BindingPubKey: &keymanager.HpkePublicKey{PublicKey: []byte("binding")},
		LifespanSecs:  3600,
	}

	resp, err := server.GenerateKEMKeypair(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.KeyHandle.GetHandle() != id.String() {
		t.Errorf("expected id %s, got %s", id.String(), resp.KeyHandle.GetHandle())
	}
	if resp.KemPubKey.GetAlgorithm() != req.Algo.GetKem() {
		t.Errorf("expected alg %v, got %v", req.Algo.GetKem(), resp.KemPubKey.GetAlgorithm())
	}

	// Error case
	mock.generateKEMKeypairFn = func(_ context.Context, _ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
		return uuid.Nil, nil, keymanager.Status_STATUS_INVALID_ARGUMENT.ToStatus()
	}
	_, err = server.GenerateKEMKeypair(context.Background(), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected code InvalidArgument, got %v", status.Code(err))
	}
}

func TestDecapAndSeal(t *testing.T) {
	id := uuid.New()
	mock := &mockKPS{
		decapAndSealFn: func(_ context.Context, _ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
			return []byte("seal-enc"), []byte("sealed-ct"), nil
		},
	}
	server := &grpcServer{svc: mock}

	req := &kpspb.DecapAndSealRequest{
		KeyHandle:  &keymanager.KeyHandle{Handle: id.String()},
		Ciphertext: &keymanager.KemCiphertext{Ciphertext: []byte("ct")},
		Aad:        []byte("aad"),
	}

	resp, err := server.DecapAndSeal(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.SealEnc) != "seal-enc" {
		t.Errorf("expected seal-enc, got %s", resp.SealEnc)
	}

	// Invalid UUID
	req.KeyHandle.Handle = "invalid"
	_, err = server.DecapAndSeal(context.Background(), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected code InvalidArgument, got %v", status.Code(err))
	}

	// SVC Error case
	req.KeyHandle.Handle = id.String()
	mock.decapAndSealFn = func(_ context.Context, _ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
		return nil, nil, keymanager.Status_STATUS_NOT_FOUND.ToStatus()
	}
	_, err = server.DecapAndSeal(context.Background(), req)
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected code NotFound, got %v", status.Code(err))
	}
}

func TestEnumerateKEMKeys(t *testing.T) {
	id := uuid.New()
	mock := &mockKPS{
		enumerateKEMKeysFn: func(_ context.Context, _, _ int) ([]kpskcc.KEMKeyInfo, bool, error) {
			return []kpskcc.KEMKeyInfo{
				{
					ID:                    id,
					Algorithm:             &keymanager.HpkeAlgorithm{Kem: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256},
					KEMPubKey:             []byte("pub"),
					RemainingLifespanSecs: 100,
				},
			}, true, nil
		},
	}
	server := &grpcServer{svc: mock}

	req := &kpspb.EnumerateKEMKeysRequest{
		Limit:  10,
		Offset: 0,
	}

	resp, err := server.EnumerateKEMKeys(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.HasMore {
		t.Errorf("expected HasMore true")
	}
	if len(resp.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(resp.Keys))
	}
	if resp.Keys[0].KeyHandle.GetHandle() != id.String() {
		t.Errorf("expected id %s, got %s", id.String(), resp.Keys[0].KeyHandle.GetHandle())
	}

	// SVC Error case
	mock.enumerateKEMKeysFn = func(_ context.Context, _, _ int) ([]kpskcc.KEMKeyInfo, bool, error) {
		return nil, false, keymanager.Status_STATUS_PERMISSION_DENIED.ToStatus()
	}
	_, err = server.EnumerateKEMKeys(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("expected code PermissionDenied, got %v", status.Code(err))
	}
}

func TestDestroyKEMKey(t *testing.T) {
	id := uuid.New()
	mock := &mockKPS{
		destroyKEMKeyFn: func(_ context.Context, _ uuid.UUID) error {
			return nil
		},
	}
	server := &grpcServer{svc: mock}

	req := &kpspb.DestroyKEMKeyRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: id.String()},
	}

	_, err := server.DestroyKEMKey(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Invalid UUID
	req.KeyHandle.Handle = "invalid"
	_, err = server.DestroyKEMKey(context.Background(), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected code InvalidArgument, got %v", status.Code(err))
	}

	// SVC Error case
	req.KeyHandle.Handle = id.String()
	mock.destroyKEMKeyFn = func(_ context.Context, _ uuid.UUID) error {
		return keymanager.Status_STATUS_NOT_FOUND.ToStatus()
	}
	_, err = server.DestroyKEMKey(context.Background(), req)
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected code NotFound, got %v", status.Code(err))
	}
}

func TestGetKEMKey(t *testing.T) {
	id := uuid.New()
	mock := &mockKPS{
		GetKEMKeyFn: func(_ context.Context, _ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
			return []byte("kem-pub"), []byte("binding-pub"), &keymanager.HpkeAlgorithm{Kem: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256}, 100, nil
		},
	}
	server := &grpcServer{svc: mock}

	req := &kpspb.GetKEMKeyRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: id.String()},
	}

	resp, err := server.GetKEMKey(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.KemPubKey.PublicKey) != "kem-pub" {
		t.Errorf("expected kem-pub, got %s", resp.KemPubKey.PublicKey)
	}

	// Invalid UUID
	req.KeyHandle.Handle = "invalid"
	_, err = server.GetKEMKey(context.Background(), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected code InvalidArgument, got %v", status.Code(err))
	}

	// SVC Error case
	req.KeyHandle.Handle = id.String()
	mock.GetKEMKeyFn = func(_ context.Context, _ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
		return nil, nil, nil, 0, keymanager.Status_STATUS_NOT_FOUND.ToStatus()
	}
	_, err = server.GetKEMKey(context.Background(), req)
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected code NotFound, got %v", status.Code(err))
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
