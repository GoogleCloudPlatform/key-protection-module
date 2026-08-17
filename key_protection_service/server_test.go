package keyprotectionservice

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	kpspb "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestServerRunAndShutdown(t *testing.T) {
	// Let the OS pick an available port
	srv, err := newServerWithKPS(0, NewService(),
		keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM,
		keymanager.ServiceRole_SERVICE_ROLE_KPS,
	)
	if err != nil {
		t.Fatalf("Failed to create KPS server: %v", err)
	}

	// Verify the listener was created
	addr := srv.listener.Addr().(*net.TCPAddr)
	if addr.Port == 0 {
		t.Fatalf("Expected a non-zero port assigned, got %d", addr.Port)
	}

	errChan := make(chan error, 1)
	go func() {
		// Serve() returns nil upon GracefulStop()
		errChan <- srv.Serve()
	}()

	// Allow the server some time to start up
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Server shutdown failed: %v", err)
	}

	// Ensure Serve() returned without unexpected errors
	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("Serve() returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Serve() did not return in time after shutdown")
	}
}

func TestServerInvalidPort(t *testing.T) {
	// Try to start on a system/reserved port that we likely cannot bind to, or invalid port string
	// Passing an invalid port like -1 causes net.Listen to fail
	_, err := NewServer(-1, keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM,
		keymanager.ServiceRole_SERVICE_ROLE_KPS)
	if err == nil {
		t.Fatal("Expected NewServer() to return an error for invalid port -1")
	}
}

func TestServerGRPCRegistration(t *testing.T) {
	mock := &mockKPS{}

	srv, err := newServerWithKPS(0, mock,
		keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM,
		keymanager.ServiceRole_SERVICE_ROLE_KPS,
	)
	if err != nil {
		t.Fatalf("failed to create KPS server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Serve()
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Allow server to start up
	time.Sleep(100 * time.Millisecond)

	addr := srv.listener.Addr().String()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial grpc server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := kpspb.NewKeyProtectionServiceClient(conn)
	_, err = client.EnumerateKEMKeys(context.Background(), &kpspb.EnumerateKEMKeysRequest{Limit: 1, Offset: 0})
	if err != nil {
		t.Fatalf("gRPC call failed: %v", err)
	}
}

func TestServerRejectsInvalidKeyHandleUUID(t *testing.T) {
	var backendCalled atomic.Bool
	mock := &mockKPS{
		decapAndSealFn: func(_ context.Context, _ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
			backendCalled.Store(true)
			return nil, nil, nil
		},
		destroyKEMKeyFn: func(_ context.Context, _ uuid.UUID) error {
			backendCalled.Store(true)
			return nil
		},
		GetKEMKeyFn: func(_ context.Context, _ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
			backendCalled.Store(true)
			return nil, nil, nil, 0, nil
		},
	}

	srv, err := newServerWithKPS(0, mock,
		keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM,
		keymanager.ServiceRole_SERVICE_ROLE_KPS,
	)
	if err != nil {
		t.Fatalf("failed to create KPS server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Serve()
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	addr := srv.listener.Addr().String()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial grpc server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := kpspb.NewKeyProtectionServiceClient(conn)
	invalidHandle := &keymanager.KeyHandle{Handle: "not-a-uuid"}
	tests := []struct {
		name string
		call func(context.Context) error
	}{
		{
			name: "DecapAndSeal",
			call: func(ctx context.Context) error {
				_, err := client.DecapAndSeal(ctx, &kpspb.DecapAndSealRequest{KeyHandle: invalidHandle})
				return err
			},
		},
		{
			name: "DestroyKEMKey",
			call: func(ctx context.Context) error {
				_, err := client.DestroyKEMKey(ctx, &kpspb.DestroyKEMKeyRequest{KeyHandle: invalidHandle})
				return err
			},
		},
		{
			name: "GetKEMKey",
			call: func(ctx context.Context) error {
				_, err := client.GetKEMKey(ctx, &kpspb.GetKEMKeyRequest{KeyHandle: invalidHandle})
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backendCalled.Store(false)
			err := tc.call(t.Context())
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("expected InvalidArgument, got %v (err: %v)", status.Code(err), err)
			}
			if backendCalled.Load() {
				t.Fatal("backend was called for an invalid key handle")
			}
		})
	}
}

func TestServerHeartbeat(t *testing.T) {
	mock := &mockKPS{}

	srv, err := newServerWithKPS(0, mock,
		keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM,
		keymanager.ServiceRole_SERVICE_ROLE_KPS,
	)
	if err != nil {
		t.Fatalf("failed to create KPS server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Serve()
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Allow server to start up
	time.Sleep(100 * time.Millisecond)

	addr := srv.listener.Addr().String()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial grpc server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := kpspb.NewKeyProtectionServiceClient(conn)
	resp, err := client.Heartbeat(context.Background(), &kpspb.HeartbeatRequest{})
	if err != nil {
		t.Fatalf("gRPC Heartbeat call failed: %v", err)
	}

	if resp.KpsBootToken != srv.bootToken {
		t.Errorf("expected boot token %q, got %q", srv.bootToken, resp.KpsBootToken)
	}
}

func TestServerGetKeyClaims(t *testing.T) {
	kemUUID := uuid.New()
	expectedKemPubKey := []byte("kem-pub-key-bytes")
	expectedBindingPubKey := []byte("binding-pub-key-bytes")
	expectedAlgo := &keymanager.HpkeAlgorithm{
		Kem: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
	}
	expectedLifespan := uint64(3600)

	mock := &mockKPS{
		GetKEMKeyFn: func(_ context.Context, id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
			if id == kemUUID {
				return expectedKemPubKey, expectedBindingPubKey, expectedAlgo, expectedLifespan, nil
			}
			return nil, nil, nil, 0, keymanager.Status_STATUS_NOT_FOUND.ToStatus()
		},
	}

	srv, err := newServerWithKPS(0, mock,
		keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM,
		keymanager.ServiceRole_SERVICE_ROLE_KPS,
	)
	if err != nil {
		t.Fatalf("failed to create KPS server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Serve()
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Allow server to start up
	time.Sleep(100 * time.Millisecond)

	addr := srv.listener.Addr().String()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial grpc server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := keymanager.NewKeyClaimsServiceClient(conn)

	t.Run("Success", func(t *testing.T) {
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}

		res, err := client.GetKeyClaims(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		vmClaims := res.GetVmKeyClaims()
		if vmClaims == nil {
			t.Fatal("expected VmKeyClaims to be populated")
		}

		if string(vmClaims.GetKemPubKey().GetPublicKey()) != string(expectedKemPubKey) {
			t.Errorf("expected kem pub key %s, got %s", expectedKemPubKey, vmClaims.GetKemPubKey().GetPublicKey())
		}
		if string(vmClaims.GetBindingPubKey().GetPublicKey()) != string(expectedBindingPubKey) {
			t.Errorf("expected binding pub key %s, got %s", expectedBindingPubKey, vmClaims.GetBindingPubKey().GetPublicKey())
		}
		if vmClaims.GetKemPubKey().GetAlgorithm() != expectedAlgo.GetKem() {
			t.Errorf("expected kem algorithm %v, got %v", expectedAlgo.GetKem(), vmClaims.GetKemPubKey().GetAlgorithm())
		}
		if vmClaims.GetExpirationTime() <= float64(time.Now().Unix()) {
			t.Errorf("expected expiration time in the future, got %f", vmClaims.GetExpirationTime())
		}
	})

	t.Run("UnsupportedKeyType", func(t *testing.T) {
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
		}

		_, err := client.GetKeyClaims(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument code, got %v", err)
		}
	})

	t.Run("InvalidKeyHandle", func(t *testing.T) {
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: "invalid-uuid"},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}

		_, err := client.GetKeyClaims(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument code, got %v", err)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: uuid.New().String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}

		_, err := client.GetKeyClaims(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.NotFound {
			t.Fatalf("expected NotFound code, got %v", err)
		}
	})

	t.Run("WrongMode", func(t *testing.T) {
		srv.mode = keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED
		defer func() { srv.mode = keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM }()

		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}

		_, err := client.GetKeyClaims(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied code, got %v", err)
		}
	})

	t.Run("WrongModeInvalidKeyHandle", func(t *testing.T) {
		srv.mode = keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED
		defer func() { srv.mode = keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM }()

		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: "invalid-uuid"},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}

		_, err := client.GetKeyClaims(context.Background(), req)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied code, got %v", err)
		}
	})

	t.Run("WrongRole", func(t *testing.T) {
		srv.role = keymanager.ServiceRole_SERVICE_ROLE_WSD
		defer func() { srv.role = keymanager.ServiceRole_SERVICE_ROLE_KPS }()

		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}

		_, err := client.GetKeyClaims(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied code, got %v", err)
		}
	})

	t.Run("WrongRoleInvalidKeyHandle", func(t *testing.T) {
		srv.role = keymanager.ServiceRole_SERVICE_ROLE_WSD
		defer func() { srv.role = keymanager.ServiceRole_SERVICE_ROLE_KPS }()

		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: "invalid-uuid"},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}

		_, err := client.GetKeyClaims(context.Background(), req)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied code, got %v", err)
		}
	})
}
