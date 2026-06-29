// Package workloadservice implements the Key Orchestration Layer (KOL) for the
// Workload Service Daemon (WSD). It provides an HTTP server on a unix socket
// exposing key management endpoints.
package workloadservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"

	"google.golang.org/protobuf/encoding/protojson"

	api "github.com/GoogleCloudPlatform/key-protection-module/workload_service/proto"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/types/known/durationpb"

	kpskcc "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/key_custody_core"
	kpspb "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	wskcc "github.com/GoogleCloudPlatform/key-protection-module/workload_service/key_custody_core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	defaultKpsPort        = 50050
	heartbeatInterval     = 30 * time.Second
	heartbeatTimeout      = 5 * time.Second
	defaultInitialBackoff = 1 * time.Second
	defaultMaxBackoff     = 128 * time.Second
	// math.MaxInt64 nanoseconds is approx 292 years or 9223372036 seconds.
	maxDurationSeconds = math.MaxInt64 / int64(time.Second)
)

// WorkloadService defines the interface for generating and managing binding keypairs.
// These keypairs are used by workloads to securely bind shared secrets to their identity.
type WorkloadService interface {
	// GenerateBindingKeypair generates a new binding keypair for a workload.
	// This keypair ensures that only the workload possessing the private key
	// can open (decrypt) sealed secrets intended for it.
	//
	// Parameters:
	//   - algo: The HPKE algorithm suite to use for the binding keypair.
	//   - lifespanSecs: The duration (in seconds) for which the generated keypair remains valid.
	//
	// Returns:
	//   - uuid.UUID: A unique identifier representing the stored binding keypair.
	//   - []byte: The public binding key bytes to be shared with the Key Protection Service.
	//   - error: An error if generation or storage fails.
	GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error)

	// DestroyBindingKey removes the specified binding keypair from the active key registry.
	// It ensures that the keypair can no longer be used to decrypt (open) sealed secrets.
	//
	// Parameters:
	//   - bindingUUID: The unique identifier of the stored binding keypair to destroy.
	//
	// Returns:
	//   - error: An error if the key is not found or deletion fails.
	DestroyBindingKey(bindingUUID uuid.UUID) error

	// GetBindingKey retrieves metadata and public keys associated with a stored binding keypair.
	//
	// Parameters:
	//   - id: The unique identifier of the stored binding keypair.
	//
	// Returns:
	//   - []byte: The public binding key bytes.
	//   - *keymanager.HpkeAlgorithm: The HPKE algorithm suite of the binding key.
	//   - error: An error if the key is not found or has expired.
	GetBindingKey(id uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error)

	// Open decrypts a sealed ciphertext using the specified binding private key.
	// It is used by the workload to access shared secrets that have been resealed
	// for its specific binding key.
	//
	// Parameters:
	//   - bindingUUID: The unique identifier of the stored binding keypair.
	//   - enc: The encapsulated key for the resealed shared secret (seal_enc).
	//   - ciphertext: The authenticated ciphertext of the resealed shared secret (sealed_ct).
	//   - aad: Additional Authenticated Data used during the sealing process.
	//
	// Returns:
	//   - []byte: The original plaintext (the shared secret).
	//   - error: An error if the binding key is not found, expired, or decryption fails.
	Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error)

	// DestroyAllKeys removes all binding keypairs from the active key registry.
	//
	// Returns:
	//   - error: An error if deletion fails.
	DestroyAllKeys() error
}
type keyProtectionService struct{}

// KeyProtectionService defines the interface for generating KEM keypairs.
type KeyProtectionService interface {
	GenerateKEMKeypair(ctx context.Context, algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	EnumerateKEMKeys(ctx context.Context, limit, offset int32) ([]kpskcc.KEMKeyInfo, bool, error)
	DestroyKEMKey(ctx context.Context, kemUUID uuid.UUID) error
	GetKEMKey(ctx context.Context, id uuid.UUID) (kemPubKey []byte, bindingPubKey []byte, algo *keymanager.HpkeAlgorithm, deleteAfter uint64, err error)
	DecapAndSeal(ctx context.Context, kemUUID uuid.UUID, encapsulatedKey, aad []byte) (sealEnc []byte, sealedCT []byte, err error)
}

// workloadService implements WorkloadService by delegating to the WSD KCC FFI.
type workloadService struct{}

// GenerateBindingKeypair generates a new binding keypair for the workload by
// delegating to the underlying WorkloadService backend (WSD KCC FFI).
func (r *workloadService) GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

// DestroyBindingKey removes the specified binding keypair from the active key registry
// by delegating to the underlying WorkloadService backend (WSD KCC FFI).
func (r *workloadService) DestroyBindingKey(bindingUUID uuid.UUID) error {
	return wskcc.DestroyBindingKey(bindingUUID)
}

// Open decrypts a sealed ciphertext securely using the specified binding private key
// by delegating to the underlying WorkloadService backend (WSD KCC FFI).
func (r *workloadService) Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	return wskcc.Open(bindingUUID, enc, ciphertext, aad)
}

// GetBindingKey retrieves the public binding key and HPKE algorithm of a stored
// binding keypair by delegating to the underlying WorkloadService backend (WSD KCC FFI).
func (r *workloadService) GetBindingKey(id uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error) {
	return wskcc.GetBindingKey(id)
}

// DestroyAllKeys destroys all binding keys managed by the service by calling wskcc.
func (r *workloadService) DestroyAllKeys() error {
	return wskcc.DestroyAllKeys()
}

func (r *keyProtectionService) GenerateKEMKeypair(_ context.Context, algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return kpskcc.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

func (r *keyProtectionService) EnumerateKEMKeys(_ context.Context, limit, offset int32) ([]kpskcc.KEMKeyInfo, bool, error) {
	return kpskcc.EnumerateKEMKeys(limit, offset)
}

func (r *keyProtectionService) DestroyKEMKey(_ context.Context, kemUUID uuid.UUID) error {
	return kpskcc.DestroyKEMKey(kemUUID)
}

func (r *keyProtectionService) DecapAndSeal(_ context.Context, kemUUID uuid.UUID, encapsulatedKey, aad []byte) (sealEnc []byte, sealedCT []byte, err error) {
	return kpskcc.DecapAndSeal(kemUUID, encapsulatedKey, aad)
}

func (r *keyProtectionService) GetKEMKey(_ context.Context, id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return kpskcc.GetKEMKey(id)
}

type remoteKeyProtectionService struct {
	client kpspb.KeyProtectionServiceClient
}

// NewRemoteKeyProtectionService returns a KeyProtectionService that proxies
// every call over the given gRPC client to a remote KPS instance.
func NewRemoteKeyProtectionService(client kpspb.KeyProtectionServiceClient) KeyProtectionService {
	return &remoteKeyProtectionService{
		client: client,
	}
}

// ffiStatusFromGrpcError translates a gRPC status error from the remote KPS
// back into a typed *FFIStatus error, so the rest of WSD (notably
// httpStatusFromError) can treat remote and in-process KPS errors identically.
// Errors that aren't gRPC statuses, or whose codes don't have an FFI analogue,
// are passed through and end up as HTTP 500.
var grpcCodeToFfiStatus = map[codes.Code]keymanager.Status{
	codes.NotFound:         keymanager.Status_STATUS_NOT_FOUND,
	codes.InvalidArgument:  keymanager.Status_STATUS_INVALID_ARGUMENT,
	codes.PermissionDenied: keymanager.Status_STATUS_PERMISSION_DENIED,
	codes.Unauthenticated:  keymanager.Status_STATUS_UNAUTHENTICATED,
	codes.AlreadyExists:    keymanager.Status_STATUS_ALREADY_EXISTS,
}

func ffiStatusFromGrpcError(err error) error {
	if err == nil {
		return nil
	}
	s, ok := status.FromError(err)
	if !ok {
		return err
	}
	if s.Code() == codes.OK {
		return nil
	}
	if ffiStat, ok := grpcCodeToFfiStatus[s.Code()]; ok {
		return ffiStat.ToStatus()
	}
	return err
}

func (r *remoteKeyProtectionService) GenerateKEMKeypair(ctx context.Context, algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	req := &kpspb.GenerateKEMKeypairRequest{
		Algo: algo,
		BindingPubKey: &keymanager.HpkePublicKey{
			Algorithm: algo,
			PublicKey: bindingPubKey,
		},
		LifespanSecs: lifespanSecs,
	}
	ctx, cancel := context.WithTimeout(ctx, RPCTimeout)
	defer cancel()
	resp, err := r.client.GenerateKEMKeypair(ctx, req)
	if err != nil {
		return uuid.Nil, nil, ffiStatusFromGrpcError(err)
	}
	id, err := uuid.Parse(resp.GetKeyHandle().GetHandle())
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("invalid KEM key handle from server: %w", err)
	}
	return id, resp.GetKemPubKey().GetPublicKey(), nil
}

func (r *remoteKeyProtectionService) EnumerateKEMKeys(ctx context.Context, limit, offset int32) ([]kpskcc.KEMKeyInfo, bool, error) {
	req := &kpspb.EnumerateKEMKeysRequest{
		Limit:  limit,
		Offset: offset,
	}
	ctx, cancel := context.WithTimeout(ctx, RPCTimeout)
	defer cancel()
	resp, err := r.client.EnumerateKEMKeys(ctx, req)
	if err != nil {
		return nil, false, ffiStatusFromGrpcError(err)
	}

	keys := make([]kpskcc.KEMKeyInfo, 0, len(resp.GetKeys()))
	for _, k := range resp.GetKeys() {
		handle := k.GetKeyHandle().GetHandle()
		id, err := uuid.Parse(handle)
		if err != nil {
			return nil, false, fmt.Errorf("invalid key handle %q from server: %w", handle, err)
		}
		keys = append(keys, kpskcc.KEMKeyInfo{
			ID:                    id,
			Algorithm:             k.GetAlgorithm(),
			KEMPubKey:             k.GetKemPubKey(),
			RemainingLifespanSecs: k.GetRemainingLifespanSecs(),
		})
	}
	return keys, resp.GetHasMore(), nil
}

func (r *remoteKeyProtectionService) DestroyKEMKey(ctx context.Context, kemUUID uuid.UUID) error {
	req := &kpspb.DestroyKEMKeyRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
	}
	ctx, cancel := context.WithTimeout(ctx, RPCTimeout)
	defer cancel()
	_, err := r.client.DestroyKEMKey(ctx, req)
	return ffiStatusFromGrpcError(err)
}

func (r *remoteKeyProtectionService) DecapAndSeal(ctx context.Context, kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	req := &kpspb.DecapAndSealRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
		Ciphertext: &keymanager.KemCiphertext{
			Ciphertext: encapsulatedKey,
		},
		Aad: aad,
	}
	ctx, cancel := context.WithTimeout(ctx, RPCTimeout)
	defer cancel()
	resp, err := r.client.DecapAndSeal(ctx, req)
	if err != nil {
		return nil, nil, ffiStatusFromGrpcError(err)
	}
	return resp.GetSealEnc(), resp.GetSealedCt(), nil
}

func (r *remoteKeyProtectionService) GetKEMKey(ctx context.Context, id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	req := &kpspb.GetKEMKeyRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: id.String()},
	}
	ctx, cancel := context.WithTimeout(ctx, RPCTimeout)
	defer cancel()
	resp, err := r.client.GetKEMKey(ctx, req)
	if err != nil {
		return nil, nil, nil, 0, ffiStatusFromGrpcError(err)
	}
	return resp.GetKemPubKey().GetPublicKey(), resp.GetBindingPubKey().GetPublicKey(), resp.GetBindingPubKey().GetAlgorithm(), resp.GetRemainingLifespanSecs(), nil
}

// Server is the WSD HTTP server.
type Server struct {
	api.UnimplementedWorkloadServiceServer

	keymanager.UnimplementedKeyClaimsServiceServer
	keyProtectionService KeyProtectionService
	workloadService      WorkloadService
	mu                   sync.RWMutex
	kemToBindingMap      map[uuid.UUID]uuid.UUID
	mode                 keymanager.KeyProtectionMechanism

	httpServer      *http.Server
	httpListener    net.Listener
	grpcServer      *grpc.Server
	grpcListener    net.Listener
	conn            *grpc.ClientConn
	heartbeatCancel context.CancelFunc
	initialBackoff  time.Duration
	maxBackoff      time.Duration
	mechanism       keymanager.KeyProtectionMechanism
	// todo: add logging mechanism here
}

var (
	// WsdReadHeaderTimeout is the maximum time allowed to read HTTP request headers.
	// It is set to mitigate Slowloris attacks.
	WsdReadHeaderTimeout = 5 * time.Second
	// RPCTimeout is the maximum time to wait for remote KPS RPC calls.
	RPCTimeout = 5 * time.Second
)

// New creates a new WSD Server listening on the given unix socket path.
func New(_ context.Context, socketPath string, mode keymanager.KeyProtectionMechanism, kpsVMIP string) (*Server, error) {
	var kps KeyProtectionService
	var conn *grpc.ClientConn
	switch mode {
	case keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED:
		kps = &keyProtectionService{}
	case keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM:
		if kpsVMIP == "" {
			return nil, fmt.Errorf("KPS VM IP must be provided when using KEY_PROTECTION_VM mode")
		}
		target := fmt.Sprintf("%s:%d", kpsVMIP, defaultKpsPort)

		// Note on Transport Security:
		// We use insecure.NewCredentials() here because transport-layer confidentiality
		// and integrity are explicitly NOT part of the threat model for this channel.
		// All sensitive material passed over this gRPC connection is application-layer
		// encrypted (HPKE-sealed) using the WSD's Binding Key. Additionally, KPS/WSD
		// authentication is guaranteed out-of-band by the hardware CVM attestation
		// quotes generated by each VM.
		var err error
		conn, err = grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("failed to dial KPS: %w", err)
		}
		kpsClient := kpspb.NewKeyProtectionServiceClient(conn)
		kps = NewRemoteKeyProtectionService(kpsClient)
	case keymanager.KeyProtectionMechanism_KEY_PROTECTION_MECHANISM_UNSPECIFIED:
		return nil, fmt.Errorf("key protection mechanism is unspecified")
	default:
		return nil, fmt.Errorf("unknown key protection mechanism provided: %v", mode)
	}
	s, err := NewServer(kps, &workloadService{}, socketPath, mode)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	s.conn = conn
	s.mechanism = mode
	return s, nil
}

func customHTTPErrorHandler(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
	st := status.Convert(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(runtime.HTTPStatusFromCode(st.Code()))
	if err := json.NewEncoder(w).Encode(map[string]string{"error": st.Message()}); err != nil {
		log.Printf("Warning: failed to encode error response: %v", err)
	}
}

func grpcCodeFromError(err error) codes.Code {
	if err == nil {
		return codes.OK
	}

	switch {
	case errors.Is(err, keymanager.Status_STATUS_NOT_FOUND):
		return codes.NotFound
	case errors.Is(err, keymanager.Status_STATUS_INVALID_ARGUMENT),
		errors.Is(err, keymanager.Status_STATUS_UNSUPPORTED_ALGORITHM),
		errors.Is(err, keymanager.Status_STATUS_INVALID_KEY):
		return codes.InvalidArgument
	case errors.Is(err, keymanager.Status_STATUS_PERMISSION_DENIED):
		return codes.PermissionDenied
	case errors.Is(err, keymanager.Status_STATUS_UNAUTHENTICATED):
		return codes.Unauthenticated
	case errors.Is(err, keymanager.Status_STATUS_ALREADY_EXISTS):
		return codes.AlreadyExists
	default:
		return codes.Internal
	}
}

// NewServer creates a new WSD server with the given dependencies.
func NewServer(keyProtectionService KeyProtectionService, workloadService WorkloadService, socketPath string, mode keymanager.KeyProtectionMechanism) (*Server, error) {
	s := &Server{
		keyProtectionService: keyProtectionService,
		workloadService:      workloadService,
		kemToBindingMap:      make(map[uuid.UUID]uuid.UUID),
		mu:                   sync.RWMutex{},
		mode:                 mode,
		initialBackoff:       defaultInitialBackoff,
		maxBackoff:           defaultMaxBackoff,
		mechanism:            keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED,
	}
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return nil, fmt.Errorf("socket path must not be empty")
	}
	restSocketPath := socketPath
	grpcSocketPath := strings.TrimSuffix(socketPath, filepath.Ext(socketPath)) + "-grpc.sock"

	grpcServer, grpcListener, conn, err := initGRPCServer(s, grpcSocketPath)
	if err != nil {
		return nil, err
	}

	httpServer, httpListener, err := initRESTGatewayProxy(restSocketPath, conn)
	if err != nil {
		grpcServer.GracefulStop()
		return nil, err
	}

	s.grpcServer = grpcServer
	s.grpcListener = grpcListener
	s.httpServer = httpServer
	s.httpListener = httpListener
	s.conn = conn

	ctx, cancel := context.WithCancel(context.Background())
	s.heartbeatCancel = cancel
	go s.startHeartbeat(ctx)

	return s, nil
}

func initGRPCServer(s *Server, grpcSocketPath string) (*grpc.Server, net.Listener, *grpc.ClientConn, error) {
	_ = os.Remove(grpcSocketPath)
	grpcListener, err := net.Listen("unix", grpcSocketPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to listen on gRPC socket %s: %w", grpcSocketPath, err)
	}

	grpcServer := grpc.NewServer()
	api.RegisterWorkloadServiceServer(grpcServer, s)
	keymanager.RegisterKeyClaimsServiceServer(grpcServer, s)

	go func() {
		if err := grpcServer.Serve(grpcListener); err != nil {
			log.Printf("native gRPC server stopped: %v", err)
		}
	}()
	conn, err := grpc.NewClient(
		"unix:"+grpcSocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial internal native gRPC server: %w", err)
	}
	return grpcServer, grpcListener, conn, nil
}

func initRESTGatewayProxy(restSocketPath string, conn *grpc.ClientConn) (*http.Server, net.Listener, error) {
	mux := runtime.NewServeMux(
		// Intercept gRPC status errors and serialize them back into the legacy {"error": "<message>"} JSON layout
		runtime.WithErrorHandler(customHTTPErrorHandler),
		// Preserve original snake_case protobuf field casing and enforce inclusion of empty structures unconditionally
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: true,
			},
		}),
	)

	if err := api.RegisterWorkloadServiceHandler(context.Background(), mux, conn); err != nil {
		return nil, nil, fmt.Errorf("failed to register proxy handler: %w", err)
	}

	_ = os.Remove(restSocketPath)
	restListener, err := net.Listen("unix", restSocketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on REST unix socket %s: %w", restSocketPath, err)
	}

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Type", "application/json")
			mux.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: WsdReadHeaderTimeout,
	}

	return httpServer, restListener, nil
}

// Serve starts the HTTP server listening on the given unix socket path.
func (s *Server) Serve() error {
	go func() {
		if err := s.grpcServer.Serve(s.grpcListener); err != nil {
			log.Printf("failed to serve WSD grpc server: %v", err)
		}
	}()
	if err := s.httpServer.Serve(s.httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to serve WSD server: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	if s.grpcServer != nil {
		shutdownDone := make(chan struct{})
		go func() {
			s.grpcServer.GracefulStop()
			close(shutdownDone)
		}()

		select {
		case <-ctx.Done():
			s.grpcServer.Stop() // Force stop if context is cancelled
			errs = append(errs, fmt.Errorf("WSD gRPC shutdown context cancelled: %w", ctx.Err()))
		case <-shutdownDone:
		}
	}
	if s.heartbeatCancel != nil {
		s.heartbeatCancel()
	}
	if err := s.httpServer.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Handler returns the HTTP handler for testing purposes.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// LookupBindingUUID returns the binding UUID associated with the given KEM UUID.
func (s *Server) LookupBindingUUID(kemUUID uuid.UUID) (uuid.UUID, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.kemToBindingMap[kemUUID]
	return id, ok
}

func decapsAADContext(kemUUID uuid.UUID, algorithm keymanager.KemAlgorithm) []byte {
	// Bind the KPS->WSD transport ciphertext to this decapsulation context.
	// Note: The AAD context string retains `decaps` as it is part of the internal binding protocol
	// and changing it might affect backward compatibility if keys were already persisted (though lifespan is short).
	// For API alignment, we only change the external endpoint and JSON.
	return []byte(fmt.Sprintf("wsd:keys:decaps:v1:%d:%s", algorithm, kemUUID))
}

// Decaps handles the decapsulation of incoming HPKE ciphertext payloads.
func (s *Server) Decaps(ctx context.Context, req *api.DecapsRequest) (*api.DecapsResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	if !IsSupportedKemAlgorithm(req.Ciphertext.Algorithm) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported ciphertext algorithm: %d. Supported algorithms: %s", req.Ciphertext.Algorithm, SupportedKemAlgorithmsString())
	}

	kemUUID, err := uuid.Parse(req.KeyHandle.Handle)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid key_handle.handle: %v", err)
	}

	encapsulatedKey := req.Ciphertext.Ciphertext
	if len(encapsulatedKey) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "ciphertext.ciphertext must not be empty")
	}
	aad := decapsAADContext(kemUUID, req.Ciphertext.Algorithm)

	// Look up the binding UUID for this KEM key.
	bindingUUID, ok := s.LookupBindingUUID(kemUUID)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "KEM key handle not found: %s", kemUUID)
	}

	// Decapsulate and reseal via KPS.
	sealEnc, sealedCT, err := s.keyProtectionService.DecapAndSeal(ctx, kemUUID, encapsulatedKey, aad)
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to decap and seal: %v", err)
	}

	// Open the sealed secret using the binding key via WSD KCC.
	plaintext, err := s.workloadService.Open(bindingUUID, sealEnc, sealedCT, aad)
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to open sealed secret: %v", err)
	}

	// Return the shared secret.
	return &api.DecapsResponse{
		SharedSecret: &keymanager.KemSharedSecret{
			Algorithm: req.Ciphertext.Algorithm,
			Secret:    plaintext,
		},
	}, nil
}

// GenerateKey handles the creation of new key pairs for workload environments.
func (s *Server) GenerateKey(ctx context.Context, req *api.GenerateKeyRequest) (*api.GenerateKeyResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "request cannot be nil")
	}
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	switch req.Algorithm.Type {
	case "kem":
		return s.generateKEMKey(ctx, req)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported algorithm type: %q. Only 'kem' is supported.", req.Algorithm.Type)
	}
}

func (s *Server) generateKEMKey(ctx context.Context, req *api.GenerateKeyRequest) (*api.GenerateKeyResponse, error) {
	// Validate algorithm.
	if req.Algorithm.GetParams() == nil || !IsSupportedKemAlgorithm(req.Algorithm.GetParams().GetKemId()) {
		kemID := keymanager.KemAlgorithm_KEM_ALGORITHM_UNSPECIFIED
		if req.Algorithm.GetParams() != nil {
			kemID = req.Algorithm.GetParams().GetKemId()
		}
		return nil, status.Errorf(codes.InvalidArgument, "unsupported algorithm: %s. Supported algorithms: %s", kemID.String(), SupportedKemAlgorithmsString())
	}

	// Construct the full HPKE algorithm suite based on the requested KEM.
	// We currently only support one suite.
	algo, err := KemToHpkeAlgorithm(req.Algorithm.GetParams().GetKemId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to convert KEM algorithm to HPKE algorithm: %v", err)
	}

	// Generate binding keypair via WSD KCC FFI.
	bindingUUID, bindingPubKey, err := s.workloadService.GenerateBindingKeypair(algo, req.Lifespan)
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to generate binding keypair: %v", err)
	}

	// Generate KEM keypair via KPS KOL, passing the binding public key.
	kemUUID, kemPubKey, err := s.keyProtectionService.GenerateKEMKeypair(ctx, algo, bindingPubKey, req.Lifespan)
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to generate KEM keypair: %v", err)
	}

	// Store the KEM UUID → Binding UUID mapping.
	s.mu.Lock()
	s.kemToBindingMap[kemUUID] = bindingUUID
	s.mu.Unlock()

	// Return KEM UUID to workload.
	return &api.GenerateKeyResponse{
		KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
		PubKey: &keymanager.PubKeyInfo{
			Algorithm: &keymanager.AlgorithmDetails{
				Type: req.Algorithm.Type,
				Params: &keymanager.AlgorithmParams{
					Params: &keymanager.AlgorithmParams_KemId{
						KemId: req.Algorithm.GetParams().GetKemId(),
					},
				},
			},
			PublicKey: kemPubKey,
		},
		KeyProtectionMechanism: s.mechanism.String(),
		ExpirationTime:         float64(time.Now().Unix()) + float64(req.Lifespan),
	}, nil
}

// GetCapabilities returns the list of supported cryptographic operations and HPKE suites.
func (s *Server) GetCapabilities(_ context.Context, req *api.GetCapabilitiesRequest) (*api.GetCapabilitiesResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	var supportedAlgos []*keymanager.SupportedAlgorithm
	for _, algo := range SupportedKemAlgorithms {
		supportedAlgos = append(supportedAlgos, &keymanager.SupportedAlgorithm{
			Algorithm: &keymanager.AlgorithmDetails{
				Type: "kem",
				Params: &keymanager.AlgorithmParams{
					Params: &keymanager.AlgorithmParams_KemId{
						KemId: algo,
					},
				},
			},
		})
	}

	return &api.GetCapabilitiesResponse{
		SupportedAlgorithms: supportedAlgos,
	}, nil
}

// EnumerateKeys lists all available cryptographic keys currently registered with the Key Protection Service.
func (s *Server) EnumerateKeys(ctx context.Context, req *api.EnumerateKeysRequest) (*api.EnumerateKeysResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	keys, _, err := s.keyProtectionService.EnumerateKEMKeys(ctx, 100, 0)
	if err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to enumerate keys: %v", err)
	}

	keyInfos := make([]*api.KeyInfo, 0, len(keys))
	for _, key := range keys {
		var kemAlgo keymanager.KemAlgorithm
		if key.Algorithm != nil {
			kemAlgo = key.Algorithm.Kem
		}

		keyInfos = append(keyInfos, &api.KeyInfo{
			KeyHandle: &keymanager.KeyHandle{Handle: key.ID.String()},
			PubKey: &keymanager.PubKeyInfo{
				Algorithm: &keymanager.AlgorithmDetails{
					Type: "kem",
					Params: &keymanager.AlgorithmParams{
						Params: &keymanager.AlgorithmParams_KemId{
							KemId: kemAlgo,
						},
					},
				},
				PublicKey: key.KEMPubKey,
			},
			KeyProtectionMechanism: s.mechanism.String(),
			ExpirationTime:         float64(time.Now().Unix()) + float64(key.RemainingLifespanSecs),
		})
	}

	return &api.EnumerateKeysResponse{
		KeyInfos: keyInfos,
	}, nil
}

// Destroy deletes a registered cryptographic keypair permanently.
func (s *Server) Destroy(ctx context.Context, req *api.DestroyRequest) (*api.DestroyResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	kemUUID, err := uuid.Parse(req.KeyHandle.Handle)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid key handle: %v", err)
	}

	// Look up the binding UUID for this KEM key.
	bindingUUID, ok := s.LookupBindingUUID(kemUUID)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "KEM key handle not found: %s", kemUUID)
	}

	errKps := s.keyProtectionService.DestroyKEMKey(ctx, kemUUID)
	errWs := s.workloadService.DestroyBindingKey(bindingUUID)

	// Remove the mapping.
	s.mu.Lock()
	delete(s.kemToBindingMap, kemUUID)
	s.mu.Unlock()

	if err := errors.Join(errKps, errWs); err != nil {
		return nil, status.Errorf(grpcCodeFromError(err), "failed to destroy keys: %v", err)
	}

	return &api.DestroyResponse{}, nil
}

// handleGetBindingKeyClaims returns the claims for a binding key identified by its KEM UUID.
func (s *Server) handleGetBindingKeyClaims(id uuid.UUID) (*keymanager.KeyClaims, error) {
	// Key ID Lookup. The orchestration layer will look-up the key_handle
	// in its ActiveKeyRegistry to find the Binding Key ID.
	bindingID, ok := s.LookupBindingUUID(id)
	if !ok {
		return nil, fmt.Errorf("binding key ID not found for key handle: %s", id)
	}

	// Key Metadata Lookup.
	pubKey, algo, err := s.workloadService.GetBindingKey(bindingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get binding key: %w", err)
	}

	// Create KeyClaims
	claims := &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmBindingClaims{
			VmBindingClaims: &keymanager.KeyClaims_VmProtectionBindingClaims{
				BindingPubKey: &keymanager.HpkePublicKey{
					Algorithm: algo,
					PublicKey: pubKey,
				},
			},
		},
	}
	return claims, nil
}

// handleGetKEMKeyClaims returns the claims for a KEM key identified by its UUID.
func (s *Server) handleGetKEMKeyClaims(ctx context.Context, id uuid.UUID) (*keymanager.KeyClaims, error) {
	// Key Metadata Lookup.
	kemPubKey, bindingPubKey, algo, remainingLifespanSecs, err := s.keyProtectionService.GetKEMKey(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEM key: %w", err)
	}

	// Calculate remaining time.
	var remaining time.Duration
	if remainingLifespanSecs > uint64(maxDurationSeconds) {
		remaining = time.Duration(math.MaxInt64)
	} else {
		remaining = time.Duration(remainingLifespanSecs) * time.Second
	}

	// Create KeyClaims
	claims := &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmKeyClaims{
			VmKeyClaims: &keymanager.KeyClaims_VmProtectionKeyClaims{
				KemPubKey: &keymanager.KemPublicKey{
					Algorithm: algo.GetKem(),
					PublicKey: kemPubKey,
				},
				BindingPubKey: &keymanager.HpkePublicKey{
					Algorithm: algo,
					PublicKey: bindingPubKey,
				},
				RemainingLifespan: durationpb.New(remaining),
				ExpirationTime:    float64(time.Now().Unix()) + float64(remainingLifespanSecs),
			},
		},
	}
	return claims, nil
}

// GetKeyClaims processes a single GetKeyClaimsRequest and returns the result.
func (s *Server) GetKeyClaims(ctx context.Context, req *keymanager.GetKeyClaimsRequest) (*keymanager.KeyClaims, error) {
	keyHandle := req.GetKeyHandle().GetHandle()
	keyType := req.GetKeyType()

	id, err := uuid.Parse(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key claims: %w", err)
	}

	var claims *keymanager.KeyClaims
	switch keyType {
	case keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING:
		claims, err = s.handleGetBindingKeyClaims(id)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve binding key claims: %w", err)
		}

	case keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY:
		if s.mode == keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM {
			return nil, status.Errorf(codes.InvalidArgument, "KEM key claims must be retrieved directly from the KPS VM in KEY_PROTECTION_VM mode")
		}
		claims, err = s.handleGetKEMKeyClaims(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve VM protection key claims: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	return claims, nil
}

// startHeartbeat starts a background loop to send heartbeats to the KPS.
func (s *Server) startHeartbeat(ctx context.Context) {
	kpsIP := os.Getenv("KPS_IP")
	if kpsIP == "" {
		log.Println("KPS_IP environment variable not set, skipping heartbeat")
		return
	}
	kpsAddr := kpsIP
	if !strings.Contains(kpsAddr, ":") {
		kpsAddr = fmt.Sprintf("%s:%d", kpsIP, defaultKpsPort)
	}

	conn, err := grpc.NewClient(kpsAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Failed to connect to KPS at %s: %v", kpsAddr, err)
		return
	}
	defer func() { _ = conn.Close() }()

	client := kpspb.NewKeyProtectionServiceClient(conn)

	var cachedToken string
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	// Perform an initial heartbeat immediately upon startup
	s.performHeartbeat(ctx, client, &cachedToken)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.performHeartbeat(ctx, client, &cachedToken)
		}
	}
}

// performHeartbeat sends a single heartbeat request to the KPS and handles the response.
// It implements exponential backoff on failure.
func (s *Server) performHeartbeat(ctx context.Context, client kpspb.KeyProtectionServiceClient, cachedToken *string) {
	backoff := s.initialBackoff
	maxBackoff := s.maxBackoff

	var timer *time.Timer

	for {
		rpcCtx, cancel := context.WithTimeout(ctx, heartbeatTimeout)
		resp, err := client.Heartbeat(rpcCtx, &kpspb.HeartbeatRequest{})
		cancel()
		if err == nil {
			// Success: reset and return
			if timer != nil {
				timer.Stop()
			}
			token := resp.GetKpsBootToken()
			if *cachedToken != "" && *cachedToken != token {
				log.Println("Token mismatch! Triggering cleanup.")
				s.cleanupState()
			} else {
				log.Println("Heartbeat handshake successful.")
			}
			*cachedToken = token
			return
		}

		log.Printf("Heartbeat failed: %v. Backing off %v...", err, backoff)

		// Initialize or reset the timer
		if timer == nil {
			timer = time.NewTimer(backoff)
		} else {
			timer.Reset(backoff)
		}

		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-timer.C:
			if backoff >= maxBackoff {
				log.Println("Persistent heartbeat failure after max backoff. Triggering cleanup.")
				s.cleanupState()
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// cleanupState purges the KEM to Binding mapping and destroys all binding keys
// in case of persistent heartbeat failure or token mismatch.
func (s *Server) cleanupState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Println("Purging kemToBindingMap and Binding keys due to heartbeat failure/token mismatch.")

	if err := s.workloadService.DestroyAllKeys(); err != nil {
		log.Printf("Failed to destroy all binding keys: %v", err)
	}
	s.kemToBindingMap = make(map[uuid.UUID]uuid.UUID)
}
