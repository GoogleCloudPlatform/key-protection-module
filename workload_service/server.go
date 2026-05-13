// Package workloadservice implements the Key Orchestration Layer (KOL) for the
// Workload Service Daemon (WSD). It provides an HTTP server on a unix socket
// exposing key management endpoints.
package workloadservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	api "github.com/GoogleCloudPlatform/key-protection-module/workload_service/proto"
	"github.com/google/uuid"
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
	EnumerateKEMKeys(ctx context.Context, limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error)
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

func (r *keyProtectionService) EnumerateKEMKeys(_ context.Context, limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error) {
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

func (r *remoteKeyProtectionService) EnumerateKEMKeys(ctx context.Context, limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error) {
	req := &kpspb.EnumerateKEMKeysRequest{
		Limit:  int32(limit),
		Offset: int32(offset),
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

// KeyClaimsProvider defines the interface for retrieving key claims.
// This abstraction allows the underlying implementation to be a local channel
// or a remote RPC call in future.
type KeyClaimsProvider interface {
	GetKeyClaims(ctx context.Context, keyHandle string, keyType keymanager.KeyType) (*keymanager.KeyClaims, error)
}

// ClaimsCall acts as the internal "envelope" for the channel.
type ClaimsCall struct {
	Ctx      context.Context
	Request  *keymanager.GetKeyClaimsRequest
	RespChan chan *ClaimsResult
}

// ClaimsResult wraps the protobuf response with an error.
type ClaimsResult struct {
	Reply *keymanager.KeyClaims
	Err   error
}

// Server is the WSD HTTP server.
type Server struct {
	keyProtectionService KeyProtectionService
	workloadService      WorkloadService
	mu                   sync.RWMutex
	kemToBindingMap      map[uuid.UUID]uuid.UUID

	claimsChan chan *ClaimsCall

	httpServer *http.Server
	listener   net.Listener
	conn       *grpc.ClientConn

	heartbeatCancel context.CancelFunc
	initialBackoff  time.Duration
	maxBackoff      time.Duration
	// todo: add logging mechanism here
}

var (
	// ClaimsResponseTimeout is the maximum time to wait for the caller to receive
	// the result of a GetKeyClaims request before timing out.
	ClaimsResponseTimeout = 5 * time.Second
	// ClaimsRequestTimeout is the maximum time to wait for enqueuing the request to
	// claims channel for getting the key claims.
	ClaimsRequestTimeout = 5 * time.Second
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
	s, err := NewServer(kps, &workloadService{}, socketPath)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	s.conn = conn
	return s, nil
}

// NewServer creates a new WSD server with the given dependencies.
func NewServer(keyProtectionService KeyProtectionService, workloadService WorkloadService, socketPath string) (*Server, error) {
	s := &Server{
		keyProtectionService: keyProtectionService,
		workloadService:      workloadService,
		kemToBindingMap:      make(map[uuid.UUID]uuid.UUID),
		mu:                   sync.RWMutex{},
		claimsChan:           make(chan *ClaimsCall, 4),
		initialBackoff:       defaultInitialBackoff,
		maxBackoff:           defaultMaxBackoff,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys:generate_key", s.handleGenerateKey)
	mux.HandleFunc("POST /v1/keys:decap", s.handleDecaps)
	mux.HandleFunc("GET /v1/capabilities", s.handleGetCapabilities)
	mux.HandleFunc("GET /v1/keys", s.handleEnumerateKeys)
	mux.HandleFunc("POST /v1/keys:destroy", s.handleDestroy)
	s.httpServer = &http.Server{Handler: mux}

	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on unix socket %s: %w", socketPath, err)
	}
	s.listener = ln

	go s.processClaims()

	ctx, cancel := context.WithCancel(context.Background())
	s.heartbeatCancel = cancel
	go s.startHeartbeat(ctx)

	return s, nil
}

// Serve starts the HTTP server listening on the given unix socket path.
func (s *Server) Serve() error {
	return s.httpServer.Serve(s.listener)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.heartbeatCancel != nil {
		s.heartbeatCancel()
	}
	var errs []error
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

func httpStatusFromError(err error) int {
	if err == nil {
		return http.StatusOK
	}

	switch {
	case errors.Is(err, keymanager.Status_STATUS_NOT_FOUND):
		return http.StatusNotFound
	case errors.Is(err, keymanager.Status_STATUS_INVALID_ARGUMENT),
		errors.Is(err, keymanager.Status_STATUS_UNSUPPORTED_ALGORITHM),
		errors.Is(err, keymanager.Status_STATUS_INVALID_KEY):
		return http.StatusBadRequest
	case errors.Is(err, keymanager.Status_STATUS_PERMISSION_DENIED):
		return http.StatusForbidden
	case errors.Is(err, keymanager.Status_STATUS_UNAUTHENTICATED):
		return http.StatusUnauthorized
	case errors.Is(err, keymanager.Status_STATUS_ALREADY_EXISTS):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func decapsAADContext(kemUUID uuid.UUID, algorithm keymanager.KemAlgorithm) []byte {
	// Bind the KPS->WSD transport ciphertext to this decapsulation context.
	// Note: The AAD context string retains `decaps` as it is part of the internal binding protocol
	// and changing it might affect backward compatibility if keys were already persisted (though lifespan is short).
	// For API alignment, we only change the external endpoint and JSON.
	return []byte(fmt.Sprintf("wsd:keys:decaps:v1:%d:%s", algorithm, kemUUID))
}

func (s *Server) handleDecaps(w http.ResponseWriter, r *http.Request) {
	var req api.DecapsRequest
	if err := readRequest(r, &req); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !IsSupportedKemAlgorithm(req.Ciphertext.Algorithm) {
		writeError(w, fmt.Sprintf("unsupported ciphertext algorithm: %d. Supported algorithms: %s", req.Ciphertext.Algorithm, SupportedKemAlgorithmsString()), http.StatusBadRequest)
		return
	}

	kemUUID, err := uuid.Parse(req.KeyHandle.Handle)
	if err != nil {
		writeError(w, fmt.Sprintf("invalid key_handle.handle: %v", err), http.StatusBadRequest)
		return
	}

	encapsulatedKey := req.Ciphertext.Ciphertext
	if len(encapsulatedKey) == 0 {
		writeError(w, "ciphertext.ciphertext must not be empty", http.StatusBadRequest)
		return
	}
	aad := decapsAADContext(kemUUID, req.Ciphertext.Algorithm)

	// Look up the binding UUID for this KEM key.
	bindingUUID, ok := s.LookupBindingUUID(kemUUID)
	if !ok {
		writeError(w, fmt.Sprintf("KEM key handle not found: %s", kemUUID), http.StatusNotFound)
		return
	}

	// Decapsulate and reseal via KPS.
	sealEnc, sealedCT, err := s.keyProtectionService.DecapAndSeal(r.Context(), kemUUID, encapsulatedKey, aad)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to decap and seal: %v", err), httpStatusFromError(err))
		return
	}

	// Open the sealed secret using the binding key via WSD KCC.
	plaintext, err := s.workloadService.Open(bindingUUID, sealEnc, sealedCT, aad)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to open sealed secret: %v", err), httpStatusFromError(err))
		return
	}

	// Return the shared secret.
	resp := api.DecapsResponse{
		SharedSecret: &keymanager.KemSharedSecret{
			Algorithm: req.Ciphertext.Algorithm,
			Secret:    plaintext,
		},
	}
	writeJSON(w, &resp, http.StatusOK)
}

func (s *Server) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	var req api.GenerateKeyRequest
	if err := readRequest(r, &req); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch req.Algorithm.Type {
	case "kem":
		s.generateKEMKey(w, r, &req)
	default:
		writeError(w, fmt.Sprintf("unsupported algorithm type: %q. Only 'kem' is supported.", req.Algorithm.Type), http.StatusBadRequest)
	}
}

func (s *Server) generateKEMKey(w http.ResponseWriter, r *http.Request, req *api.GenerateKeyRequest) {
	// Validate algorithm.
	if !IsSupportedKemAlgorithm(req.Algorithm.GetParams().GetKemId()) {
		writeError(w, fmt.Sprintf("unsupported algorithm: %s. Supported algorithms: %s", req.Algorithm.GetParams().GetKemId(), SupportedKemAlgorithmsString()), http.StatusBadRequest)
		return
	}

	// Construct the full HPKE algorithm suite based on the requested KEM.
	// We currently only support one suite.
	algo, err := KemToHpkeAlgorithm(req.Algorithm.GetParams().GetKemId())
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Generate binding keypair via WSD KCC FFI.
	bindingUUID, bindingPubKey, err := s.workloadService.GenerateBindingKeypair(algo, req.Lifespan)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to generate binding keypair: %v", err), httpStatusFromError(err))
		return
	}

	// Generate KEM keypair via KPS KOL, passing the binding public key.
	kemUUID, kemPubKey, err := s.keyProtectionService.GenerateKEMKeypair(r.Context(), algo, bindingPubKey, req.Lifespan)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to generate KEM keypair: %v", err), httpStatusFromError(err))
		return
	}

	// Store the KEM UUID → Binding UUID mapping.
	s.mu.Lock()
	s.kemToBindingMap[kemUUID] = bindingUUID
	s.mu.Unlock()

	// Return KEM UUID to workload.
	resp := api.GenerateKeyResponse{
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
		KeyProtectionMechanism: keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(),
		ExpirationTime:         float64(time.Now().Unix()) + float64(req.Lifespan),
	}
	writeJSON(w, &resp, http.StatusOK)
}

func (s *Server) handleGetCapabilities(w http.ResponseWriter, _ *http.Request) {

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

	resp := api.GetCapabilitiesResponse{
		SupportedAlgorithms: supportedAlgos,
	}

	writeJSON(w, &resp, http.StatusOK)
}

func (s *Server) handleEnumerateKeys(w http.ResponseWriter, r *http.Request) {
	keys, _, err := s.keyProtectionService.EnumerateKEMKeys(r.Context(), 100, 0)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to enumerate keys: %v", err), httpStatusFromError(err))
		return
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
			KeyProtectionMechanism: keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(),
			ExpirationTime:         float64(time.Now().Unix()) + float64(key.RemainingLifespanSecs),
		})
	}

	resp := api.EnumerateKeysResponse{
		KeyInfos: keyInfos,
	}

	writeJSON(w, &resp, http.StatusOK)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, v proto.Message, code int) {
	if err := protovalidate.Validate(v); err != nil {
		writeError(w, fmt.Sprintf("validation failed for response: %v", err), http.StatusInternalServerError)
		return
	}

	b, err := protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}.Marshal(v)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	if _, err := w.Write(b); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	b, err := json.Marshal(map[string]string{"error": message})
	if err != nil {
		log.Printf("failed to marshal error response: %v", err)
		b = []byte(`{"error":"internal error serializing response"}`)
	}
	if _, err := w.Write(b); err != nil {
		log.Printf("failed to write error response: %v", err)
	}
}

// readRequest reads the HTTP request body, unmarshals it into a proto.Message,
// and validates it.
func readRequest(r *http.Request, req proto.Message) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	if err := protojson.Unmarshal(body, req); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	if err := protovalidate.Validate(req); err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}
	return nil
}

func (s *Server) handleDestroy(w http.ResponseWriter, r *http.Request) {
	var req api.DestroyRequest
	if err := readRequest(r, &req); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	kemUUID, err := uuid.Parse(req.KeyHandle.Handle)
	if err != nil {
		writeError(w, fmt.Sprintf("invalid key handle: %v", err), http.StatusBadRequest)
		return
	}

	// Look up the binding UUID for this KEM key.
	bindingUUID, ok := s.LookupBindingUUID(kemUUID)
	if !ok {
		writeError(w, fmt.Sprintf("KEM key handle not found: %s", kemUUID), http.StatusNotFound)
		return
	}

	errKps := s.keyProtectionService.DestroyKEMKey(r.Context(), kemUUID)
	errWs := s.workloadService.DestroyBindingKey(bindingUUID)

	// Remove the mapping.
	s.mu.Lock()
	delete(s.kemToBindingMap, kemUUID)
	s.mu.Unlock()

	if err := errors.Join(errKps, errWs); err != nil {
		writeError(w, fmt.Sprintf("failed to destroy keys: %v", err), httpStatusFromError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
	remaining := time.Duration(remainingLifespanSecs) * time.Second

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

// processClaims is a background worker that processes key claims requests from claimsChan.
func (s *Server) processClaims() {
	for call := range s.claimsChan {
		result := s.handleGetClaims(call.Ctx, call.Request)

		select {
		case call.RespChan <- result:
		case <-time.After(ClaimsResponseTimeout):
			log.Printf("processClaims: timed out sending response for key %s", call.Request.GetKeyHandle().GetHandle())
		}
	}
}

// handleGetClaims processes a single GetKeyClaimsRequest and returns the result.
func (s *Server) handleGetClaims(ctx context.Context, req *keymanager.GetKeyClaimsRequest) *ClaimsResult {
	keyHandle := req.GetKeyHandle().GetHandle()
	keyType := req.GetKeyType()

	id, err := uuid.Parse(keyHandle)
	if err != nil {
		return &ClaimsResult{Err: fmt.Errorf("failed to retrieve key claims: %w", err)}
	}

	var claims *keymanager.KeyClaims
	switch keyType {
	case keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING:
		claims, err = s.handleGetBindingKeyClaims(id)
		if err != nil {
			return &ClaimsResult{Err: fmt.Errorf("failed to retrieve binding key claims: %w", err)}
		}

	case keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY:
		claims, err = s.handleGetKEMKeyClaims(ctx, id)
		if err != nil {
			return &ClaimsResult{Err: fmt.Errorf("failed to retrieve VM protection key claims: %w", err)}
		}
	default:
		return &ClaimsResult{Err: fmt.Errorf("unsupported key type: %v", keyType)}
	}

	return &ClaimsResult{Reply: claims}
}

// GetKeyClaims enqueues request for getting key claims to claims channel.
func (s *Server) GetKeyClaims(ctx context.Context, keyHandle string, keyType keymanager.KeyType) (*keymanager.KeyClaims, error) {
	respChan := make(chan *ClaimsResult, 1)
	req := &keymanager.GetKeyClaimsRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: keyHandle},
		KeyType:   keyType,
	}
	select {
	case s.claimsChan <- &ClaimsCall{Ctx: ctx, Request: req, RespChan: respChan}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(ClaimsRequestTimeout):
		return nil, fmt.Errorf("failed to send request: claims channel is full or worker is stuck")
	}
	select {
	case result := <-respChan:
		if result.Err != nil {
			return nil, fmt.Errorf("worker error: %w", result.Err)
		}
		return result.Reply, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(ClaimsResponseTimeout):
		return nil, fmt.Errorf("timed out waiting for processClaims to respond for key: %s", keyHandle)
	}
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
			if *cachedToken == "" {
				*cachedToken = token
				log.Printf("Heartbeat handshake successful, cached token: %s", token)
			} else if *cachedToken != token {
				log.Printf("Token mismatch! Cached: %s, Received: %s. Triggering cleanup.", *cachedToken, token)
				s.cleanupState()
				*cachedToken = token
			}
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
